// Package etcd implements registry.Registry against etcd v3.
//
// Each Service registration becomes a key under <Prefix>/<Name>/<ID>, with
// the Service serialized as JSON. Lifecycle is bound to an etcd lease
// (configured to TTL or DefaultTTL); a background goroutine renews the lease
// indefinitely. Watch is implemented via etcd prefix WATCH so multiple
// processes can subscribe.
package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/platform/registry"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// Defaults applied when a corresponding Config field is zero.
const (
	DefaultPrefix      = "/snaplink/registry"
	DefaultDialTimeout = 5 * time.Second
	DefaultTTL         = 30 * time.Second

	leaseCleanupTimeout = 2 * time.Second
)

var errClosed = errors.New("registry/etcd: registry closed")

// Config configures the etcd Registry.
type Config struct {
	Endpoints   []string      // etcd cluster endpoints, e.g. ["localhost:2379"]
	Prefix      string        // key namespace; defaults to DefaultPrefix
	DialTimeout time.Duration // connect timeout; defaults to DefaultDialTimeout
	Username    string
	Password    string
}

// leaseClient contains the etcd operations needed during registration. Keeping
// this seam narrow allows lease failure paths to be tested without an etcd
// server.
type leaseClient interface {
	Grant(context.Context, int64) (*clientv3.LeaseGrantResponse, error)
	Put(context.Context, string, string, ...clientv3.OpOption) (*clientv3.PutResponse, error)
	KeepAlive(context.Context, clientv3.LeaseID) (<-chan *clientv3.LeaseKeepAliveResponse, error)
	Revoke(context.Context, clientv3.LeaseID) (*clientv3.LeaseRevokeResponse, error)
}

// Registry is the etcd-backed implementation.
type Registry struct {
	client   *clientv3.Client
	leaseOps leaseClient
	prefix   string

	mu     sync.Mutex
	leases map[string]clientv3.LeaseID // instanceID -> leaseID
	cancel map[string]context.CancelFunc
	closed bool
}

// New connects to etcd and returns a Registry. The caller owns the lifecycle —
// call Close to release the connection and revoke outstanding leases.
func New(cfg Config) (*Registry, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("registry/etcd: at least one endpoint required")
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.Prefix == "" {
		cfg.Prefix = DefaultPrefix
	}
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   cfg.Endpoints,
		DialTimeout: cfg.DialTimeout,
		Username:    cfg.Username,
		Password:    cfg.Password,
	})
	if err != nil {
		return nil, fmt.Errorf("registry/etcd: dial: %w", err)
	}
	return &Registry{
		client:   cli,
		leaseOps: cli,
		prefix:   cfg.Prefix,
		leases:   make(map[string]clientv3.LeaseID),
		cancel:   make(map[string]context.CancelFunc),
	}, nil
}

// NewWithClient is for tests — pass a pre-configured *clientv3.Client.
// The caller must NOT close that client; ownership transfers to Registry.
func NewWithClient(cli *clientv3.Client, prefix string) *Registry {
	if prefix == "" {
		prefix = DefaultPrefix
	}
	return &Registry{
		client:   cli,
		leaseOps: cli,
		prefix:   prefix,
		leases:   make(map[string]clientv3.LeaseID),
		cancel:   make(map[string]context.CancelFunc),
	}
}

func (r *Registry) Register(ctx context.Context, svc *registry.Service) error {
	if svc == nil || svc.ID == "" || svc.Name == "" {
		return errors.New("registry/etcd: service id and name required")
	}
	if err := r.checkOpen(); err != nil {
		return err
	}

	ttl := svc.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	ttlSec := max(int64(ttl.Seconds()), 1)

	data, err := json.Marshal(svc)
	if err != nil {
		return fmt.Errorf("registry/etcd: marshal: %w", err)
	}

	leaseOps := r.leaseOperations()
	lease, err := leaseOps.Grant(ctx, ttlSec)
	if err != nil {
		return fmt.Errorf("registry/etcd: lease grant: %w", err)
	}

	if _, err := leaseOps.Put(ctx, r.serviceKey(svc.Name, svc.ID), string(data),
		clientv3.WithLease(lease.ID)); err != nil {
		cleanupGrantedLease(leaseOps, lease.ID)
		return fmt.Errorf("registry/etcd: put: %w", err)
	}

	keepCtx, cancel := context.WithCancel(context.Background())
	keepAlive, err := leaseOps.KeepAlive(keepCtx, lease.ID)
	if err != nil {
		cancel()
		cleanupGrantedLease(leaseOps, lease.ID)
		return fmt.Errorf("registry/etcd: keepalive: %w", err)
	}
	go drainKeepAlive(keepAlive)

	if err := r.publishLease(ctx, svc.ID, lease.ID, cancel, leaseOps); err != nil {
		cancel()
		cleanupGrantedLease(leaseOps, lease.ID)
		return err
	}
	return nil
}

func (r *Registry) checkOpen() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errClosed
	}
	return nil
}

func (r *Registry) publishLease(ctx context.Context, serviceID string, leaseID clientv3.LeaseID, cancel context.CancelFunc, leaseOps leaseClient) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errClosed
	}
	if old, ok := r.cancel[serviceID]; ok {
		old()
		_, _ = leaseOps.Revoke(ctx, r.leases[serviceID])
	}
	r.leases[serviceID] = leaseID
	r.cancel[serviceID] = cancel
	return nil
}

func (r *Registry) Deregister(ctx context.Context, instanceID string) error {
	r.mu.Lock()
	leaseID, ok := r.leases[instanceID]
	cancel := r.cancel[instanceID]
	r.mu.Unlock()

	if !ok {
		return nil // already gone
	}
	if cancel != nil {
		cancel()
	}
	if _, err := r.leaseOperations().Revoke(ctx, leaseID); err != nil {
		return fmt.Errorf("registry/etcd: revoke: %w", err)
	}

	r.mu.Lock()
	if currentLease, stillRegistered := r.leases[instanceID]; stillRegistered && currentLease == leaseID {
		delete(r.leases, instanceID)
		delete(r.cancel, instanceID)
	}
	r.mu.Unlock()
	return nil
}

func (r *Registry) Discover(ctx context.Context, serviceName string) ([]*registry.Service, error) {
	resp, err := r.client.Get(ctx, r.serviceNamespace(serviceName), clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("registry/etcd: get: %w", err)
	}
	if resp.Count == 0 {
		return nil, registry.ErrNotFound
	}
	out := make([]*registry.Service, 0, resp.Count)
	for _, kv := range resp.Kvs {
		var svc registry.Service
		if err := json.Unmarshal(kv.Value, &svc); err != nil {
			continue // skip corrupt entry rather than fail the whole call
		}
		out = append(out, &svc)
	}
	if len(out) == 0 {
		return nil, registry.ErrNotFound
	}
	return out, nil
}

func (r *Registry) Watch(ctx context.Context, serviceName string) (<-chan registry.Event, error) {
	out := make(chan registry.Event, 16)
	wch := r.client.Watch(ctx, r.serviceNamespace(serviceName), clientv3.WithPrefix(), clientv3.WithPrevKV())

	go func() {
		defer close(out)
		for resp := range wch {
			if err := resp.Err(); err != nil {
				return
			}
			for _, ev := range resp.Events {
				evt := translateEvent(ev)
				if evt.Service == nil {
					continue
				}
				select {
				case out <- evt:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

// Ping reports etcd reachability for [sso.WithReadyCheck] wiring.
// Issues a Maintenance.Status RPC against each configured endpoint
// in turn and returns nil as soon as one responds. Returns an
// aggregate error only when every endpoint is unreachable so a
// single down member doesn't trip /readyz on an otherwise healthy
// cluster.
func (r *Registry) Ping(ctx context.Context) error {
	if r == nil || r.client == nil {
		return errors.New("registry/etcd: closed")
	}
	endpoints := r.client.Endpoints()
	if len(endpoints) == 0 {
		return errors.New("registry/etcd: no endpoints configured")
	}
	var lastErr error
	for _, ep := range endpoints {
		if _, err := r.client.Status(ctx, ep); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("registry/etcd: all endpoints unreachable: %w", lastErr)
}

func (r *Registry) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	cancels := make([]context.CancelFunc, 0, len(r.cancel))
	leases := make([]clientv3.LeaseID, 0, len(r.leases))
	for id, c := range r.cancel {
		cancels = append(cancels, c)
		if l, ok := r.leases[id]; ok {
			leases = append(leases, l)
		}
	}
	r.leases = nil
	r.cancel = nil
	r.mu.Unlock()

	for _, c := range cancels {
		c()
	}
	revokeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, l := range leases {
		_, _ = r.client.Revoke(revokeCtx, l)
	}
	return r.client.Close()
}

func (r *Registry) leaseOperations() leaseClient {
	if r.leaseOps != nil {
		return r.leaseOps
	}
	return r.client
}

// cleanupGrantedLease does not inherit the request context: after a grant,
// cleanup must still run if the failed operation canceled that context. The
// deadline bounds a stuck revoke without replacing the original error.
func cleanupGrantedLease(client leaseClient, leaseID clientv3.LeaseID) {
	ctx, cancel := context.WithTimeout(context.Background(), leaseCleanupTimeout)
	defer cancel()
	_, _ = client.Revoke(ctx, leaseID)
}

// serviceKey is the etcd key for one instance.
func (r *Registry) serviceKey(name, id string) string {
	return path.Join(r.prefix, name, id)
}

// serviceNamespace is the prefix that contains all instances of a service.
// Trailing slash makes WithPrefix() match exactly this service, not e.g.
// "sso-prime" when asked for "sso".
func (r *Registry) serviceNamespace(name string) string {
	return path.Join(r.prefix, name) + "/"
}

func translateEvent(ev *clientv3.Event) registry.Event {
	switch ev.Type {
	case clientv3.EventTypePut:
		var svc registry.Service
		if err := json.Unmarshal(ev.Kv.Value, &svc); err != nil {
			return registry.Event{}
		}
		t := registry.EventAdded
		if ev.IsModify() {
			t = registry.EventUpdated
		}
		return registry.Event{Type: t, Service: &svc}
	case clientv3.EventTypeDelete:
		// On delete, current Kv.Value is empty; PrevKv has the old payload.
		if ev.PrevKv == nil {
			id := path.Base(string(ev.Kv.Key))
			parts := strings.Split(strings.Trim(string(ev.Kv.Key), "/"), "/")
			name := ""
			if len(parts) >= 2 {
				name = parts[len(parts)-2]
			}
			return registry.Event{Type: registry.EventRemoved, Service: &registry.Service{ID: id, Name: name}}
		}
		var svc registry.Service
		if err := json.Unmarshal(ev.PrevKv.Value, &svc); err != nil {
			return registry.Event{}
		}
		return registry.Event{Type: registry.EventRemoved, Service: &svc}
	default:
		return registry.Event{}
	}
}

// drainKeepAlive consumes the KeepAlive response channel so the etcd client
// doesn't block on backpressure. We don't care about the values; we only need
// the channel drained for KeepAlive to keep working.
func drainKeepAlive(ch <-chan *clientv3.LeaseKeepAliveResponse) {
	for range ch { //nolint:revive
	}
}
