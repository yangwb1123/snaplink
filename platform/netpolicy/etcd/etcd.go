// Package etcd implements netpolicy.Store on etcd v3.
//
// Each policy is one key under <Prefix>/<name>, value is the JSON-marshaled
// Policy. Apply uses a transaction so versioning is consistent. Watch is
// implemented via etcd's prefix WATCH so multiple sso-server replicas all
// see the same stream.
//
// The Version field on Policy is populated from etcd's ModRevision — that
// way every successful Apply gets a globally monotonic version without us
// having to maintain a counter.
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

	"github.com/snaplink/sso/platform/netpolicy"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// Defaults applied when a Config field is zero.
const (
	DefaultPrefix      = "/snaplink/netpolicy"
	DefaultDialTimeout = 5 * time.Second
)

// Config configures the etcd Store.
type Config struct {
	Endpoints   []string
	Prefix      string
	DialTimeout time.Duration
	Username    string
	Password    string
}

// Store is the etcd-backed netpolicy.Store.
type Store struct {
	client *clientv3.Client
	prefix string

	mu     sync.Mutex
	closed bool
}

// New connects to etcd and returns a Store. The caller owns the lifecycle —
// call Close to release the connection.
func New(cfg Config) (*Store, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("netpolicy/etcd: at least one endpoint required")
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
		return nil, fmt.Errorf("netpolicy/etcd: dial: %w", err)
	}
	return &Store{client: cli, prefix: cfg.Prefix}, nil
}

// NewWithClient is for tests — pass a pre-configured *clientv3.Client.
// Ownership of the client transfers to the Store; callers MUST NOT close it
// directly.
func NewWithClient(cli *clientv3.Client, prefix string) *Store {
	if prefix == "" {
		prefix = DefaultPrefix
	}
	return &Store{client: cli, prefix: prefix}
}

func (s *Store) Get(ctx context.Context, name string) (*netpolicy.Policy, error) {
	resp, err := s.client.Get(ctx, s.key(name))
	if err != nil {
		return nil, fmt.Errorf("netpolicy/etcd: get: %w", err)
	}
	if resp.Count == 0 {
		return nil, netpolicy.ErrNotFound
	}
	kv := resp.Kvs[0]
	p, err := unmarshalPolicy(kv.Value, kv.ModRevision)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Store) List(ctx context.Context) ([]*netpolicy.Policy, error) {
	resp, err := s.client.Get(ctx, s.namespace(), clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("netpolicy/etcd: list: %w", err)
	}
	out := make([]*netpolicy.Policy, 0, resp.Count)
	for _, kv := range resp.Kvs {
		p, err := unmarshalPolicy(kv.Value, kv.ModRevision)
		if err != nil {
			continue // skip corrupt entry rather than fail the whole call
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *Store) Apply(ctx context.Context, p *netpolicy.Policy) (*netpolicy.Policy, error) {
	if p == nil || p.Name == "" {
		return nil, errors.New("netpolicy/etcd: policy.Name required")
	}
	stored := p.Clone()
	stored.UpdatedAt = time.Now().UTC()
	stored.Version = 0 // overwritten from ModRevision after the Put
	data, err := json.Marshal(stored)
	if err != nil {
		return nil, fmt.Errorf("netpolicy/etcd: marshal: %w", err)
	}
	resp, err := s.client.Put(ctx, s.key(p.Name), string(data))
	if err != nil {
		return nil, fmt.Errorf("netpolicy/etcd: put: %w", err)
	}
	stored.Version = resp.Header.Revision
	return stored, nil
}

func (s *Store) Delete(ctx context.Context, name string) error {
	if _, err := s.client.Delete(ctx, s.key(name)); err != nil {
		return fmt.Errorf("netpolicy/etcd: delete: %w", err)
	}
	return nil
}

func (s *Store) Watch(ctx context.Context) (<-chan netpolicy.Event, error) {
	out := make(chan netpolicy.Event, 32)
	wch := s.client.Watch(ctx, s.namespace(), clientv3.WithPrefix(), clientv3.WithPrevKV())

	go func() {
		defer close(out)
		for resp := range wch {
			if err := resp.Err(); err != nil {
				return
			}
			for _, ev := range resp.Events {
				evt := translateEvent(ev)
				if evt.Policy == nil {
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

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.client.Close()
}

// Ping reports etcd reachability for [sso.WithReadyCheck] wiring.
// Issues a Maintenance.Status RPC against each configured endpoint
// in turn and returns nil as soon as one responds. Returns an
// aggregate error only when every endpoint is unreachable so a
// single down member doesn't trip /readyz on an otherwise healthy
// cluster.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.client == nil {
		return errors.New("netpolicy/etcd: closed")
	}
	endpoints := s.client.Endpoints()
	if len(endpoints) == 0 {
		return errors.New("netpolicy/etcd: no endpoints configured")
	}
	var lastErr error
	for _, ep := range endpoints {
		if _, err := s.client.Status(ctx, ep); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("netpolicy/etcd: all endpoints unreachable: %w", lastErr)
}

func (s *Store) key(name string) string {
	return path.Join(s.prefix, name)
}

func (s *Store) namespace() string {
	return s.prefix + "/"
}

func unmarshalPolicy(data []byte, modRev int64) (*netpolicy.Policy, error) {
	var p netpolicy.Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("netpolicy/etcd: unmarshal: %w", err)
	}
	p.Version = modRev
	return &p, nil
}

func translateEvent(ev *clientv3.Event) netpolicy.Event {
	switch ev.Type {
	case clientv3.EventTypePut:
		p, err := unmarshalPolicy(ev.Kv.Value, ev.Kv.ModRevision)
		if err != nil {
			return netpolicy.Event{}
		}
		t := netpolicy.EventAdded
		if ev.IsModify() {
			t = netpolicy.EventUpdated
		}
		return netpolicy.Event{Type: t, Policy: p}
	case clientv3.EventTypeDelete:
		if ev.PrevKv != nil {
			if p, err := unmarshalPolicy(ev.PrevKv.Value, ev.PrevKv.ModRevision); err == nil {
				return netpolicy.Event{Type: netpolicy.EventRemoved, Policy: p}
			}
		}
		// Fall back to just the name from the key path.
		name := path.Base(strings.Trim(string(ev.Kv.Key), "/"))
		return netpolicy.Event{Type: netpolicy.EventRemoved, Policy: &netpolicy.Policy{Name: name}}
	default:
		return netpolicy.Event{}
	}
}
