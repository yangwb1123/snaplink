// Package etcd implements config.Source against etcd v3, so operators
// can park a node's configuration in etcd alongside service discovery
// and have it picked up by every sso-server on startup.
//
// Layout: each etcd key under <Prefix>/ is treated as one dotted config
// path, with '/' as the separator. The leaf value is run through
// parse.Value (yaml.Unmarshal), so "true" → bool, "42" → int, "5s" →
// string-as-duration (parsed downstream by goccy/go-yaml into the
// typed *Config). Operators who want to drop a whole subtree at one
// key can put a YAML literal there — it gets parsed as a map and
// folded into the tree.
//
// Example:
//
//	$ etcdctl put /snaplink/config/server/listen ':9090'
//	$ etcdctl put /snaplink/config/logging/level debug
//	$ etcdctl put /snaplink/config/bootstrap/disabled true
//	$ etcdctl put /snaplink/config/snapshot '{enabled: true, storage: {backend: file, file: {dir: /var/lib/sso}}}'
//
// matches the YAML:
//
//	server: {listen: ":9090"}
//	logging: {level: "debug"}
//	bootstrap: {disabled: true}
//	snapshot:
//	  enabled: true
//	  storage: {backend: "file", file: {dir: "/var/lib/sso"}}
//
// The Source intentionally re-fetches on every Load and does NOT watch
// — config-file semantics are "boot-time", and watching would require
// either a hot-reload pathway through *Config (which doesn't exist) or
// a process restart (which the operator can do via a redeploy).
//
// Place this source AFTER FileSource and BEFORE FlagSource in the
// Loader chain so an operator's CLI override still wins:
//
//	config.LoadFromSources(ctx,
//	    config.NewFileSource(cfgPath),
//	    config.NewEnvSource(),
//	    etcd.NewSource(...),    // remote ops, overrides local file + env
//	    flagSource,             // CLI override always wins
//	)
package etcd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso/config/internal/parse"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// Defaults applied when a Config field is zero.
const (
	DefaultPrefix      = "/snaplink/config"
	DefaultDialTimeout = 5 * time.Second
)

// Config configures the etcd Source.
type Config struct {
	Endpoints   []string      // etcd cluster endpoints, e.g. ["localhost:2379"]
	Prefix      string        // key namespace; defaults to DefaultPrefix
	DialTimeout time.Duration // connect timeout; defaults to DefaultDialTimeout
	Username    string
	Password    string
}

// Source is the etcd-backed config.Source.
type Source struct {
	client *clientv3.Client
	prefix string
}

// New connects to etcd and returns a Source. The caller owns the
// lifecycle — call Close to release the connection.
func New(cfg Config) (*Source, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("config/etcd: at least one endpoint required")
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
		return nil, fmt.Errorf("config/etcd: dial: %w", err)
	}
	return &Source{client: cli, prefix: cfg.Prefix}, nil
}

// NewWithClient is for tests and for callers that already hold a
// shared *clientv3.Client. Ownership of the client transfers to the
// Source; callers MUST NOT Close it directly if they call (*Source).Close.
func NewWithClient(cli *clientv3.Client, prefix string) *Source {
	if prefix == "" {
		prefix = DefaultPrefix
	}
	return &Source{client: cli, prefix: prefix}
}

// Name returns "etcd:<prefix>", matching the convention every Loader
// error message uses to identify which source failed.
func (s *Source) Name() string {
	return "etcd:" + s.prefix
}

// Load fetches every key under the prefix in a single Get-with-prefix,
// projects each into a config path via parseKey, and folds the values
// (coerced through parse.Value) into a nested map.
//
// The supplied ctx is honored as-is — callers wanting a deadline
// should wrap with context.WithTimeout themselves. The Loader passes
// its own ctx straight through, so the operator controls the budget.
//
// Errors are returned wrapped with the package name; the Loader will
// re-wrap with the Source's Name().
func (s *Source) Load(ctx context.Context) (map[string]any, error) {
	if s.client == nil {
		return nil, errors.New("config/etcd: nil client")
	}
	// Trailing slash on the Get prefix is what prevents the
	// "/snaplink/config" → "/snaplink/configX/..." prefix-collision
	// trap. parseKey ALSO defends against this for the case where the
	// etcd server is configured with a stricter scheme, but the
	// trailing slash is the cheap layer-1 fix.
	resp, err := s.client.Get(ctx, s.prefix+"/", clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("config/etcd: get %s: %w", s.prefix, err)
	}
	kvs := make([]kv, 0, len(resp.Kvs))
	for _, x := range resp.Kvs {
		kvs = append(kvs, kv{Key: string(x.Key), Value: string(x.Value)})
	}
	return buildConfigMap(s.prefix, kvs), nil
}

// Close releases the etcd connection. Idempotent.
func (s *Source) Close() error {
	if s.client == nil {
		return nil
	}
	return s.client.Close()
}

// Ping reports etcd reachability for [sso.WithReadyCheck] wiring.
// Config etcd is loaded once at startup, but operators running the
// loader against a live etcd cluster (e.g. for env-overlay reloads)
// still benefit from a readiness signal that catches a disappeared
// keyspace before a reload silently leaves stale config in place.
// Returns nil as soon as one configured endpoint responds; only
// fails when every endpoint is unreachable.
func (s *Source) Ping(ctx context.Context) error {
	if s == nil || s.client == nil {
		return errors.New("config/etcd: closed")
	}
	endpoints := s.client.Endpoints()
	if len(endpoints) == 0 {
		return errors.New("config/etcd: no endpoints configured")
	}
	var lastErr error
	for _, ep := range endpoints {
		if _, err := s.client.Status(ctx, ep); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("config/etcd: all endpoints unreachable: %w", lastErr)
}

// kv is the thin internal shape used by buildConfigMap so the pure-logic
// projection doesn't pull etcd types into its signature.
type kv struct {
	Key, Value string
}

// buildConfigMap is the pure-logic core of Load. Extracted so unit
// tests can exercise the key-to-path projection + value coercion
// without standing up an etcd server.
func buildConfigMap(prefix string, kvs []kv) map[string]any {
	out := map[string]any{}
	for _, x := range kvs {
		path := parseKey(prefix, x.Key)
		if len(path) == 0 {
			continue
		}
		parse.SetPath(out, path, parse.Value(x.Value))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseKey converts a full etcd key into a config path by stripping
// the prefix and splitting on '/'. Returns nil when the key isn't
// under the prefix or has no path component left after stripping.
//
// Segments are lowercased to match the yaml field tags used throughout
// the codebase (all snake_case lower).
func parseKey(prefix, full string) []string {
	p := strings.TrimRight(prefix, "/")
	// Enforce the slash boundary so prefix "/snaplink/config" doesn't
	// match key "/snaplink/configX/...". Allow exact-match (handled by
	// the trim below) so the caller can detect "bare prefix" cleanly.
	if full != p && !strings.HasPrefix(full, p+"/") {
		return nil
	}
	suffix := strings.TrimPrefix(full, p)
	suffix = strings.Trim(suffix, "/")
	if suffix == "" {
		return nil
	}
	parts := strings.Split(suffix, "/")
	out := make([]string, 0, len(parts))
	for _, x := range parts {
		if x == "" {
			continue
		}
		out = append(out, strings.ToLower(x))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
