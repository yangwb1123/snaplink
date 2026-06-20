package netpolicy

import "context"

// Store is the persistence interface for network policies. Implementations
// must be safe for concurrent use.
//
// Apply is upsert: same name overwrites. The store stamps Version and
// UpdatedAt on every write. Delete is idempotent — removing a missing
// name returns nil (so reconciliation loops don't churn on already-clean
// state).
type Store interface {
	Get(ctx context.Context, name string) (*Policy, error)
	List(ctx context.Context) ([]*Policy, error)
	Apply(ctx context.Context, p *Policy) (*Policy, error)
	Delete(ctx context.Context, name string) error

	// Watch streams changes to any policy. The channel closes when ctx is
	// done or the store is closed. Slow consumers may miss events — clients
	// must seed their state via List() at startup and on reconnect.
	Watch(ctx context.Context) (<-chan Event, error)

	// Close releases backend resources (etcd connection, watcher goroutines).
	// Safe to call multiple times.
	Close() error
}
