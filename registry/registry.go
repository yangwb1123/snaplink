package registry

import (
	"context"
	"errors"
)

// ErrNotFound is returned by Discover when no instances exist for a name.
var ErrNotFound = errors.New("registry: service not found")

// Registry is the contract every backend (memory, etcd, consul, ...) implements.
//
// Implementations must be safe for concurrent use. Watch channels MUST be
// closed when the supplied ctx is canceled and on Close().
type Registry interface {
	// Register adds (or replaces) the instance. Backends with TTL support
	// start renewing automatically; the caller does not need to heartbeat.
	Register(ctx context.Context, svc *Service) error

	// Deregister removes the instance with the given ID. It is not an error
	// to deregister an unknown instance.
	Deregister(ctx context.Context, instanceID string) error

	// Discover lists currently-healthy instances of a service.
	// Returns ErrNotFound when no instances are registered.
	Discover(ctx context.Context, serviceName string) ([]*Service, error)

	// Watch streams changes (Added / Removed / Updated) for a service name.
	// The returned channel is closed when ctx is canceled or Close is called.
	Watch(ctx context.Context, serviceName string) (<-chan Event, error)

	// Close releases backend resources (etcd client, lease keepalives, etc.).
	// Safe to call multiple times.
	Close() error
}
