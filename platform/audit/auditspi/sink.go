package auditspi

import (
	"context"
	"errors"
)

// ErrEventNotFound is returned by Sink.Get for unknown event IDs.
var ErrEventNotFound = errors.New("audit: event not found")

// Sink stores and serves audit events. Implementations must be safe for
// concurrent use. The MemorySink in the audit package is the default;
// production backends typically write to a database, file, or log shipper.
type Sink interface {
	Record(ctx context.Context, e *Event) error
	Query(ctx context.Context, q Query) ([]*Event, error)
	Get(ctx context.Context, id string) (*Event, error)
}

// ErrorHandler reports a failure from Sink.Record. Audit recording is best-
// effort by design — a failed sink should never block a login — so the only
// signal is this callback.
type ErrorHandler func(error)
