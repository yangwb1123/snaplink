package webhook

import (
	"context"
	"errors"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// DefaultDeadLetterCapacity bounds the in-memory dead-letter ring when
// NewMemoryDeadLetterStore is called with capacity <= 0.
const DefaultDeadLetterCapacity = 1000

// DefaultDeadLetterListLimit caps a List call whose Filter leaves Limit at
// its zero value.
const DefaultDeadLetterListLimit = 100

// DeadLetterEntry records one delivery that exhausted its retry budget —
// the operator-queryable audit trail of "this subscription didn't get this
// event" so a downstream outage doesn't silently lose events.
type DeadLetterEntry struct {
	ID                   string      `json:"id"`
	SubscriptionID       string      `json:"subscription_id"`
	URL                  string      `json:"url"`
	Event                audit.Event `json:"event"`
	Attempts             int         `json:"attempts"`
	LastError            string      `json:"last_error"`
	FirstFailedAt        time.Time   `json:"first_failed_at"`
	LastFailedAt         time.Time   `json:"last_failed_at"`
	ReplayState          string      `json:"replay_state,omitempty"`
	ReplayIdempotencyKey string      `json:"replay_idempotency_key,omitempty"`
	ReplayStartedAt      time.Time   `json:"replay_started_at,omitempty"`
	DeliveredAt          time.Time   `json:"delivered_at,omitempty"`
	CleanupError         string      `json:"cleanup_error,omitempty"`
}

// DeadLetterFilter narrows DeadLetterStore.List. A zero filter (Limit left
// at 0) returns the DefaultDeadLetterListLimit most recent entries across
// every subscription.
type DeadLetterFilter struct {
	SubscriptionID string
	Limit          int
}

// DeadLetterStore persists exhausted deliveries in a BOUNDED store — it is
// a diagnostic/replay queue, not a durable audit log. Implementations MUST
// be safe for concurrent use.
//
// Add is upsert-by-ID: a caller that already holds an entry's ID (Replay,
// after a repeat failure) overwrites it in place, updating Attempts/
// LastError without disturbing the entry's position in eviction order. An
// empty ID mints a new entry and is subject to capacity eviction.
type DeadLetterStore interface {
	Add(ctx context.Context, entry DeadLetterEntry) (DeadLetterEntry, error)
	Get(ctx context.Context, id string) (DeadLetterEntry, error)
	List(ctx context.Context, f DeadLetterFilter) ([]DeadLetterEntry, error)
	Delete(ctx context.Context, id string) error
}

// ErrDeadLetterNotFound is returned by Get/Replay for an unknown id.
var ErrDeadLetterNotFound = errors.New("webhook: dead-letter entry not found")

var (
	// ErrReplayInProgress prevents a second operator request from sending an
	// event while the first replay has an ambiguous/in-flight outcome.
	ErrReplayInProgress = errors.New("webhook: replay is already in progress")
	// ErrReplayCleanup marks a replay whose delivery succeeded but whose DLQ
	// cleanup did not. The delivered marker remains queryable and makes a
	// later retry cleanup-only.
	ErrReplayCleanup = errors.New("webhook: replay delivered but DLQ cleanup failed")
)

const (
	ReplayStateInProgress      = "in_progress"
	ReplayStateCleanupPending  = "delivered_cleanup_pending"
	ReplayStateDeliveryFailed  = "delivery_failed"
	replayIdempotencyKeyPrefix = "snaplink-webhook-replay:"
)
