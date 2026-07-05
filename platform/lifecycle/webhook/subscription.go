package webhook

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/snaplink/sso/platform/audit"
)

// EventSubscription is an operator-registered webhook destination: a
// destination URL plus the audit.EventType vocabulary it wants pushed, and
// the per-subscription HMAC secret the Engine signs each delivery with.
//
// Zero registered subscriptions is the default state and produces ZERO
// webhook traffic — see doc.go.
type EventSubscription struct {
	ID          string
	URL         string
	EventTypes  []audit.EventType
	Secret      string
	Description string
	Disabled    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Matches reports whether an enabled subscription wants events of type t. A
// disabled subscription, or one with no configured EventTypes, never
// matches — there is no implicit "everything" wildcard; an operator must
// opt into each type explicitly.
func (s EventSubscription) Matches(t audit.EventType) bool {
	if s.Disabled {
		return false
	}
	for _, want := range s.EventTypes {
		if want == t {
			return true
		}
	}
	return false
}

// Validate checks the invariants every SubscriptionStore implementation
// MUST enforce: at least one subscribed event type, a signing secret (HMAC
// signing is not optional for this engine — every subscription must be
// independently verifiable by its receiver), and an https destination.
// Exported so both the admin HTTP handlers and a caller wiring subscriptions
// directly in Go share the SAME check.
func (s EventSubscription) Validate() error {
	if len(s.EventTypes) == 0 {
		return ErrNoEventTypes
	}
	if s.Secret == "" {
		return ErrSecretRequired
	}
	return validateHTTPSURL(s.URL)
}

// validateHTTPSURL enforces the same anti-SSRF/anti-exfil invariant
// protocols/caep.ValidateReceiverEndpoint applies to CAEP receiver
// endpoints: an absolute https URL with a host. Declared independently
// (rather than imported) because platform/lifecycle/webhook sits BELOW protocols/caep
// in the layer ordering (AGENTS.md §0.2 / architecture_layer_test.go) — a
// domains package may never import a protocols package.
func validateHTTPSURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ErrInvalidURL
	}
	return nil
}

// SubscriptionStore persists EventSubscriptions. Implementations MUST be
// safe for concurrent use and MUST enforce EventSubscription.Validate on
// Create. Create assigns ID/CreatedAt/UpdatedAt when the caller leaves them
// zero (mirrors audit.Event.ID: "assigned by the Sink on Record, callers
// leave it empty"). Delete is idempotent — removing an unknown id returns
// nil, matching platform/netpolicy.Store's discipline.
type SubscriptionStore interface {
	Create(ctx context.Context, sub EventSubscription) (EventSubscription, error)
	Get(ctx context.Context, id string) (EventSubscription, error)
	List(ctx context.Context) ([]EventSubscription, error)
	Delete(ctx context.Context, id string) error
}

var (
	// ErrSubscriptionNotFound is returned by Get for an unknown id.
	ErrSubscriptionNotFound = errors.New("webhook: subscription not found")
	// ErrInvalidURL is returned when the destination is not an absolute
	// https URL with a host.
	ErrInvalidURL = errors.New("webhook: destination must be an https URL with a host")
	// ErrNoEventTypes is returned when EventTypes is empty — a subscription
	// with no vocabulary would silently never fire, which is more likely an
	// operator mistake than an intentional no-op registration.
	ErrNoEventTypes = errors.New("webhook: at least one event type is required")
	// ErrSecretRequired is returned when Secret is empty.
	ErrSecretRequired = errors.New("webhook: a signing secret is required")
)
