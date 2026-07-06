package mqttbus

import (
	"errors"
	"sync"

	"github.com/snaplink/sso/platform/cluster"
)

// ErrClosed is returned by Publish/Subscribe once Close has been called.
var ErrClosed = errors.New("mqttbus: bus closed")

// Bus is the MQTT-backed cluster.Bus. The caller owns the lifecycle —
// call Close to release resources.
//
// Publish and Subscribe each manage their OWN connection rather than
// sharing one: Publish is a one-shot, fire-and-forget connect-publish-
// disconnect (matching the interface's "fire-and-forget from the
// caller's perspective" contract, and avoiding a ClientID collision with
// Subscribe's persistent session — see client.go's dialConnect doc);
// Subscribe holds one long-lived, persistent-session connection for as
// long as ctx stays live and the transport stays up.
type Bus struct {
	cfg Config

	mu     sync.Mutex
	closed bool
}

var _ cluster.Bus = (*Bus)(nil)

// New validates cfg and returns a Bus. New does not dial — a connection
// is established lazily on the first Publish or Subscribe call.
func New(cfg Config) (*Bus, error) {
	if cfg.BrokerAddr == "" {
		return nil, errors.New("mqttbus: BrokerAddr required")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("mqttbus: ClientID required")
	}
	return &Bus{cfg: cfg.withDefaults()}, nil
}

// Close marks the Bus closed; subsequent Publish/Subscribe calls return
// ErrClosed. Idempotent. Does not itself need to tear down a shared
// connection (there isn't one — see the type doc); an in-flight
// Subscribe's own goroutine notices ctx cancellation independently.
func (b *Bus) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}

func (b *Bus) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}
