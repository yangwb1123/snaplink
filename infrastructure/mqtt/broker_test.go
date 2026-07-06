package mqttbus

import (
	"sync"
	"testing"
	"time"

	mqttserver "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/hooks/auth"
	"github.com/mochi-mqtt/server/v2/listeners"
)

// testBroker wraps *mqttserver.Server with an idempotent Close: mochi's
// own Close() unconditionally does `close(s.done)` with no internal
// once-guard, so calling it twice panics — a real gotcha of the library,
// not this package. Tests that deliberately kill the broker mid-test
// (e.g. TestBus_SubscribeChannelClosesWhenBrokerDies) still need
// t.Cleanup's own Close call to be a safe no-op afterward.
type testBroker struct {
	*mqttserver.Server
	closeOnce sync.Once
}

func (b *testBroker) Close() error {
	var err error
	b.closeOnce.Do(func() { err = b.Server.Close() })
	return err
}

// newTestBroker spins up an in-process mochi-mqtt broker on a random
// loopback port — no real MQTT daemon or Docker needed in CI, mirroring
// infrastructure/redis's miniredis pattern. Returns the broker (so a test
// can Close it mid-test to exercise Subscribe's disconnect-detection
// path) and its "host:port" address.
func newTestBroker(t *testing.T) (*testBroker, string) {
	t.Helper()
	srv := mqttserver.New(&mqttserver.Options{InlineClient: false})
	if err := srv.AddHook(new(auth.AllowHook), nil); err != nil {
		t.Fatalf("add allow-all auth hook: %v", err)
	}
	tcp := listeners.NewTCP(listeners.Config{ID: "test", Address: "127.0.0.1:0"})
	if err := srv.AddListener(tcp); err != nil {
		t.Fatalf("add tcp listener: %v", err)
	}
	go func() { _ = srv.Serve() }()
	b := &testBroker{Server: srv}
	t.Cleanup(func() { _ = b.Close() })
	// AddListener's Init binds synchronously so Address() is already
	// valid, but give Serve a moment to start accepting.
	time.Sleep(20 * time.Millisecond)
	return b, tcp.Address()
}
