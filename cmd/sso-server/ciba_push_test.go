package main

import (
	"context"
	"testing"

	"github.com/snaplink/sso/config"
)

// TestCibaPushEndpointResolver_ResolvesConfiguredClient proves the
// resolver reads back an endpoint registered in cmd config for a known
// client_id.
func TestCibaPushEndpointResolver_ResolvesConfiguredClient(t *testing.T) {
	t.Parallel()
	resolve := cibaPushEndpointResolver(config.CIBAPushConfig{
		Endpoints: map[string]string{"client-a": "https://rp.example/ciba/push"},
	})
	uri, err := resolve(context.Background(), "client-a")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if uri != "https://rp.example/ciba/push" {
		t.Errorf("uri = %q, want https://rp.example/ciba/push", uri)
	}
}

// TestCibaPushEndpointResolver_UnknownClientDegradesToPoll proves a client
// absent from the map resolves to ("", nil) — the notifier's contract for
// "this client uses poll/ping instead", not an error.
func TestCibaPushEndpointResolver_UnknownClientDegradesToPoll(t *testing.T) {
	t.Parallel()
	resolve := cibaPushEndpointResolver(config.CIBAPushConfig{
		Endpoints: map[string]string{"client-a": "https://rp.example/ciba/push"},
	})
	uri, err := resolve(context.Background(), "client-unknown")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if uri != "" {
		t.Errorf("uri = %q, want empty for an unregistered client", uri)
	}
}

// TestCibaPushEndpointResolver_CopiesMap proves the resolver snapshots the
// config map at construction time, so a caller mutating the ORIGINAL map
// afterward can't race the notifier — mirrors newHTTPCIBAPingNotifier's
// same copy-on-construct convention.
func TestCibaPushEndpointResolver_CopiesMap(t *testing.T) {
	t.Parallel()
	eps := map[string]string{"client-a": "https://rp.example/ciba/push"}
	resolve := cibaPushEndpointResolver(config.CIBAPushConfig{Endpoints: eps})
	eps["client-a"] = "https://mutated.example/ciba/push"

	uri, err := resolve(context.Background(), "client-a")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if uri != "https://rp.example/ciba/push" {
		t.Errorf("uri = %q, want the pre-mutation snapshot", uri)
	}
}

// TestWireCIBAPushDelivery_DisabledIsNoOp proves wireCIBAPushDelivery is a
// clean no-op (empty suffix, nil error, no options appended) when push is
// not enabled — byte-identical (poll/ping-only) wiring.
func TestWireCIBAPushDelivery_DisabledIsNoOp(t *testing.T) {
	t.Parallel()
	b := &appBuilder{schemaCtx: context.Background()}
	suffix, err := b.wireCIBAPushDelivery(config.CIBAConfig{}, testNopLogger{})
	if err != nil {
		t.Fatalf("wireCIBAPushDelivery: %v", err)
	}
	if suffix != "" {
		t.Errorf("suffix = %q, want empty when push is disabled", suffix)
	}
	if len(b.opts) != 0 {
		t.Errorf("expected no options appended when push is disabled, got %d", len(b.opts))
	}
}

// TestWireCIBAPushDelivery_EnabledAppendsNotifierOption proves enabling
// push (memory backend, the default) wires a CIBAPushNotifier option and
// returns the "+push" mode suffix, without requiring a SQLite DSN.
func TestWireCIBAPushDelivery_EnabledAppendsNotifierOption(t *testing.T) {
	t.Parallel()
	b := &appBuilder{schemaCtx: context.Background()}
	cfg := config.CIBAConfig{
		Push: config.CIBAPushConfig{
			Enabled:   true,
			Endpoints: map[string]string{"client-a": "https://rp.example/ciba/push"},
		},
	}
	suffix, err := b.wireCIBAPushDelivery(cfg, testNopLogger{})
	if err != nil {
		t.Fatalf("wireCIBAPushDelivery: %v", err)
	}
	if suffix != "+push" {
		t.Errorf("suffix = %q, want +push", suffix)
	}
	if len(b.opts) != 1 {
		t.Fatalf("expected exactly one option appended (WithCIBAPushNotifier), got %d", len(b.opts))
	}
}

// TestWireCIBAPushDelivery_SQLiteBackendWithoutDSNErrors proves the same
// "sqlite_dsn required" guard BuildCIBA enforces for the main CIBA store
// also applies to the dead-letter store, since it reuses the SAME backend
// selection.
func TestWireCIBAPushDelivery_SQLiteBackendWithoutDSNErrors(t *testing.T) {
	t.Parallel()
	b := &appBuilder{schemaCtx: context.Background()}
	cfg := config.CIBAConfig{
		Backend: "sqlite",
		Push:    config.CIBAPushConfig{Enabled: true},
	}
	if _, err := b.wireCIBAPushDelivery(cfg, testNopLogger{}); err == nil {
		t.Fatal("expected an error when backend=sqlite without sqlite_dsn")
	}
}

// testNopLogger is a minimal spi.Logger for these tests.
type testNopLogger struct{}

func (testNopLogger) Info(string, ...any)  {}
func (testNopLogger) Error(string, ...any) {}
func (testNopLogger) Debug(string, ...any) {}
