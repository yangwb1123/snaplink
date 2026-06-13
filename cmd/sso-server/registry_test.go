package main

import (
	"os"
	"strings"
	"testing"

	"github.com/snaplink/sso/config"
)

// TestBuildRegistry_MemoryDefault proves an unset / explicit
// memory backend returns the in-process Registry with kind=memory
// so cmd's wrapper preserves the long-standing default behavior.
func TestBuildRegistry_MemoryDefault(t *testing.T) {
	for _, name := range []string{"", "memory"} {
		t.Run("backend="+name, func(t *testing.T) {
			reg, kind, err := buildRegistry(&config.RegistryConfig{Backend: name}, quietLogger())
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			defer func() { _ = reg.Close() }()
			if kind != "memory" {
				t.Errorf("kind = %q; want memory", kind)
			}
		})
	}
}

// TestBuildRegistry_EtcdRequiresEndpoints proves the etcd path
// surfaces a clear operator-facing error instead of dialing with
// no endpoints — same contract buildNetworkStore enforces.
func TestBuildRegistry_EtcdRequiresEndpoints(t *testing.T) {
	cfg := &config.RegistryConfig{Backend: "etcd"}
	_, _, err := buildRegistry(cfg, quietLogger())
	if err == nil {
		t.Fatal("expected error when etcd_endpoints is empty")
	}
	if !strings.Contains(err.Error(), "etcd_endpoints") {
		t.Errorf("error %q does not mention etcd_endpoints", err)
	}
}

// TestBuildRegistry_UnknownBackendErrors guards the validation
// boundary — typos in YAML must fail fast.
func TestBuildRegistry_UnknownBackendErrors(t *testing.T) {
	cfg := &config.RegistryConfig{Backend: "mythical"}
	if _, _, err := buildRegistry(cfg, quietLogger()); err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

// TestResolveServiceID_ExplicitWins proves the explicit YAML value
// short-circuits hostname lookup — operators with strict naming
// schemes (e.g. k8s pod name templating) need that override path.
func TestResolveServiceID_ExplicitWins(t *testing.T) {
	if got := resolveServiceID("pod-7", "sso"); got != "pod-7" {
		t.Errorf("resolveServiceID(explicit) = %q; want pod-7", got)
	}
	// Whitespace-only is treated as empty (matches the
	// strings.TrimSpace gate).
	got := resolveServiceID("   ", "sso")
	if got == "   " {
		t.Errorf("whitespace explicit not trimmed: %q", got)
	}
}

// TestResolveServiceID_DerivesFromHostname proves the default path
// produces a stable per-replica id so two pods of the same issuer
// don't collide on the etcd key — the bug a hardcoded "sso-1" had
// before this wiring.
func TestResolveServiceID_DerivesFromHostname(t *testing.T) {
	host, err := os.Hostname()
	if err != nil || host == "" {
		t.Skip("hostname lookup failed; skipping derivation test")
	}
	short := host
	if idx := strings.IndexByte(short, '.'); idx > 0 {
		short = short[:idx]
	}
	want := "sso-" + short
	if got := resolveServiceID("", "sso"); got != want {
		t.Errorf("resolveServiceID(default) = %q; want %q", got, want)
	}
}
