package main

import (
	"strings"
	"testing"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildstore"
	"github.com/snaplink/sso/config"
)

// TestBuildNetworkStore_DisabledReturnsNil mirrors the SDK
// contract — when network.enabled=false, cmd's wrapper must return
// (nil, "", nil) so the caller skips classifier wiring.
func TestBuildNetworkStore_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	store, kind, err := serverbuildstore.BuildNetworkStore(&config.NetworkConfig{Enabled: false}, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if store != nil || kind != "" {
		t.Errorf("disabled returned store=%v kind=%q; want nil/empty", store, kind)
	}
}

// TestBuildNetworkStore_MemoryAppliesSeeds proves cmd's wrapper
// delegates to config.BuildNetworkStore for memory + applies seeds
// via the shared helper. Operators expect the YAML policies block
// to be live after startup without an admin RPC.
func TestBuildNetworkStore_MemoryAppliesSeeds(t *testing.T) {
	t.Parallel()
	cfg := &config.NetworkConfig{
		Enabled: true,
		Store:   "memory",
		Policies: []config.NetworkPolicySeed{
			{Name: "intranet", CIDRs: []string{"10.0.0.0/8"}, Priority: 100},
		},
	}
	store, kind, err := serverbuildstore.BuildNetworkStore(cfg, quietLogger())
	if err != nil {
		t.Fatalf("serverbuildstore.BuildNetworkStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	if kind != "memory" {
		t.Errorf("kind = %q; want memory", kind)
	}
	policies, err := store.List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(policies) != 1 || policies[0].Name != "intranet" {
		t.Errorf("seed not applied: %+v", policies)
	}
}

// TestBuildNetworkStore_EtcdRequiresEndpoints proves the etcd path
// surfaces a clear operator-facing error instead of dialing with
// no endpoints (which would silently hang on the etcd client's
// default behavior).
func TestBuildNetworkStore_EtcdRequiresEndpoints(t *testing.T) {
	t.Parallel()
	cfg := &config.NetworkConfig{Enabled: true, Store: "etcd"}
	_, _, err := serverbuildstore.BuildNetworkStore(cfg, quietLogger())
	if err == nil {
		t.Fatal("expected error when etcd_endpoints is empty")
	}
	if !strings.Contains(err.Error(), "etcd_endpoints") {
		t.Errorf("error %q does not mention etcd_endpoints", err)
	}
}

// TestBuildNetworkStore_UnknownBackendErrors guards the validation
// boundary — typos in YAML must fail fast rather than silently
// fall through to a default.
func TestBuildNetworkStore_UnknownBackendErrors(t *testing.T) {
	t.Parallel()
	cfg := &config.NetworkConfig{Enabled: true, Store: "mythical"}
	if _, _, err := serverbuildstore.BuildNetworkStore(cfg, quietLogger()); err == nil {
		t.Fatal("expected error for unknown backend")
	}
}
