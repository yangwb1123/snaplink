package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	signingkeysetcd "github.com/yangwb1123/snaplink/platform/signingkeys/etcd"
	signingkeysmemory "github.com/yangwb1123/snaplink/platform/signingkeys/memory"
)

// wireRegistryReadyz applies the builder's accumulated options to a real
// server and returns the /readyz status code + decoded checks map. srvPtr is
// the forward-declared *sso.Server the wiring closures close over; assigning
// it here mirrors what buildApp does right after sso.NewServer, so the
// registered checks run against a live server exactly as in production.
func wireRegistryReadyz(t *testing.T, b *appBuilder, srvPtr **sso.Server) (int, map[string]string) {
	t.Helper()
	*srvPtr = sso.NewServer(b.opts...)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	(*srvPtr).Handler().ServeHTTP(rec, req)
	var body struct {
		Checks map[string]string `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /readyz: %v body=%s", err, rec.Body.String())
	}
	return rec.Code, body.Checks
}

// TestWireSigningKeyRegistryOpts_EtcdRegistersReadyzCheck proves the etcd
// signing-key registry's ReadyzCheck is wired into /readyz: while a replica's
// publish-lease KeepAlive is degraded its keys are absent from peers' JWKS,
// so tokens it signs fail verification fleet-wide — the LB must be able to
// pull it. The registry is the REAL etcd backend constructed without any I/O
// (nil client), the same construction its own lease state-machine tests use;
// ReadyzCheck never touches the connection. Degraded → error is pinned by
// TestReadyzCheck_DegradedAndRecovered in platform/signingkeys/etcd, and a
// failing check → 503 by TestBuildApp_ReadyCheck_SQLiteFlipsTo503; this test
// pins the missing link — that the check is registered at all.
func TestWireSigningKeyRegistryOpts_EtcdRegistersReadyzCheck(t *testing.T) {
	t.Parallel()
	reg := signingkeysetcd.NewWithClient(nil, signingkeysetcd.Config{})
	b := &appBuilder{cfg: &config.Config{}, logger: quietLogger()}
	var srv *sso.Server
	b.wireSigningKeyRegistryOpts(reg, &srv)

	code, checks := wireRegistryReadyz(t, b, &srv)
	if code != http.StatusOK {
		t.Fatalf("/readyz code = %d checks=%v; want 200", code, checks)
	}
	if got, ok := checks["etcd-signing-key-registry"]; !ok || got != "ok" {
		t.Fatalf("check etcd-signing-key-registry = %q present=%v; want ok / present", got, ok)
	}
	// The aggregation-subscriber check must still ride alongside: the lease
	// check supplements it (publish-side health), it does not replace it
	// (adopt-side health).
	if _, ok := checks["signing-key-aggregation"]; !ok {
		t.Fatalf("signing-key-aggregation check missing; checks=%v", checks)
	}
}

// TestWireSigningKeyRegistryOpts_MemoryAddsNoRegistryCheck pins the memory
// backend's unchanged wiring: process-local fan-out has no lease to lose, so
// no registry-level /readyz check may appear. The aggregation-subscriber
// check must still be present — it guards the Server-side loop regardless of
// backend.
func TestWireSigningKeyRegistryOpts_MemoryAddsNoRegistryCheck(t *testing.T) {
	t.Parallel()
	b := &appBuilder{cfg: &config.Config{}, logger: quietLogger()}
	var srv *sso.Server
	b.wireSigningKeyRegistryOpts(signingkeysmemory.New(), &srv)

	code, checks := wireRegistryReadyz(t, b, &srv)
	if code != http.StatusOK {
		t.Fatalf("/readyz code = %d checks=%v; want 200", code, checks)
	}
	if v, ok := checks["etcd-signing-key-registry"]; ok {
		t.Fatalf("memory backend registered registry check = %q; want absent", v)
	}
	if _, ok := checks["signing-key-aggregation"]; !ok {
		t.Fatalf("signing-key-aggregation check missing; checks=%v", checks)
	}
}

// TestWireSigningKeyRegistryOpts_NilRegistryNoOps pins the disabled path:
// registry unset must contribute zero options, keeping single-node boots
// byte-identical.
func TestWireSigningKeyRegistryOpts_NilRegistryNoOps(t *testing.T) {
	t.Parallel()
	b := &appBuilder{cfg: &config.Config{}, logger: quietLogger()}
	var srv *sso.Server
	b.wireSigningKeyRegistryOpts(nil, &srv)
	if len(b.opts) != 0 {
		t.Fatalf("nil registry appended %d opts; want 0", len(b.opts))
	}
}
