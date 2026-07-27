package health_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/federation/health"
	"github.com/yangwb1123/snaplink/shared/core"
)

// fakeHealthDeps is a hand-built health.Deps for the unit test — a real
// MemoryConnectionHealth (no mocks) plus a fixed clock/threshold.
type fakeHealthDeps struct {
	store     health.ConnectionHealth
	threshold time.Duration
	now       time.Time
}

func (d *fakeHealthDeps) FederationConnectionHealth() health.ConnectionHealth { return d.store }
func (d *fakeHealthDeps) FederationCertExpiryWarning() time.Duration          { return d.threshold }
func (d *fakeHealthDeps) FederationHealthNow() time.Time                      { return d.now }

type peersResponse struct {
	Peers []struct {
		PeerID              string `json:"peer_id"`
		LastError           string `json:"last_error"`
		ConsecutiveFailures int    `json:"consecutive_failures"`
		CertNotAfter        string `json:"cert_not_after"`
		CertExpiring        bool   `json:"cert_expiring"`
	} `json:"peers"`
	CertExpiryWarningSeconds int `json:"cert_expiry_warning_seconds"`
}

func doListRequest(t *testing.T, deps health.Deps) peersResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/admin/federation/health", nil)
	ctx := core.NewContext(rec, req)
	health.HandleListPeerHealth(deps, ctx)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out peersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	return out
}

func TestHandleListPeerHealth_NilStoreReturnsEmptyList(t *testing.T) {
	t.Parallel()
	out := doListRequest(t, &fakeHealthDeps{store: nil})
	if len(out.Peers) != 0 {
		t.Fatalf("Peers = %+v, want empty", out.Peers)
	}
}

func TestHandleListPeerHealth_ListsPeersAndFlagsExpiring(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_000, 0)
	store := health.NewMemoryConnectionHealth()
	store.RecordSuccess("https://soon.test", now, now.Add(5*24*time.Hour))
	store.RecordSuccess("https://later.test", now, now.Add(400*24*time.Hour))
	store.RecordFailure("https://down.test", now, "dial timeout")

	deps := &fakeHealthDeps{store: store, threshold: 30 * 24 * time.Hour, now: now}
	out := doListRequest(t, deps)

	if len(out.Peers) != 3 {
		t.Fatalf("Peers len = %d, want 3", len(out.Peers))
	}
	byID := map[string]int{}
	for i, p := range out.Peers {
		byID[p.PeerID] = i
	}
	soon := out.Peers[byID["https://soon.test"]]
	if !soon.CertExpiring {
		t.Fatalf("https://soon.test should be flagged cert_expiring: %+v", soon)
	}
	later := out.Peers[byID["https://later.test"]]
	if later.CertExpiring {
		t.Fatalf("https://later.test should NOT be flagged cert_expiring: %+v", later)
	}
	down := out.Peers[byID["https://down.test"]]
	if down.ConsecutiveFailures != 1 || down.LastError != "dial timeout" || down.CertExpiring {
		t.Fatalf("https://down.test unexpected view: %+v", down)
	}
	wantSeconds := int((30 * 24 * time.Hour).Seconds())
	if out.CertExpiryWarningSeconds != wantSeconds {
		t.Fatalf("cert_expiry_warning_seconds = %d, want %d", out.CertExpiryWarningSeconds, wantSeconds)
	}
}

func TestHandleListPeerHealth_ZeroThresholdUsesDefault(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_000, 0)
	store := health.NewMemoryConnectionHealth()
	// Expires in 10 days: within the 30-day DEFAULT, but the test asserts the
	// default actually applied (threshold left at zero == "unconfigured").
	store.RecordSuccess("https://op.test", now, now.Add(10*24*time.Hour))

	deps := &fakeHealthDeps{store: store, threshold: 0, now: now}
	out := doListRequest(t, deps)
	if len(out.Peers) != 1 || !out.Peers[0].CertExpiring {
		t.Fatalf("expected the default 30d threshold to flag a 10d-out expiry: %+v", out.Peers)
	}
	wantSeconds := int(health.DefaultCertExpiryWarning.Seconds())
	if out.CertExpiryWarningSeconds != wantSeconds {
		t.Fatalf("cert_expiry_warning_seconds = %d, want default %d", out.CertExpiryWarningSeconds, wantSeconds)
	}
}
