package connections_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/connections"
)

// fakeProber is a deterministic Prober test double — no real network — used
// to drive RunProbe's store-orchestration behavior independent of the
// production httpProber's HTTP parsing.
type fakeProber struct {
	result connections.ProbeResult
	calls  int
}

func (f *fakeProber) Probe(_ context.Context, _ *connections.Connection) connections.ProbeResult {
	f.calls++
	return f.result
}

func TestRunProbe_HealthyPersistsAndAdvancesLastSuccess(t *testing.T) {
	store := connections.NewMemoryStore()
	ctx := context.Background()
	conn := &connections.Connection{ID: "acme", TenantID: "t1", Type: connections.TypeOIDC}
	if err := store.Upsert(ctx, conn); err != nil {
		t.Fatal(err)
	}

	// Before any probe: unknown, zero timestamps.
	h, err := store.Health(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if h.Status != connections.HealthUnknown || !h.LastCheckedAt.IsZero() {
		t.Fatalf("pre-probe health = %+v, want unknown/zero", h)
	}

	prober := &fakeProber{result: connections.ProbeResult{Status: connections.HealthHealthy}}
	got, err := connections.RunProbe(ctx, store, prober, conn)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != connections.HealthHealthy || got.LastCheckedAt.IsZero() || got.LastSuccessAt.IsZero() {
		t.Fatalf("RunProbe healthy = %+v", got)
	}
	if prober.calls != 1 {
		t.Fatalf("prober called %d times, want 1", prober.calls)
	}

	// Persisted — a fresh Health() read returns the same outcome.
	reread, err := store.Health(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if reread.Status != connections.HealthHealthy || reread.LastSuccessAt.IsZero() {
		t.Fatalf("reread = %+v", reread)
	}
}

func TestRunProbe_FailurePreservesPriorLastSuccess(t *testing.T) {
	store := connections.NewMemoryStore()
	ctx := context.Background()
	conn := &connections.Connection{ID: "acme", TenantID: "t1", Type: connections.TypeOIDC}
	if err := store.Upsert(ctx, conn); err != nil {
		t.Fatal(err)
	}

	// First probe succeeds.
	if _, err := connections.RunProbe(ctx, store, &fakeProber{result: connections.ProbeResult{Status: connections.HealthHealthy}}, conn); err != nil {
		t.Fatal(err)
	}
	firstSuccess, err := store.Health(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}

	// Second probe fails — LastSuccessAt must NOT regress to zero.
	time.Sleep(2 * time.Millisecond) // ensure a distinguishable LastCheckedAt
	failing := &fakeProber{result: connections.ProbeResult{Status: connections.HealthUnreachable, Err: "dial tcp: connection refused"}}
	got, err := connections.RunProbe(ctx, store, failing, conn)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != connections.HealthUnreachable {
		t.Fatalf("status = %v, want unreachable", got.Status)
	}
	if !got.LastSuccessAt.Equal(firstSuccess.LastSuccessAt) {
		t.Errorf("LastSuccessAt = %v, want unchanged %v", got.LastSuccessAt, firstSuccess.LastSuccessAt)
	}
	if got.LastError == "" {
		t.Error("LastError should be populated on failure")
	}
	if !got.LastCheckedAt.After(firstSuccess.LastCheckedAt) {
		t.Errorf("LastCheckedAt did not advance: %v vs %v", got.LastCheckedAt, firstSuccess.LastCheckedAt)
	}
}

func TestRunProbe_ErrorTruncated(t *testing.T) {
	store := connections.NewMemoryStore()
	ctx := context.Background()
	conn := &connections.Connection{ID: "acme", TenantID: "t1", Type: connections.TypeOIDC}
	if err := store.Upsert(ctx, conn); err != nil {
		t.Fatal(err)
	}
	longErr := make([]byte, connections.MaxHealthErrorLen*2)
	for i := range longErr {
		longErr[i] = 'x'
	}
	prober := &fakeProber{result: connections.ProbeResult{Status: connections.HealthDegraded, Err: string(longErr)}}
	got, err := connections.RunProbe(ctx, store, prober, conn)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.LastError) != connections.MaxHealthErrorLen {
		t.Errorf("LastError len = %d, want %d", len(got.LastError), connections.MaxHealthErrorLen)
	}
}

// --- httpProber (production implementation) ---

func TestHTTPProber_OIDC_Healthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "https://idp.example.com"})
	}))
	defer srv.Close()

	prober := connections.NewHTTPProber(2 * time.Second)
	conn := &connections.Connection{ID: "acme", Type: connections.TypeOIDC, Config: map[string]string{
		connections.ConfigKeyOIDCIssuer: srv.URL,
	}}
	got := prober.Probe(context.Background(), conn)
	if got.Status != connections.HealthHealthy {
		t.Fatalf("probe = %+v, want healthy", got)
	}
}

func TestHTTPProber_OIDC_DegradedOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	prober := connections.NewHTTPProber(2 * time.Second)
	conn := &connections.Connection{ID: "acme", Type: connections.TypeOIDC, Config: map[string]string{
		connections.ConfigKeyOIDCIssuer: srv.URL,
	}}
	got := prober.Probe(context.Background(), conn)
	if got.Status != connections.HealthDegraded {
		t.Fatalf("probe = %+v, want degraded", got)
	}
	if got.Err == "" {
		t.Error("want a non-empty error detail")
	}
}

func TestHTTPProber_OIDC_DegradedOnMalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>not json</html>"))
	}))
	defer srv.Close()

	prober := connections.NewHTTPProber(2 * time.Second)
	conn := &connections.Connection{ID: "acme", Type: connections.TypeOIDC, Config: map[string]string{
		connections.ConfigKeyOIDCIssuer: srv.URL,
	}}
	got := prober.Probe(context.Background(), conn)
	if got.Status != connections.HealthDegraded {
		t.Fatalf("probe = %+v, want degraded", got)
	}
}

func TestHTTPProber_OIDC_UnreachableOnMissingConfig(t *testing.T) {
	prober := connections.NewHTTPProber(2 * time.Second)
	conn := &connections.Connection{ID: "acme", Type: connections.TypeOIDC}
	got := prober.Probe(context.Background(), conn)
	if got.Status != connections.HealthUnreachable {
		t.Fatalf("probe = %+v, want unreachable", got)
	}
}

func TestHTTPProber_OIDC_UnreachableOnDialFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	badURL := srv.URL
	srv.Close() // closed immediately — the port is now refusing connections

	prober := connections.NewHTTPProber(2 * time.Second)
	conn := &connections.Connection{ID: "acme", Type: connections.TypeOIDC, Config: map[string]string{
		connections.ConfigKeyOIDCIssuer: badURL,
	}}
	got := prober.Probe(context.Background(), conn)
	if got.Status != connections.HealthUnreachable {
		t.Fatalf("probe = %+v, want unreachable", got)
	}
}

func TestHTTPProber_SAML_Healthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/saml"></EntityDescriptor>`))
	}))
	defer srv.Close()

	prober := connections.NewHTTPProber(2 * time.Second)
	conn := &connections.Connection{ID: "acme", Type: connections.TypeSAML, Config: map[string]string{
		connections.ConfigKeySAMLMetadataURL: srv.URL,
	}}
	got := prober.Probe(context.Background(), conn)
	if got.Status != connections.HealthHealthy {
		t.Fatalf("probe = %+v, want healthy", got)
	}
}

func TestHTTPProber_SAML_DegradedOnNonMetadataXML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<not-metadata/>`))
	}))
	defer srv.Close()

	prober := connections.NewHTTPProber(2 * time.Second)
	conn := &connections.Connection{ID: "acme", Type: connections.TypeSAML, Config: map[string]string{
		connections.ConfigKeySAMLMetadataURL: srv.URL,
	}}
	got := prober.Probe(context.Background(), conn)
	if got.Status != connections.HealthDegraded {
		t.Fatalf("probe = %+v, want degraded", got)
	}
}

func TestHTTPProber_UnsupportedType(t *testing.T) {
	prober := connections.NewHTTPProber(2 * time.Second)
	conn := &connections.Connection{ID: "acme", Type: connections.ConnectionType("ldap")}
	got := prober.Probe(context.Background(), conn)
	if got.Status != connections.HealthUnreachable {
		t.Fatalf("probe = %+v, want unreachable", got)
	}
}

// TestRunProbe_StoreHealthErrorPropagates proves a Health() read failure is
// surfaced rather than silently treated as "no prior success" (fail-closed
// on the read side of the orchestration, mirroring VerifyDomainOwnership's
// discipline for the claim-lookup step).
func TestRunProbe_StoreHealthErrorPropagates(t *testing.T) {
	store := &erroringHealthStore{Store: connections.NewMemoryStore()}
	conn := &connections.Connection{ID: "acme", Type: connections.TypeOIDC}
	_, err := connections.RunProbe(context.Background(), store, &fakeProber{result: connections.ProbeResult{Status: connections.HealthHealthy}}, conn)
	if err == nil {
		t.Fatal("want an error from a failing Health() read")
	}
}

type erroringHealthStore struct {
	connections.Store
}

func (e *erroringHealthStore) Health(context.Context, string) (*connections.ConnectionHealth, error) {
	return nil, errors.New("boom")
}
