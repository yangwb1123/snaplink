package sso_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestConnectionHealthDegradedUX(t *testing.T) {
	t.Parallel()
	store := connections.NewMemoryStore()
	for _, c := range []*connections.Connection{
		{ID: "degraded-idp", TenantID: "acme", Type: connections.TypeOIDC, Domains: []string{"degraded.example"}, Enabled: true},
		{ID: "healthy-idp", TenantID: "acme", Type: connections.TypeOIDC, Domains: []string{"healthy.example"}, Enabled: true},
		{ID: "unknown-idp", TenantID: "acme", Type: connections.TypeOIDC, Domains: []string{"unknown.example"}, Enabled: true},
	} {
		if err := store.Upsert(context.Background(), c); err != nil {
			t.Fatalf("Upsert(%s): %v", c.ID, err)
		}
	}
	if err := store.RecordHealth(context.Background(), "degraded-idp", &connections.ConnectionHealth{
		ConnectionID: "degraded-idp", Status: connections.HealthDegraded,
	}); err != nil {
		t.Fatalf("RecordHealth(degraded): %v", err)
	}
	if err := store.RecordHealth(context.Background(), "healthy-idp", &connections.ConnectionHealth{
		ConnectionID: "healthy-idp", Status: connections.HealthHealthy,
	}); err != nil {
		t.Fatalf("RecordHealth(healthy): %v", err)
	}

	s := rcovNewServer(t, sso.WithConnectionStore(store))
	for _, tc := range []struct {
		name            string
		loginHint       string
		connectionID    string
		wantUnavailable bool
	}{
		{name: "degraded", loginHint: "user@degraded.example", connectionID: "degraded-idp", wantUnavailable: true},
		{name: "healthy", loginHint: "user@healthy.example", connectionID: "healthy-idp"},
		{name: "unknown", loginHint: "user@unknown.example", connectionID: "unknown-idp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertHomeRealmLogin(t, s, tc.loginHint, tc.connectionID, tc.wantUnavailable)
		})
	}
}

func TestConnectionHealthReadErrorFailsOpen(t *testing.T) {
	t.Parallel()
	base := connections.NewMemoryStore()
	if err := base.Upsert(context.Background(), &connections.Connection{
		ID: "error-idp", TenantID: "acme", Type: connections.TypeOIDC,
		Domains: []string{"error.example"}, Enabled: true,
	}); err != nil {
		t.Fatalf("Upsert(error-idp): %v", err)
	}
	s := rcovNewServer(t, sso.WithConnectionStore(&connectionHealthReadErrorStore{Store: base}))
	assertHomeRealmLogin(t, s, "user@error.example", "error-idp", false)
}

func assertHomeRealmLogin(t *testing.T, s *rcovServer, loginHint, connectionID string, wantUnavailable bool) {
	t.Helper()
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"client_id": rcovClient, "login_hint": loginHint,
	})
	if status != http.StatusOK {
		t.Fatalf("home-realm login = %d body=%v, want 200", status, out)
	}
	if out["connection_required"] != true || out["connection_id"] != connectionID {
		t.Fatalf("home-realm response = %v, want connection_required and id %q", out, connectionID)
	}
	value, present := out["unavailable"]
	if wantUnavailable && (!present || value != true) {
		t.Errorf("unavailable = %v (present=%v), want true", value, present)
	}
	if !wantUnavailable && present {
		t.Errorf("unavailable = %v, want key absent", value)
	}
}

type connectionHealthReadErrorStore struct {
	connections.Store
}

func (*connectionHealthReadErrorStore) Health(context.Context, string) (*connections.ConnectionHealth, error) {
	return nil, errors.New("health read failed")
}
