package main

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/internal/composition"
	"github.com/yangwb1123/snaplink/shared/core"
)

// TestDiscoveryMatchesConfiguredPrototypeClients pins the prototype discovery
// document: OAuth metadata only, the configured (non-openid) scopes, and none
// of the hidden or OIDC-only fields.
func TestDiscoveryMatchesConfiguredPrototypeClients(t *testing.T) {
	cfg := composition.DefaultsFromEnv(func(string) string { return "" }, edition)
	cfg.Issuer = "https://issuer.example"
	cfg.Second.Scopes = []string{"groups"}
	app, err := buildHandler(cfg)
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	server := httptest.NewServer(app)
	t.Cleanup(server.Close)

	document := getJSON(t, server.URL+sso.PathOAuthAuthorizationServerMetadata, "")
	assertStringList(t, document[composition.KeyScopes], []string{
		"profile",
		"email",
		"groups",
	})
	assertStringList(t, document[composition.KeyTokenAuthMethods], []string{
		"client_secret_basic",
		"client_secret_post",
	})
	for _, key := range composition.HiddenMetadataEndpoints {
		if _, exists := document[key]; exists {
			t.Fatalf("prototype discovery advertises %s", key)
		}
	}
	for _, key := range prototypeHiddenMetadata {
		if _, exists := document[key]; exists {
			t.Fatalf("prototype discovery advertises OIDC field %s", key)
		}
	}
}

// TestOPSessionHonorsMaxAge is the shared OP-session behavior: an expired
// session must not satisfy max_age even in the prototype edition.
func TestOPSessionHonorsMaxAge(t *testing.T) {
	cfg := composition.DefaultsFromEnv(func(string) string { return "" }, edition)
	cfg.Issuer = "http://issuer.example"
	server, client, sessions := prototypeServerWithSessions(t, cfg)
	loginForCodeWithClient(t, client, server.URL, cfg, cfg.Client, true)
	setOPSessionAuthTime(t, sessions, time.Now().Add(-10*time.Minute))

	payload := loginPayloadForClient(cfg, cfg.Second)
	delete(payload, "provider")
	delete(payload, "credential")
	payload["max_age"] = 60
	_, body := postJSONWithClient(t, client, server.URL+"/auth/login", payload)
	if body["code"] != nil {
		t.Fatalf("expired OP session satisfied max_age: %v", body)
	}
}

func setOPSessionAuthTime(t *testing.T, gate *composition.OpSessionGate, authTime time.Time) {
	t.Helper()
	mgr := gate.Manager()
	if mgr == nil {
		t.Fatal("no session manager wired")
	}
	sessions, err := mgr.ListByUser(context.Background(), composition.DefaultUserID)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("OP sessions = %d, want 1", len(sessions))
	}
	gate.SetMgr(&agedOPSessionManager{SessionManager: mgr, authTime: authTime})
}

type agedOPSessionManager struct {
	core.SessionManager
	authTime time.Time
}

func (m *agedOPSessionManager) Get(ctx context.Context, id string) (*core.Session, error) {
	session, err := m.SessionManager.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	session.CreatedAt = m.authTime
	return session, nil
}
