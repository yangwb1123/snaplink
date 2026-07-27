package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
)

const (
	tokenClientID = "tok-client"
	tokenSecret   = "shh-secret-value"
)

func newTokenHarness(t *testing.T, withDeps bool) (*httptest.Server, *audit.MemorySink) {
	t.Helper()

	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)

	opts := []sso.Option{sso.WithAuditRecorder(rec)}

	if withDeps {
		issuer := defaultimpl.NewEd25519JWTIssuer(
			defaultimpl.WithEd25519Issuer("tok-test"),
			defaultimpl.WithEd25519TokenTTL(time.Minute),
		)
		clients := defaultimpl.NewMemoryClientStore()
		clients.AddSeed(&sso.Client{
			ID: tokenClientID, Secret: tokenSecret, Name: "Tok",
			AllowedAuthenticators: []string{"password"},
			TokenStrategy:         "jwt",
			Active:                true,
		})
		opts = append(opts,
			sso.WithTokenIssuer("jwt", issuer),
			sso.WithDefaultTokenStrategy("jwt"),
			sso.WithClientStore(clients),
		)
	}

	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, sink
}

func postToken(t *testing.T, srv *httptest.Server, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/token", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST /auth/token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(respBody, &out)
	return resp.StatusCode, out
}

// ---------- prerequisite failures ----------

func TestToken_MissingDeps_500(t *testing.T) {
	srv, _ := newTokenHarness(t, false) // no token issuer / no client store
	code, body := postToken(t, srv, map[string]any{
		"grant_type": "client_credentials", "client_id": "x", "client_secret": "y",
	})
	if code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", code)
	}
	if body["error"] != "server_misconfigured" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestToken_BadJSON_400(t *testing.T) {
	srv, _ := newTokenHarness(t, true)
	resp, err := http.Post(srv.URL+"/token", "application/json",
		bytes.NewReader([]byte("{not json")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestToken_UnknownClient_401(t *testing.T) {
	srv, _ := newTokenHarness(t, true)
	code, body := postToken(t, srv, map[string]any{
		"grant_type": "client_credentials", "client_id": "no-such", "client_secret": "x",
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
	if body["error"] != "invalid_client" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestToken_BadSecret_401(t *testing.T) {
	srv, _ := newTokenHarness(t, true)
	code, body := postToken(t, srv, map[string]any{
		"grant_type": "client_credentials", "client_id": tokenClientID, "client_secret": "wrong",
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
	// RFC 6749 §5.2: a bad secret is a client-auth failure -> invalid_client,
	// the SAME code an unknown client_id returns (see TestToken above). Equal
	// codes are required for conformance AND to keep the endpoint from leaking
	// which client_ids exist (enumeration oracle).
	if body["error"] != "invalid_client" {
		t.Errorf("error = %v, want invalid_client", body["error"])
	}
}

// ---------- grant types ----------

func TestToken_ClientCredentials_HappyPath(t *testing.T) {
	srv, sink := newTokenHarness(t, true)

	code, body := postToken(t, srv, map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     tokenClientID,
		"client_secret": tokenSecret,
		"scope":         "read write",
	})
	if code != http.StatusOK {
		t.Fatalf("status = %d body=%v", code, body)
	}
	tok, _ := body["access_token"].(string)
	if tok == "" {
		t.Errorf("access_token empty: %v", body)
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", body["token_type"])
	}
	if body["scope"] != "read write" {
		t.Errorf("scope = %v", body["scope"])
	}
	if body["token_strategy"] != "jwt" {
		t.Errorf("token_strategy = %v", body["token_strategy"])
	}

	// One token_issued audit event with the client id as actor.
	events, _ := sink.Query(context.Background(), audit.Query{Type: audit.EventTokenIssued})
	if len(events) != 1 {
		t.Errorf("token_issued audit events = %d, want 1", len(events))
	} else if events[0].ActorID != tokenClientID {
		t.Errorf("audit ActorID = %q, want %q", events[0].ActorID, tokenClientID)
	}
}

// TestToken_ClientCredentials_PublicClientRejected guards RFC 6749 §4.4: the
// client_credentials grant MUST only be used by confidential clients. A public
// client (no stored secret, token_endpoint_auth_method=none) passes the auth
// ladder via the empty-secret match, so without the confidential gate anyone
// knowing the public client_id (public by design) could mint a token bearing
// its full allowlist with no credential. Must collapse to invalid_client.
func TestToken_ClientCredentials_PublicClientRejected(t *testing.T) {
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "public-spa", Secret: "", Name: "Public SPA",
		AllowedScopes: []string{"payments:write", "accounts:admin"},
		TokenStrategy: "jwt", Active: true,
	})
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithClientStore(clients),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	code, body := postToken(t, httpSrv, map[string]any{
		"grant_type": "client_credentials", "client_id": "public-spa",
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%v, want 401 (public client_credentials must be rejected)", code, body)
	}
	if body["error"] != "invalid_client" {
		t.Errorf("error = %v, want invalid_client", body["error"])
	}
	if body["access_token"] != nil {
		t.Errorf("a token was minted for a public client_credentials request: %v", body)
	}
}

func TestToken_AuthorizationCode_NotImplementedWithoutStore(t *testing.T) {
	// The token harness wires a client but no oauth.AuthCodeStore; the
	// authorization_code branch should return 501 with the dedicated
	// error code.
	srv, _ := newTokenHarness(t, true)
	code, body := postToken(t, srv, map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     tokenClientID,
		"client_secret": tokenSecret,
		"code":          "x",
	})
	if code != http.StatusNotImplemented {
		t.Fatalf("status = %d body=%v, want 501", code, body)
	}
	if body["error"] != "authorization_code_not_configured" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestToken_RefreshToken_NotImplementedWithoutStore(t *testing.T) {
	// The token harness wires a client but no oauth.RefreshTokenStore; the
	// refresh_token branch should return 501 with the dedicated error
	// code.
	srv, _ := newTokenHarness(t, true)
	code, body := postToken(t, srv, map[string]any{
		"grant_type":    "refresh_token",
		"client_id":     tokenClientID,
		"client_secret": tokenSecret,
		"refresh_token": "x",
	})
	if code != http.StatusNotImplemented {
		t.Fatalf("status = %d body=%v, want 501", code, body)
	}
	if body["error"] != "refresh_token_not_configured" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestToken_UnsupportedGrant_400(t *testing.T) {
	srv, _ := newTokenHarness(t, true)
	code, body := postToken(t, srv, map[string]any{
		"grant_type":    "password",
		"client_id":     tokenClientID,
		"client_secret": tokenSecret,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if body["error"] != "unsupported_grant_type" {
		t.Errorf("error = %v", body["error"])
	}
	// supported_grants list must be included so SPAs can render a hint.
	grants, _ := body["supported_grants"].([]any)
	if len(grants) == 0 {
		t.Errorf("supported_grants missing: %v", body)
	}
}

func TestToken_ClientCredentials_NoStrategyConfigured(t *testing.T) {
	// Build a server that has a client store but no token issuer with
	// the strategy the client requests — Step 2's DepTokenIssuer guard
	// passes (we DO register a fallback issuer), but issuerForClient
	// can't find the named strategy.
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "mismatch-client", Secret: "s",
		TokenStrategy: "nonexistent", // strategy not registered
		Active:        true,
	})
	// Wire SOME issuer so requireDeps passes — but it's under a
	// different name from what the client asks for.
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("session", defaultimpl.NewSessionTokenIssuer()),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	body, _ := json.Marshal(map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     "mismatch-client",
		"client_secret": "s",
	})
	resp, err := http.Post(httpSrv.URL+"/token", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (no matching strategy)", resp.StatusCode)
	}
}
