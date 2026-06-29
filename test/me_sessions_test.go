package ssotest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// newMeSessionsHarness wires a minimal server for /sessions/me and
// /consents/me tests: a password authenticator + Ed25519 JWT issuer +
// in-memory session manager + optional consent store. Returns the test
// server, the session manager (so callers can pre-seed sessions), a
// per-user login helper, and a second user ID for cross-user tests.
func newMeSessionsHarness(t *testing.T) (
	srv *httptest.Server,
	sessions *defaultimpl.MemorySessionManager,
	loginAs func(userID string) string,
) {
	t.Helper()

	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("me-sessions-test"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "u-alice"})
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "u-bob"})

	sessions = defaultimpl.NewMemorySessionManager()

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "me-app", Secret: "shh", Name: "Me App",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, _ string) (*sso.AuthResult, error) {
			// accept any password for alice / bob
			switch u {
			case "alice":
				return &sso.AuthResult{UserID: "u-alice"}, nil
			case "bob":
				return &sso.AuthResult{UserID: "u-bob"}, nil
			default:
				return nil, errors.New("bad credentials")
			}
		},
	))

	server := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(sessions),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	hs := httptest.NewServer(server.Handler())
	t.Cleanup(hs.Close)

	loginAs = func(username string) string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"provider":   "password",
			"client_id":  "me-app",
			"credential": map[string]string{"username": username, "password": "pw"},
		})
		resp, err := http.Post(hs.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login(%s): %v", username, err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		tok, _ := out["access_token"].(string)
		if tok == "" {
			t.Fatalf("login(%s): no access_token in %s", username, raw)
		}
		return tok
	}
	return hs, sessions, loginAs
}

// newMeConsentsHarness wires a minimal server that has a ConsentStore.
func newMeConsentsHarness(t *testing.T) (
	srv *httptest.Server,
	consentStore *defaultimpl.MemoryConsentStore,
	loginAsAlice func() string,
) {
	t.Helper()

	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("me-consents-test"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "u-consent-alice"})

	sessions := defaultimpl.NewMemorySessionManager()
	cs := defaultimpl.NewMemoryConsentStore()

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "consent-app", Secret: "s", Name: "Consent App",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: "u-consent-alice"}, nil
		},
	))

	server := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(sessions),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithConsentStore(cs),
	)
	hs := httptest.NewServer(server.Handler())
	t.Cleanup(hs.Close)

	loginAsAlice = func() string {
		t.Helper()
		// The consent gate fires for all clients when a ConsentStore is wired.
		// Pre-seed a grant for the login client so the gate passes, then revoke
		// it so each test starts with a clean store — the /consents/me
		// assertions rely on a predictable initial state.
		_ = cs.RecordConsent(context.Background(), sso.ConsentGrant{
			UserID:    "u-consent-alice",
			ClientID:  "consent-app",
			GrantedAt: time.Now(),
		})
		body, _ := json.Marshal(map[string]any{
			"provider":   "password",
			"client_id":  "consent-app",
			"credential": map[string]string{"username": "alice", "password": "pw"},
		})
		resp, err := http.Post(hs.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		tok, _ := out["access_token"].(string)
		if tok == "" {
			t.Fatalf("login: no access_token in %s", raw)
		}
		// Revoke the login-client grant so the consent list starts empty.
		_ = cs.RevokeConsent(context.Background(), "u-consent-alice", "consent-app")
		return tok
	}
	return hs, cs, loginAsAlice
}

// ---------- helpers ----------

func doReq(t *testing.T, srv *httptest.Server, method, path, bearer string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// ---------- GET /sessions/me ----------

func TestGetMySessions_HappyPath(t *testing.T) {
	srv, _, loginAs := newMeSessionsHarness(t)
	tok := loginAs("alice")

	code, body := doReq(t, srv, http.MethodGet, "/sessions/me", tok)
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	list, _ := body["sessions"].([]any)
	// Alice's login created a session; it must appear in the list.
	if len(list) == 0 {
		t.Errorf("expected at least one session, got %v", body)
	}
}

// TestGetMySessions_CapturesDeviceContext verifies the login flow records the
// request IP on the new session (device/location context), surfaced in
// /sessions/me. The httptest client connects from loopback.
func TestGetMySessions_CapturesDeviceContext(t *testing.T) {
	srv, _, loginAs := newMeSessionsHarness(t)
	tok := loginAs("alice")

	_, body := doReq(t, srv, http.MethodGet, "/sessions/me", tok)
	list, _ := body["sessions"].([]any)
	if len(list) == 0 {
		t.Fatalf("expected a session, got %v", body)
	}
	first, _ := list[0].(map[string]any)
	ip, _ := first["ip"].(string)
	if !strings.Contains(ip, "127.0.0.1") && !strings.Contains(ip, "::1") {
		t.Errorf("session ip = %q, want loopback (device context not captured)", ip)
	}
}

func TestGetMySessions_NoBearer(t *testing.T) {
	srv, _, _ := newMeSessionsHarness(t)
	code, body := doReq(t, srv, http.MethodGet, "/sessions/me", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	if body["error"] != "missing_token" {
		t.Errorf("error = %v, want missing_token", body["error"])
	}
}

func TestGetMySessions_InvalidBearer(t *testing.T) {
	srv, _, _ := newMeSessionsHarness(t)
	code, body := doReq(t, srv, http.MethodGet, "/sessions/me", "not-a-real-token")
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	if body["error"] != "invalid_token" {
		t.Errorf("error = %v, want invalid_token", body["error"])
	}
}

func TestGetMySessions_NoStoreHeaders(t *testing.T) {
	// Token and consent endpoints MUST carry Cache-Control: no-store.
	srv, _, loginAs := newMeSessionsHarness(t)
	tok := loginAs("alice")

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/sessions/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	cc := resp.Header.Get("Cache-Control")
	if cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

func TestGetMySessions_WWWAuthenticate(t *testing.T) {
	// Missing-token 401 MUST carry a WWW-Authenticate: Bearer challenge.
	srv, _, _ := newMeSessionsHarness(t)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/sessions/me", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	ch := resp.Header.Get("WWW-Authenticate")
	if ch == "" {
		t.Error("no WWW-Authenticate header on 401")
	}
}

// ---------- DELETE /sessions/me/:id ----------

func TestDeleteMySession_HappyPath(t *testing.T) {
	srv, sessions, loginAs := newMeSessionsHarness(t)
	tok := loginAs("alice")

	// Find Alice's session.
	all, _ := sessions.ListByUser(context.Background(), "u-alice")
	if len(all) == 0 {
		t.Fatal("no sessions found for alice after login")
	}
	sessID := all[0].ID

	code, _ := doReq(t, srv, http.MethodDelete, "/sessions/me/"+sessID, tok)
	if code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", code)
	}

	// Session should be gone.
	remaining, _ := sessions.ListByUser(context.Background(), "u-alice")
	for _, s := range remaining {
		if s.ID == sessID {
			t.Error("deleted session still present")
		}
	}
}

func TestDeleteMySession_OtherUserSession(t *testing.T) {
	// Alice MUST NOT be able to delete Bob's sessions (oracle-safe 404).
	srv, sessions, loginAs := newMeSessionsHarness(t)
	tokAlice := loginAs("alice")
	_ = loginAs("bob") // creates Bob's session

	bobSessions, _ := sessions.ListByUser(context.Background(), "u-bob")
	if len(bobSessions) == 0 {
		t.Fatal("no sessions found for bob after login")
	}
	bobSessID := bobSessions[0].ID

	code, body := doReq(t, srv, http.MethodDelete, "/sessions/me/"+bobSessID, tokAlice)
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %v", code, body)
	}
	if body["error"] != "not_found" {
		t.Errorf("error = %v, want not_found", body["error"])
	}
	// Bob's session must still exist.
	remaining, _ := sessions.ListByUser(context.Background(), "u-bob")
	found := false
	for _, s := range remaining {
		if s.ID == bobSessID {
			found = true
		}
	}
	if !found {
		t.Error("bob's session was deleted by alice — ownership not enforced")
	}
}

func TestDeleteMySession_Unknown(t *testing.T) {
	// Deleting a session that doesn't exist → 404 (oracle-safe, same as
	// wrong-user so attackers can't enumerate session IDs).
	srv, _, loginAs := newMeSessionsHarness(t)
	tok := loginAs("alice")

	code, body := doReq(t, srv, http.MethodDelete, "/sessions/me/no-such-session", tok)
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %v", code, body)
	}
	if body["error"] != "not_found" {
		t.Errorf("error = %v, want not_found", body["error"])
	}
}

func TestDeleteMySession_NoBearer(t *testing.T) {
	srv, _, _ := newMeSessionsHarness(t)
	code, _ := doReq(t, srv, http.MethodDelete, "/sessions/me/any-id", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
}

// ---------- DELETE /sessions/me (sign out everywhere) ----------

// sidFromJWT pulls the "sid" claim out of a compact JWT access token so the
// tests can assert which concrete session the "keep current" path preserves.
func sidFromJWT(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWT: %q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode jwt payload: %v", err)
	}
	var claims struct {
		SID string `json:"sid"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal jwt payload: %v", err)
	}
	return claims.SID
}

func TestRevokeMySessions_KeepsCurrent(t *testing.T) {
	// Default DELETE /sessions/me is "sign out of all OTHER devices": it must
	// revoke every session except the one whose ID matches the caller token's
	// sid, so the user stays signed in to the portal making the request.
	srv, sessions, loginAs := newMeSessionsHarness(t)
	tok := loginAs("alice")
	sid := sidFromJWT(t, tok)
	if sid == "" {
		t.Fatal("login token carries no sid; cannot test current-session preservation")
	}
	// Two more sessions for alice (her other devices).
	_, _ = sessions.Create(context.Background(), "u-alice")
	_, _ = sessions.Create(context.Background(), "u-alice")
	if before, _ := sessions.ListByUser(context.Background(), "u-alice"); len(before) != 3 {
		t.Fatalf("setup: want 3 sessions, got %d", len(before))
	}

	code, body := doReq(t, srv, http.MethodDelete, "/sessions/me", tok)
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	if got, _ := body["revoked"].(float64); int(got) != 2 {
		t.Errorf("revoked = %v, want 2 (all but current)", body["revoked"])
	}
	remaining, _ := sessions.ListByUser(context.Background(), "u-alice")
	if len(remaining) != 1 || remaining[0].ID != sid {
		t.Errorf("remaining = %v, want only current session %s", remaining, sid)
	}
}

func TestRevokeMySessions_All(t *testing.T) {
	// ?all=true is a full sign-out: even the current session is revoked.
	srv, sessions, loginAs := newMeSessionsHarness(t)
	tok := loginAs("alice")
	_, _ = sessions.Create(context.Background(), "u-alice")

	code, body := doReq(t, srv, http.MethodDelete, "/sessions/me?all=true", tok)
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	if remaining, _ := sessions.ListByUser(context.Background(), "u-alice"); len(remaining) != 0 {
		t.Errorf("remaining = %d, want 0 with all=true", len(remaining))
	}
}

func TestRevokeMySessions_OtherUserUntouched(t *testing.T) {
	// Alice signing out everywhere MUST NOT touch Bob's sessions.
	srv, sessions, loginAs := newMeSessionsHarness(t)
	tokAlice := loginAs("alice")
	_ = loginAs("bob")
	_, _ = sessions.Create(context.Background(), "u-bob")

	code, _ := doReq(t, srv, http.MethodDelete, "/sessions/me?all=true", tokAlice)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if bob, _ := sessions.ListByUser(context.Background(), "u-bob"); len(bob) == 0 {
		t.Error("bob's sessions were revoked by alice's sign-out-everywhere")
	}
	if alice, _ := sessions.ListByUser(context.Background(), "u-alice"); len(alice) != 0 {
		t.Errorf("alice still has %d sessions after all=true", len(alice))
	}
}

func TestRevokeMySessions_NoBearer(t *testing.T) {
	srv, _, _ := newMeSessionsHarness(t)
	code, body := doReq(t, srv, http.MethodDelete, "/sessions/me", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
	if body["error"] != "missing_token" {
		t.Errorf("error = %v, want missing_token", body["error"])
	}
}

func TestRevokeMySessions_NoStoreHeaders(t *testing.T) {
	srv, _, loginAs := newMeSessionsHarness(t)
	tok := loginAs("alice")
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/sessions/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

// ---------- GET /consents/me ----------

func TestGetMyConsents_Empty(t *testing.T) {
	srv, _, loginAs := newMeConsentsHarness(t)
	tok := loginAs()

	code, body := doReq(t, srv, http.MethodGet, "/consents/me", tok)
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	list, _ := body["consents"].([]any)
	if len(list) != 0 {
		t.Errorf("expected empty consent list, got %v", body)
	}
}

func TestGetMyConsents_WithGrant(t *testing.T) {
	srv, cs, loginAs := newMeConsentsHarness(t)
	tok := loginAs()
	_ = cs.RecordConsent(context.Background(), sso.ConsentGrant{
		UserID:    "u-consent-alice",
		ClientID:  "app-x",
		Scopes:    []string{"openid", "profile"},
		GrantedAt: time.Now(),
	})

	code, body := doReq(t, srv, http.MethodGet, "/consents/me", tok)
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	list, _ := body["consents"].([]any)
	if len(list) != 1 {
		t.Errorf("expected 1 consent, got %d: %v", len(list), body)
	}
}

func TestGetMyConsents_NoBearer(t *testing.T) {
	srv, _, _ := newMeConsentsHarness(t)
	code, body := doReq(t, srv, http.MethodGet, "/consents/me", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	if body["error"] != "missing_token" {
		t.Errorf("error = %v, want missing_token", body["error"])
	}
}

func TestGetMyConsents_NoStoreHeaders(t *testing.T) {
	srv, _, loginAs := newMeConsentsHarness(t)
	tok := loginAs()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/consents/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

// ---------- DELETE /consents/me/:client_id ----------

func TestDeleteMyConsent_HappyPath(t *testing.T) {
	srv, cs, loginAs := newMeConsentsHarness(t)
	tok := loginAs()
	_ = cs.RecordConsent(context.Background(), sso.ConsentGrant{
		UserID:    "u-consent-alice",
		ClientID:  "app-y",
		Scopes:    []string{"read"},
		GrantedAt: time.Now(),
	})

	code, _ := doReq(t, srv, http.MethodDelete, "/consents/me/app-y", tok)
	if code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", code)
	}

	// The grant must be gone.
	_, err := cs.GetConsent(context.Background(), "u-consent-alice", "app-y")
	if !errors.Is(err, sso.ErrNoConsentGrant) {
		t.Errorf("grant still present after revoke: err = %v", err)
	}
}

func TestDeleteMyConsent_NotFound(t *testing.T) {
	srv, _, loginAs := newMeConsentsHarness(t)
	tok := loginAs()

	code, body := doReq(t, srv, http.MethodDelete, "/consents/me/no-such-client", tok)
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %v", code, body)
	}
	if body["error"] != "not_found" {
		t.Errorf("error = %v, want not_found", body["error"])
	}
}

func TestDeleteMyConsent_NoBearer(t *testing.T) {
	srv, _, _ := newMeConsentsHarness(t)
	code, _ := doReq(t, srv, http.MethodDelete, "/consents/me/any-client", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
}

// ---------- routes not mounted when store is nil ----------

func TestSessionRoutes_NotMountedWithoutSessionMgr(t *testing.T) {
	// A server wired WITHOUT a SessionManager must return 404 for /sessions/me
	// (the route is simply not registered — byte-identical to a build without it).
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "no-sess", Secret: "s", Active: true, TokenStrategy: "jwt"})
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	resp, err := http.Get(hs.URL + "/sessions/me")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (route unmounted)", resp.StatusCode)
	}
}

func TestConsentRoutes_NotMountedWithoutConsentStore(t *testing.T) {
	// Same: /consents/me returns 404 when no ConsentStore is wired.
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "no-consent", Secret: "s", Active: true, TokenStrategy: "jwt"})
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	resp, err := http.Get(hs.URL + "/consents/me")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (route unmounted)", resp.StatusCode)
	}
}

// ---------- GET /me/sessions ----------
//
// These tests mirror the /sessions/me tests but hit the /me/sessions
// alias registered in mountSelfServiceProfile.

func TestGetMeSessions_HappyPath(t *testing.T) {
	srv, _, loginAs := newMeSessionsHarness(t)
	tok := loginAs("alice")

	code, body := doReq(t, srv, http.MethodGet, "/me/sessions", tok)
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	list, _ := body["sessions"].([]any)
	if len(list) == 0 {
		t.Errorf("expected at least one session, got %v", body)
	}
}

func TestGetMeSessions_NoBearer(t *testing.T) {
	srv, _, _ := newMeSessionsHarness(t)
	code, body := doReq(t, srv, http.MethodGet, "/me/sessions", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	if body["error"] != "missing_token" {
		t.Errorf("error = %v, want missing_token", body["error"])
	}
}

func TestGetMeSessions_InvalidBearer(t *testing.T) {
	srv, _, _ := newMeSessionsHarness(t)
	code, body := doReq(t, srv, http.MethodGet, "/me/sessions", "not-a-real-token")
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	if body["error"] != "invalid_token" {
		t.Errorf("error = %v, want invalid_token", body["error"])
	}
}

func TestGetMeSessions_NoStoreHeaders(t *testing.T) {
	srv, _, loginAs := newMeSessionsHarness(t)
	tok := loginAs("alice")

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/me/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

// ---------- DELETE /me/sessions/:id ----------

func TestDeleteMeSession_HappyPath(t *testing.T) {
	srv, sessions, loginAs := newMeSessionsHarness(t)
	tok := loginAs("alice")

	all, _ := sessions.ListByUser(context.Background(), "u-alice")
	if len(all) == 0 {
		t.Fatal("no sessions found for alice after login")
	}
	sessID := all[0].ID

	code, _ := doReq(t, srv, http.MethodDelete, "/me/sessions/"+sessID, tok)
	if code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", code)
	}

	remaining, _ := sessions.ListByUser(context.Background(), "u-alice")
	for _, s := range remaining {
		if s.ID == sessID {
			t.Error("deleted session still present")
		}
	}
}

func TestDeleteMeSession_OtherUserSession(t *testing.T) {
	srv, sessions, loginAs := newMeSessionsHarness(t)
	tokAlice := loginAs("alice")
	_ = loginAs("bob")

	bobSessions, _ := sessions.ListByUser(context.Background(), "u-bob")
	if len(bobSessions) == 0 {
		t.Fatal("no sessions found for bob after login")
	}
	bobSessID := bobSessions[0].ID

	code, body := doReq(t, srv, http.MethodDelete, "/me/sessions/"+bobSessID, tokAlice)
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %v", code, body)
	}
	if body["error"] != "not_found" {
		t.Errorf("error = %v, want not_found", body["error"])
	}
	remaining, _ := sessions.ListByUser(context.Background(), "u-bob")
	found := false
	for _, s := range remaining {
		if s.ID == bobSessID {
			found = true
		}
	}
	if !found {
		t.Error("bob's session was deleted by alice — ownership not enforced")
	}
}

func TestDeleteMeSession_Unknown(t *testing.T) {
	srv, _, loginAs := newMeSessionsHarness(t)
	tok := loginAs("alice")

	code, body := doReq(t, srv, http.MethodDelete, "/me/sessions/no-such-session", tok)
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %v", code, body)
	}
	if body["error"] != "not_found" {
		t.Errorf("error = %v, want not_found", body["error"])
	}
}

func TestDeleteMeSession_NoBearer(t *testing.T) {
	srv, _, _ := newMeSessionsHarness(t)
	code, _ := doReq(t, srv, http.MethodDelete, "/me/sessions/any-id", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
}

// ---------- POST /me/sessions/revoke-all ----------

func postMeSessionsRevokeAll(t *testing.T, srv *httptest.Server, bearer string) (int, map[string]any) {
	t.Helper()
	r, _ := http.NewRequest(http.MethodPost, srv.URL+"/me/sessions/revoke-all", nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("revoke-all: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func TestMeSessionsRevokeAll_RevokesAllIncludingCurrent(t *testing.T) {
	// POST /me/sessions/revoke-all is a hard sign-out-everywhere: it revokes
	// ALL sessions including the caller's current session (no keepCurrent logic).
	srv, sessions, loginAs := newMeSessionsHarness(t)

	tok1 := loginAs("alice")
	_ = loginAs("alice") // second session

	before, _ := sessions.ListByUser(context.Background(), "u-alice")
	if len(before) < 2 {
		t.Fatalf("expected >= 2 sessions before revoke-all, got %d", len(before))
	}

	status, body := postMeSessionsRevokeAll(t, srv, tok1)
	if status != http.StatusOK {
		t.Fatalf("status = %d body=%v", status, body)
	}
	if revoked, _ := body["revoked"].(float64); int(revoked) != len(before) {
		t.Errorf("revoked = %v want %d (all sessions including current)", revoked, len(before))
	}
	// No sessions must remain — including the caller's current one.
	after, _ := sessions.ListByUser(context.Background(), "u-alice")
	if len(after) != 0 {
		t.Errorf("sessions remaining = %d, want 0 after revoke-all", len(after))
	}
}

func TestMeSessionsRevokeAll_RequiresBearer(t *testing.T) {
	srv, _, _ := newMeSessionsHarness(t)
	status, body := postMeSessionsRevokeAll(t, srv, "")
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d want 401", status)
	}
	if body["error"] != "missing_token" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestMeSessionsRevokeAll_InvalidBearer(t *testing.T) {
	srv, _, _ := newMeSessionsHarness(t)
	status, body := postMeSessionsRevokeAll(t, srv, "garbage-bearer")
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d want 401", status)
	}
	if body["error"] != "invalid_token" {
		t.Errorf("error = %v", body["error"])
	}
}

// ---------- routes not mounted without store ----------

func TestMeSessionRoutes_NotMountedWithoutSessionMgr(t *testing.T) {
	// Without a SessionManager, /me/sessions* routes must not be mounted.
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "no-sess", Secret: "s", Active: true, TokenStrategy: "jwt"})
	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	type check struct {
		method, path string
	}
	for _, c := range []check{
		{http.MethodGet, "/me/sessions"},
		{http.MethodDelete, "/me/sessions/any-id"},
		{http.MethodPost, "/me/sessions/revoke-all"},
	} {
		req, _ := http.NewRequest(c.method, hs.URL+c.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", c.method, c.path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s: status = %d, want 404 (route unmounted)", c.method, c.path, resp.StatusCode)
		}
	}
}
