package ssotest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/security"
)

// OIDC Back-Channel Logout 1.0:
// - /logout fans out to client.BackchannelLogoutURI
// - logout_token is a signed JWT with typ=logout+jwt + events claim
// - audit event emitted on success and failure
// - signature verifies against the same JWKS key as access tokens
// - discovery advertises backchannel_logout_supported when wired

const (
	bclUser     = "u-bcl"
	bclClient   = "bcl-client"
	bclSecret   = "bcl-secret"
	bclPassword = "pw"
)

// captureNotifier records every Notify call into an in-memory
// channel so tests can assert what was POSTed. Implements the
// LogoutNotifier interface.
type captureNotifier struct {
	mu      sync.Mutex
	calls   []captureCall
	failNth int32 // 0 = always succeed; >0 = fail the Nth call
	count   int32
}
type captureCall struct {
	URI         string
	LogoutToken string
}

func (c *captureNotifier) Notify(_ context.Context, uri string, logoutToken string) error {
	n := atomic.AddInt32(&c.count, 1)
	c.mu.Lock()
	c.calls = append(c.calls, captureCall{URI: uri, LogoutToken: logoutToken})
	c.mu.Unlock()
	if c.failNth > 0 && n == c.failNth {
		return errors.New("synthetic failure")
	}
	return nil
}

func (c *captureNotifier) snapshot() []captureCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]captureCall, len(c.calls))
	copy(out, c.calls)
	return out
}

func newBCLServer(t *testing.T, bcURI string, notifier sso.LogoutNotifier) (*httptest.Server, *audit.MemorySink, *defaultimpl.Ed25519JWTIssuer) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: bclUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    bclClient,
		Secret:                bclSecret,
		Name:                  "BCL Test",
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		Active:                true,
		BackchannelLogoutURI:  bcURI,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == bclUser && p == bclPassword {
				return &sso.AuthResult{UserID: bclUser}, nil
			}
			return nil, errors.New("bad")
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://sso.test"))
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithBackchannelLogout(issuer, notifier),
		sso.WithAuditRecorder(rec),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, sink, issuer
}

// loginBCL drives the direct-mint flow and returns the access_token.
func loginBCL(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  bclClient,
		"credential": map[string]string{"username": bclUser, "password": bclPassword},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("login status=%d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	tok, _ := out["access_token"].(string)
	if tok == "" {
		t.Fatalf("no access_token in login response: %v", out)
	}
	return tok
}

// logoutBCL POSTs /logout with the given bearer.
func logoutBCL(t *testing.T, srv *httptest.Server, bearer string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/logout", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("logout status=%d body=%s", resp.StatusCode, raw)
	}
}

func TestBCL_NotifierCalledOnLogout(t *testing.T) {
	n := &captureNotifier{}
	srv, _, _ := newBCLServer(t, "https://app.example.com/bc-logout", n)
	tok := loginBCL(t, srv)
	logoutBCL(t, srv, tok)

	calls := n.snapshot()
	if len(calls) != 1 {
		t.Fatalf("expected 1 notifier call, got %d", len(calls))
	}
	if calls[0].URI != "https://app.example.com/bc-logout" {
		t.Errorf("URI = %q want client's BackchannelLogoutURI", calls[0].URI)
	}
	if calls[0].LogoutToken == "" {
		t.Errorf("LogoutToken empty")
	}
}

func TestBCL_LogoutTokenShapeIsValid(t *testing.T) {
	n := &captureNotifier{}
	srv, _, issuer := newBCLServer(t, "https://app.example.com/bc-logout", n)
	tok := loginBCL(t, srv)
	logoutBCL(t, srv, tok)

	calls := n.snapshot()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call")
	}
	parts := strings.Split(calls[0].LogoutToken, ".")
	if len(parts) != 3 {
		t.Fatalf("logout_token not a JWT: %q", calls[0].LogoutToken)
	}

	// Decode header.
	hraw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var hdr map[string]any
	_ = json.Unmarshal(hraw, &hdr)
	if hdr["typ"] != "logout+jwt" {
		t.Errorf("typ = %v want logout+jwt (OIDC BCL §2.4)", hdr["typ"])
	}
	if hdr["alg"] != "EdDSA" {
		t.Errorf("alg = %v want EdDSA", hdr["alg"])
	}

	// Decode payload.
	praw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var p map[string]any
	_ = json.Unmarshal(praw, &p)
	if p["sub"] != bclUser {
		t.Errorf("sub = %v want %q", p["sub"], bclUser)
	}
	if p["aud"] != bclClient {
		t.Errorf("aud = %v want %q", p["aud"], bclClient)
	}
	if p["iss"] != "https://sso.test" {
		t.Errorf("iss = %v want https://sso.test", p["iss"])
	}
	if _, ok := p["iat"]; !ok {
		t.Errorf("iat missing")
	}
	if _, ok := p["exp"]; !ok {
		t.Errorf("exp missing")
	}
	if _, ok := p["jti"].(string); !ok || p["jti"] == "" {
		t.Errorf("jti missing or empty (OIDC BCL §2.4 REQUIRED)")
	}
	if _, ok := p["nonce"]; ok {
		t.Errorf("nonce forbidden per §2.4: %v", p["nonce"])
	}
	events, ok := p["events"].(map[string]any)
	if !ok {
		t.Fatalf("events claim missing or wrong shape: %v", p["events"])
	}
	if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Errorf("events missing the BCL event URI key: %v", events)
	}

	// Verify the signature against the issuer's public key —
	// proves the same JWKS key chain works for logout tokens.
	signingInput := parts[0] + "." + parts[1]
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if !ed25519.Verify(issuer.PublicKey(), []byte(signingInput), sig) {
		t.Errorf("signature verification failed against issuer.PublicKey()")
	}
}

func TestBCL_DeliveredOverHTTP(t *testing.T) {
	// End-to-end: stand up an httptest server playing the RP and
	// assert it receives the form-encoded logout_token per §2.5.
	var (
		mu       sync.Mutex
		received string
		ct       string
	)
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = r.ParseForm()
		received = r.FormValue("logout_token")
		ct = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(rp.Close)

	notifier := sso.NewHTTPLogoutNotifier()
	srv, _, _ := newBCLServer(t, rp.URL, notifier)
	tok := loginBCL(t, srv)
	logoutBCL(t, srv, tok)

	// Give the round-trip a microscopic window if it's not yet drained.
	time.Sleep(20 * time.Millisecond)

	mu.Lock()
	gotToken := received
	gotCT := ct
	mu.Unlock()
	if gotToken == "" {
		t.Fatal("RP did not receive logout_token")
	}
	if !strings.HasPrefix(gotCT, "application/x-www-form-urlencoded") {
		t.Errorf("Content-Type = %q want form-encoded (OIDC BCL §2.5)", gotCT)
	}
	// And the body MUST be a valid 3-segment JWT.
	if strings.Count(gotToken, ".") != 2 {
		t.Errorf("logout_token not a JWT: %q", gotToken)
	}
}

func TestBCL_AuditOnSuccess(t *testing.T) {
	n := &captureNotifier{}
	srv, sink, _ := newBCLServer(t, "https://app.example.com/bc-logout", n)
	tok := loginBCL(t, srv)
	logoutBCL(t, srv, tok)

	events, _ := sink.Query(context.Background(), audit.Query{Type: audit.EventLogoutNotified})
	if len(events) != 1 {
		t.Fatalf("expected 1 logout_notified event, got %d", len(events))
	}
	if events[0].Outcome != audit.OutcomeSuccess {
		t.Errorf("Outcome = %v want success", events[0].Outcome)
	}
	if events[0].ClientID != bclClient {
		t.Errorf("ClientID = %q want %q", events[0].ClientID, bclClient)
	}
	if events[0].ActorID != bclUser {
		t.Errorf("ActorID = %q want %q", events[0].ActorID, bclUser)
	}
}

func TestBCL_AuditOnFailure(t *testing.T) {
	// RP returns 500 → audit failure path.
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(rp.Close)

	notifier := sso.NewHTTPLogoutNotifier()
	srv, sink, _ := newBCLServer(t, rp.URL, notifier)
	tok := loginBCL(t, srv)
	logoutBCL(t, srv, tok)

	events, _ := sink.Query(context.Background(), audit.Query{Type: audit.EventLogoutNotified})
	if len(events) != 1 {
		t.Fatalf("expected 1 logout_notified event, got %d", len(events))
	}
	if events[0].Outcome != audit.OutcomeFailure {
		t.Errorf("Outcome = %v want failure", events[0].Outcome)
	}
	if events[0].Reason == "" {
		t.Errorf("Reason should carry the failure detail")
	}
}

func TestBCL_NoURI_NoNotification(t *testing.T) {
	// Client has BackchannelLogoutURI = "" → notifier MUST NOT be called.
	n := &captureNotifier{}
	srv, _, _ := newBCLServer(t, "" /* no URI */, n)
	tok := loginBCL(t, srv)
	logoutBCL(t, srv, tok)
	if calls := n.snapshot(); len(calls) != 0 {
		t.Errorf("expected 0 notifier calls when URI empty, got %d", len(calls))
	}
}

func TestBCL_DiscoveryAdvertisesSupport(t *testing.T) {
	n := &captureNotifier{}
	srv, _, _ := newBCLServer(t, "https://app.example.com/bc-logout", n)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	if doc["backchannel_logout_supported"] != true {
		t.Errorf("backchannel_logout_supported = %v want true", doc["backchannel_logout_supported"])
	}
	// SessionManager is wired in newBCLServer → sid is stamped
	// in access + id tokens → session support advertised.
	if doc["backchannel_logout_session_supported"] != true {
		t.Errorf("backchannel_logout_session_supported = %v want true (session manager wired → sid emitted)", doc["backchannel_logout_session_supported"])
	}
}

func TestBCL_EndSessionAlsoFiresNotification(t *testing.T) {
	// /end_session is the redirect-style mirror of POST /logout.
	// When a user logs out via that path, the back-channel
	// notification MUST fire for the client identified by the
	// id_token_hint. Without this, federated session
	// termination only works half the time (POST-style only).
	n := &captureNotifier{}
	srv, _, _ := newBCLServer(t, "https://app.example.com/bc-logout", n)
	tok := loginBCL(t, srv)

	// validateAnyToken accepts any AS-signed token; we use the
	// access token in place of an id_token_hint — the carrier
	// shape is the same and handleEndSession identifies user +
	// client from the validated claims.
	endSessionURL := srv.URL + "/end_session?id_token_hint=" + tok
	resp, err := http.Get(endSessionURL)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s want 204 (no post_logout_redirect_uri)", resp.StatusCode, body)
	}

	calls := n.snapshot()
	if len(calls) != 1 {
		t.Fatalf("expected 1 notifier call from /end_session, got %d", len(calls))
	}
	if calls[0].URI != "https://app.example.com/bc-logout" {
		t.Errorf("URI = %q want client's BackchannelLogoutURI", calls[0].URI)
	}
	if calls[0].LogoutToken == "" {
		t.Errorf("LogoutToken empty")
	}
}

func TestBCL_NotWired_NoNotification(t *testing.T) {
	// Server with NO WithBackchannelLogout option — even when the
	// client has BackchannelLogoutURI set, no notification fires.
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: bclUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: bclClient, Secret: bclSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		BackchannelLogoutURI:  "http://will-not-be-called.invalid",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == bclUser && p == bclPassword {
				return &sso.AuthResult{UserID: bclUser}, nil
			}
			return nil, errors.New("bad")
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		// no WithBackchannelLogout — discovery + /logout should
		// behave as before, no notification.
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// Login + logout, neither should fail. Without a notifier
	// wired we just don't observe one.
	tok := loginBCL(t, httpSrv)
	logoutBCL(t, httpSrv, tok)

	resp, err := http.Get(httpSrv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	// When false, omitempty omits it entirely.
	if doc["backchannel_logout_supported"] == true {
		t.Errorf("backchannel_logout_supported should be omitted/false when not wired; got %v", doc["backchannel_logout_supported"])
	}
}

// TestBCL_PairwiseClientLogoutTokenUsesPairwiseSub guards that the back-channel
// logout_token carries the TARGET client's per-sector pairwise sub — the same
// pseudonym the client received in its id_token — NOT the local user id. The
// local id would defeat pairwise unlinkability (colluding RPs correlate by the
// shared id) and break a sub-matching RP. Covers BOTH the local-resolution of
// the bearer's pairwise sub in /logout and the per-client re-derivation in
// sendBackchannelLogout.
func TestBCL_PairwiseClientLogoutTokenUsesPairwiseSub(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: bclUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: bclClient, Secret: bclSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		BackchannelLogoutURI:  "https://app.example/bc-logout",
		SubjectType:           security.SubjectTypePairwise,
		SectorIdentifierURI:   "https://app.example/sector",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == bclUser && p == bclPassword {
				return &sso.AuthResult{UserID: bclUser}, nil
			}
			return nil, errors.New("bad")
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://sso.test"))
	notifier := &captureNotifier{}
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithBackchannelLogout(issuer, notifier),
		sso.WithPairwiseSubjectStore(security.NewMemoryPairwiseSubjectStore()),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	access := loginBCL(t, httpSrv)
	pairwiseSub, _ := jwtAllClaims(t, access)["sub"].(string)
	if pairwiseSub == "" || pairwiseSub == bclUser {
		t.Fatalf("precondition: expected a pairwise sub distinct from local %q, got %q", bclUser, pairwiseSub)
	}

	logoutBCL(t, httpSrv, access)
	calls := notifier.snapshot()
	if len(calls) != 1 {
		t.Fatalf("expected 1 backchannel notify, got %d", len(calls))
	}
	gotSub, _ := jwtAllClaims(t, calls[0].LogoutToken)["sub"].(string)
	if gotSub != pairwiseSub {
		t.Errorf("logout_token sub = %q, want the pairwise pseudonym %q (NOT the local id %q)", gotSub, pairwiseSub, bclUser)
	}
}
