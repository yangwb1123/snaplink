package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

// auditHarness wires the SSO server with a memory audit sink + every
// dependency the OAuth/OIDC code paths need to emit the new events.
type oauthAuditHarness struct {
	srv   *httptest.Server
	sink  *audit.MemorySink
	store *defaultimpl.MemoryRefreshTokenStore
	users *defaultimpl.MemoryUserProvider
}

const (
	oaClientID = "oa-client"
	oaSecret   = "oa-secret"
	oaUserID   = "u-oa"
)

func newOAuthAuditHarness(t *testing.T) *oauthAuditHarness {
	t.Helper()
	sink := audit.NewMemorySink(100)
	rec := audit.New(sink)

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: oaUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: oaClientID, Secret: oaSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		AllowedScopes:         []string{"openid", "profile"},
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: oaUserID, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	store := defaultimpl.NewMemoryRefreshTokenStore()

	srv := sso.NewServer(
		sso.WithAuditRecorder(rec),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(store, time.Hour),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDeviceCodeStore(defaultimpl.NewMemoryDeviceCodeStore(), 5*time.Minute, time.Second, ""),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return &oauthAuditHarness{srv: httpSrv, sink: sink, store: store, users: users}
}

func (h *oauthAuditHarness) hasEvent(t *testing.T, kind audit.EventType) *audit.Event {
	t.Helper()
	events, err := h.sink.Query(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("sink.Query: %v", err)
	}
	for _, e := range events {
		if e.Type == kind {
			return e
		}
	}
	return nil
}

func (h *oauthAuditHarness) countEvents(t *testing.T, kind audit.EventType) int {
	t.Helper()
	events, _ := h.sink.Query(context.Background(), audit.Query{})
	n := 0
	for _, e := range events {
		if e.Type == kind {
			n++
		}
	}
	return n
}

// ---------- refresh_token_issued ----------

func TestAuditEvent_RefreshTokenIssuedOnLogin(t *testing.T) {
	h := newOAuthAuditHarness(t)
	loginAndGetTokens(t, h)
	e := h.hasEvent(t, audit.EventRefreshTokenIssued)
	if e == nil {
		t.Fatal("expected refresh_token_issued after login, none recorded")
	}
	if e.Metadata["rotation"] != "" {
		t.Errorf("login should not be marked as rotation; got rotation=%q", e.Metadata["rotation"])
	}
}

func TestAuditEvent_RefreshTokenIssuedOnRotation(t *testing.T) {
	h := newOAuthAuditHarness(t)
	_, refresh := loginAndGetTokens(t, h)

	// Burn the existing refresh_token_issued so we can detect the new one.
	startCount := h.countEvents(t, audit.EventRefreshTokenIssued)

	body := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {oaClientID},
		"client_secret": {oaSecret},
		"refresh_token": {refresh},
	}
	resp, err := http.Post(h.srv.URL+"/token", "application/x-www-form-urlencoded",
		strings.NewReader(body.Encode()))
	if err != nil {
		t.Fatalf("rotation post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotation status = %d", resp.StatusCode)
	}

	if got := h.countEvents(t, audit.EventRefreshTokenIssued); got != startCount+1 {
		t.Fatalf("expected one new event, count went %d -> %d", startCount, got)
	}
	// Last event should be a rotation.
	// MemorySink.Query returns events newest-first, so the FIRST
	// refresh_token_issued in the slice is the rotation we just did.
	events, _ := h.sink.Query(context.Background(), audit.Query{})
	var newestRefresh *audit.Event
	for _, e := range events {
		if e.Type == audit.EventRefreshTokenIssued {
			newestRefresh = e
			break
		}
	}
	if newestRefresh == nil {
		t.Fatal("no refresh event")
	}
	if newestRefresh.Metadata["rotation"] != "true" {
		t.Errorf("expected rotation=true, got %q", newestRefresh.Metadata["rotation"])
	}
}

// ---------- id_token_issued ----------

func TestAuditEvent_IDTokenIssuedOnOpenIDLogin(t *testing.T) {
	h := newOAuthAuditHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  oaClientID,
		"credential": map[string]string{"username": "x", "password": "y"},
		"scope":      []string{"openid", "profile"},
	})
	resp, err := http.Post(h.srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out["id_token"] == nil {
		t.Fatalf("expected id_token in login: %s", raw)
	}
	if e := h.hasEvent(t, audit.EventIDTokenIssued); e == nil {
		t.Fatal("expected id_token_issued event after openid login")
	}
}

func TestAuditEvent_IDTokenNotIssuedWithoutOpenIDScope(t *testing.T) {
	h := newOAuthAuditHarness(t)
	// No "openid" scope → no id_token, no audit event.
	loginAndGetTokens(t, h)
	if e := h.hasEvent(t, audit.EventIDTokenIssued); e != nil {
		t.Fatal("id_token_issued event recorded without openid scope")
	}
}

// ---------- device_code_issued / approved / denied ----------

func TestAuditEvent_DeviceCodeIssued(t *testing.T) {
	h := newOAuthAuditHarness(t)
	body := url.Values{"client_id": {oaClientID}}
	resp, err := http.Post(h.srv.URL+"/device/code",
		"application/x-www-form-urlencoded", strings.NewReader(body.Encode()))
	if err != nil {
		t.Fatalf("device/code: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if e := h.hasEvent(t, audit.EventDeviceCodeIssued); e == nil {
		t.Fatal("expected device_code_issued event")
	}
}

func TestAuditEvent_DeviceCodeApproved(t *testing.T) {
	h := newOAuthAuditHarness(t)
	access, _ := loginAndGetTokens(t, h)
	userCode := startDeviceFlow(t, h)

	approveBody := url.Values{
		"user_code": {userCode},
		"approve":   {"true"},
	}
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/device/verify",
		strings.NewReader(approveBody.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	e := h.hasEvent(t, audit.EventDeviceCodeApproved)
	if e == nil {
		t.Fatal("expected device_code_approved event")
	}
	if e.ActorID != oaUserID {
		t.Errorf("actor_id = %q, want %q", e.ActorID, oaUserID)
	}
	if e.Metadata["device_client_id"] != oaClientID {
		t.Errorf("device_client_id meta = %q", e.Metadata["device_client_id"])
	}
}

func TestAuditEvent_DeviceCodeDenied(t *testing.T) {
	h := newOAuthAuditHarness(t)
	access, _ := loginAndGetTokens(t, h)
	userCode := startDeviceFlow(t, h)

	denyBody := url.Values{
		"user_code": {userCode},
		"approve":   {"false"},
	}
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/device/verify",
		strings.NewReader(denyBody.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	e := h.hasEvent(t, audit.EventDeviceCodeDenied)
	if e == nil {
		t.Fatal("expected device_code_denied event")
	}
	if e.Outcome != audit.OutcomeFailure {
		t.Errorf("outcome = %q, want failure", e.Outcome)
	}
}

// ---------- helpers ----------

func loginAndGetTokens(t *testing.T, h *oauthAuditHarness) (string, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  oaClientID,
		"credential": map[string]string{"username": "x", "password": "y"},
	})
	resp, err := http.Post(h.srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	a, _ := out["access_token"].(string)
	r, _ := out["refresh_token"].(string)
	if a == "" || r == "" {
		t.Fatalf("missing tokens: %s", raw)
	}
	return a, r
}

// startDeviceFlow starts a device authorization, returns the
// (dashless-normalized) user_code so the test can approve/deny.
func startDeviceFlow(t *testing.T, h *oauthAuditHarness) string {
	t.Helper()
	body := url.Values{"client_id": {oaClientID}}
	resp, err := http.Post(h.srv.URL+"/device/code",
		"application/x-www-form-urlencoded", strings.NewReader(body.Encode()))
	if err != nil {
		t.Fatalf("device/code: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	uc, _ := out["user_code"].(string)
	if uc == "" {
		t.Fatalf("no user_code: %s", raw)
	}
	return uc
}
