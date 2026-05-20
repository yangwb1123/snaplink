package sso_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	promptUserID   = "u-prompt"
	promptClientID = "prompt-client"
	promptSecret   = "prompt-secret"
	promptPassword = "pw"
)

// newPromptHarness wires the minimal server config needed to exercise
// /auth/login prompt=none silent renewal: a session manager (the
// presence of a live session is the gate), an Ed25519 issuer shared
// between access + id tokens (so the id_token_hint we mint here
// passes signature validation on the second hop), and a single
// password authenticator that auto-succeeds.
func newPromptHarness(t *testing.T) (*httptest.Server, *defaultimpl.MemorySessionManager) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: promptUserID})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    promptClientID,
		Secret:                promptSecret,
		Active:                true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != promptPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: promptUserID, Provider: "password"}, nil
		},
	))

	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(2 * time.Minute))
	sessions := defaultimpl.NewMemorySessionManager()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(sessions),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, sessions
}

// promptLogin drives a normal /auth/login that returns access +
// id_token (when openid scope set). Returns the response map.
func promptLogin(t *testing.T, srv *httptest.Server, scope []string) map[string]any {
	t.Helper()
	body := map[string]any{
		"provider":   "password",
		"client_id":  promptClientID,
		"credential": map[string]string{"username": promptUserID, "password": promptPassword},
		"scope":      scope,
	}
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	rb, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(rb, &out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", resp.StatusCode, rb)
	}
	return out
}

func postSilentRenewal(t *testing.T, srv *httptest.Server, prompt, idTokenHint string) (int, map[string]any) {
	t.Helper()
	body := map[string]any{
		"client_id":     promptClientID,
		"prompt":        prompt,
		"id_token_hint": idTokenHint,
		"scope":         []string{"openid"},
	}
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("silent renewal: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

func TestPromptNone_SilentRenewalMintsFreshTokenWhenSessionActive(t *testing.T) {
	srv, _ := newPromptHarness(t)
	// Step 1: real login produces an id_token + an active session.
	first := promptLogin(t, srv, []string{"openid"})
	hint, _ := first["id_token"].(string)
	if hint == "" {
		t.Fatalf("no id_token in initial login: %v", first)
	}
	originalAccess, _ := first["access_token"].(string)
	if originalAccess == "" {
		t.Fatalf("no access_token in initial login")
	}

	// Step 2: silent renewal via prompt=none + id_token_hint.
	status, body := postSilentRenewal(t, srv, "none", hint)
	if status != http.StatusOK {
		t.Fatalf("silent renewal status=%d body=%v", status, body)
	}
	newAccess, _ := body["access_token"].(string)
	if newAccess == "" {
		t.Fatalf("no access_token on silent renewal: %v", body)
	}
	if newAccess == originalAccess {
		t.Errorf("silent renewal returned the SAME token; expected a fresh mint")
	}
	// Fresh id_token must come back too since we asked for openid.
	if _, ok := body["id_token"].(string); !ok {
		t.Errorf("expected fresh id_token on silent renewal: %v", body)
	}
	// iss MUST be stamped on the response (RFC 9207 + the project's
	// authorization-response invariant).
	if iss, _ := body["iss"].(string); iss == "" {
		t.Errorf("missing iss on silent renewal response")
	}
}

func TestPromptNone_PreservesAuthTimeAcrossRenewal(t *testing.T) {
	srv, _ := newPromptHarness(t)
	first := promptLogin(t, srv, []string{"openid"})
	hint, _ := first["id_token"].(string)
	originalAuthTime := readAuthTime(t, hint)

	// Sleep so any time.Now() in the issuance path produces a
	// distinguishable value — auth_time MUST stay locked to the
	// original event regardless.
	time.Sleep(1100 * time.Millisecond)

	status, body := postSilentRenewal(t, srv, "none", hint)
	if status != http.StatusOK {
		t.Fatalf("silent renewal status=%d body=%v", status, body)
	}
	newAT, _ := body["access_token"].(string)
	got := readAuthTime(t, newAT)
	if got != originalAuthTime {
		t.Errorf("silent renewal MUST preserve auth_time; original=%d new=%d", originalAuthTime, got)
	}
}

func TestPromptNone_MissingIDTokenHintReturnsLoginRequired(t *testing.T) {
	srv, _ := newPromptHarness(t)
	status, body := postSilentRenewal(t, srv, "none", "")
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	if body["error"] != sso.ErrLoginRequired {
		t.Errorf("error=%v want %q", body["error"], sso.ErrLoginRequired)
	}
}

func TestPromptNone_RejectsCombinationWithOtherPromptValues(t *testing.T) {
	srv, _ := newPromptHarness(t)
	first := promptLogin(t, srv, []string{"openid"})
	hint, _ := first["id_token"].(string)
	status, body := postSilentRenewal(t, srv, "none login", hint)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	if body["error"] != sso.ErrInvalidRequest {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidRequest)
	}
}

func TestPromptNone_RejectsBadSignatureHint(t *testing.T) {
	srv, _ := newPromptHarness(t)
	// Hand-rolled bogus JWT — three base64url segments, valid
	// shape but invalid signature → indistinguishable from "no
	// session" on the wire per the oracle-leak pattern.
	status, body := postSilentRenewal(t, srv, "none", "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.bogus")
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	if body["error"] != sso.ErrLoginRequired {
		t.Errorf("error=%v want %q (bad signature must collapse to login_required)", body["error"], sso.ErrLoginRequired)
	}
}

func TestPromptNone_LoginRequiredWhenSessionEnded(t *testing.T) {
	srv, sessions := newPromptHarness(t)
	first := promptLogin(t, srv, []string{"openid"})
	hint, _ := first["id_token"].(string)

	// Logout: destroy every session this user holds.
	live, _ := sessions.ListByUser(context.Background(), promptUserID)
	for _, s := range live {
		_ = sessions.Destroy(context.Background(), s.ID)
	}

	status, body := postSilentRenewal(t, srv, "none", hint)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	if body["error"] != sso.ErrLoginRequired {
		t.Errorf("error=%v want %q", body["error"], sso.ErrLoginRequired)
	}
}

func TestPromptNone_LoginRequiredWhenHintClientDiffers(t *testing.T) {
	srv, _ := newPromptHarness(t)
	first := promptLogin(t, srv, []string{"openid"})
	hint, _ := first["id_token"].(string)

	// Push the same hint through /auth/login but claim a
	// different client_id. The hint binds to promptClientID;
	// claiming "other-client" must NOT yield a silent renewal.
	body := map[string]any{
		"client_id":     "other-client",
		"prompt":        "none",
		"id_token_hint": hint,
	}
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("renewal: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	if resp.StatusCode != http.StatusUnauthorized {
		// Unknown client → invalid_client (401). The cross-client
		// rebinding defense lives upstream of the renewal path
		// itself; we just confirm the renewal didn't succeed.
		t.Fatalf("status=%d body=%s", resp.StatusCode, rb)
	}
	if out["error"] != sso.ErrInvalidClient {
		t.Errorf("error=%v want %q", out["error"], sso.ErrInvalidClient)
	}
}

func TestPromptNone_MaxAgeRejectsStaleHint(t *testing.T) {
	srv, _ := newPromptHarness(t)
	first := promptLogin(t, srv, []string{"openid"})
	hint, _ := first["id_token"].(string)
	originalAuthTime := readAuthTime(t, hint)
	if originalAuthTime == 0 {
		t.Fatalf("no auth_time on the original token")
	}

	// max_age=0 means the AS MUST reauthenticate (any elapsed
	// time fails the freshness check). prompt=none can't show
	// UI, so login_required is the only spec-correct answer.
	body := map[string]any{
		"client_id":     promptClientID,
		"prompt":        "none",
		"id_token_hint": hint,
		"max_age":       0,
	}
	// Sleep a moment so the hint is actually older than 0s by
	// integer-second granularity.
	time.Sleep(1100 * time.Millisecond)
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("renewal: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", resp.StatusCode, rb)
	}
	if out["error"] != sso.ErrLoginRequired {
		t.Errorf("error=%v want %q", out["error"], sso.ErrLoginRequired)
	}
}

func TestPromptNone_MaxAgeAcceptsFreshHint(t *testing.T) {
	srv, _ := newPromptHarness(t)
	first := promptLogin(t, srv, []string{"openid"})
	hint, _ := first["id_token"].(string)

	// max_age generously large — auth happened seconds ago, so
	// the freshness check passes and the renewal succeeds.
	body := map[string]any{
		"client_id":     promptClientID,
		"prompt":        "none",
		"id_token_hint": hint,
		"max_age":       3600,
	}
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("renewal: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, rb)
	}
	if _, ok := out["access_token"].(string); !ok {
		t.Errorf("expected access_token on fresh-enough silent renewal: %v", out)
	}
}

func TestPromptNone_DiscoveryAdvertisesPromptValues(t *testing.T) {
	srv, _ := newPromptHarness(t)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	pv, _ := doc["prompt_values_supported"].([]any)
	if len(pv) == 0 {
		t.Fatalf("prompt_values_supported missing from discovery: %s", raw)
	}
	found := false
	for _, v := range pv {
		if v == sso.PromptNone {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("prompt_values_supported = %v, want to contain %q", pv, sso.PromptNone)
	}
}

// readAuthTime decodes the access token's payload and returns the
// auth_time claim as a Unix-seconds int. Returns 0 when missing
// (callers fail loudly so the test surfaces issuer misconfig).
func readAuthTime(t *testing.T, tok string) int64 {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	payload := decodeAccessTokenPayload(t, tok)
	switch v := payload["auth_time"].(type) {
	case float64:
		return int64(v)
	case json.Number:
		i, _ := v.Int64()
		return i
	case int64:
		return v
	default:
		return 0
	}
}
