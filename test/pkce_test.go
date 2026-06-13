package ssotest

import "github.com/snaplink/sso/oauth"

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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

// PKCE test constants kept distinct from the auth_code_test suite so
// the two can run in parallel without clashing on the shared package
// vars.
const (
	pkceUser     = "u-pkce"
	pkceClient   = "pkce-client"
	pkceSecret   = "pkce-secret"
	pkceRedirect = "https://app.example.com/cb"
	pkceUsername = "alice"
	pkcePassword = "pw"
)

// validVerifier is a deterministic 43-char base64url string used as the
// canonical PKCE code_verifier in tests. Length matches the RFC 7636
// §4.1 minimum.
const validVerifier = "abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"

// s256Challenge returns the S256-derived code_challenge for a verifier.
func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// newPKCEServer wires the same surface as the auth_code harness, with
// an optional Client.RequirePKCE toggle.
func newPKCEServer(t *testing.T, requirePKCE bool) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: pkceUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    pkceClient,
		Secret:                pkceSecret,
		Name:                  "PKCE Client",
		RedirectURIs:          []string{pkceRedirect},
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		Active:                true,
		RequirePKCE:           requirePKCE,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == pkceUsername && p == pkcePassword {
				return &sso.AuthResult{UserID: pkceUser}, nil
			}
			return nil, errors.New("bad")
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// requestCodeWithPKCE drives /auth/login response_type=code with the
// supplied PKCE parameters, returns status + body.
func requestCodeWithPKCE(t *testing.T, srv *httptest.Server, challenge, method string) (int, map[string]any) {
	t.Helper()
	payload := map[string]any{
		"provider":      "password",
		"client_id":     pkceClient,
		"credential":    map[string]string{"username": pkceUsername, "password": pkcePassword},
		"response_type": "code",
		"redirect_uri":  pkceRedirect,
	}
	if challenge != "" {
		payload["code_challenge"] = challenge
	}
	if method != "" {
		payload["code_challenge_method"] = method
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// exchangeWithVerifier posts /token grant_type=authorization_code with
// code + optional code_verifier.
func exchangeWithVerifier(t *testing.T, srv *httptest.Server, code, verifier string) (int, map[string]any) {
	t.Helper()
	payload := map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     pkceClient,
		"client_secret": pkceSecret,
		"redirect_uri":  pkceRedirect,
	}
	if verifier != "" {
		payload["code_verifier"] = verifier
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(srv.URL+"/token", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// ---------- happy paths ----------

func TestPKCE_S256_RoundTrip(t *testing.T) {
	srv := newPKCEServer(t, false)
	challenge := s256Challenge(validVerifier)

	status, body := requestCodeWithPKCE(t, srv, challenge, "S256")
	if status != http.StatusOK {
		t.Fatalf("login status = %d body=%v", status, body)
	}
	code, _ := body["code"].(string)
	if code == "" {
		t.Fatalf("no code: %v", body)
	}

	exStatus, exBody := exchangeWithVerifier(t, srv, code, validVerifier)
	if exStatus != http.StatusOK {
		t.Fatalf("exchange status = %d body=%v", exStatus, exBody)
	}
	if exBody["access_token"] == "" {
		t.Errorf("access_token empty: %v", exBody)
	}
}

func TestPKCE_Plain_RoundTrip(t *testing.T) {
	// plain method: code_challenge == code_verifier literally.
	srv := newPKCEServer(t, false)

	status, body := requestCodeWithPKCE(t, srv, validVerifier, "plain")
	if status != http.StatusOK {
		t.Fatalf("login status = %d body=%v", status, body)
	}
	code, _ := body["code"].(string)

	exStatus, exBody := exchangeWithVerifier(t, srv, code, validVerifier)
	if exStatus != http.StatusOK {
		t.Fatalf("exchange status = %d body=%v", exStatus, exBody)
	}
}

func TestPKCE_DefaultMethodIsPlain(t *testing.T) {
	// Per RFC 7636 §4.3: code_challenge_method defaults to plain when
	// omitted from the request.
	srv := newPKCEServer(t, false)

	status, body := requestCodeWithPKCE(t, srv, validVerifier, "")
	if status != http.StatusOK {
		t.Fatalf("login status = %d body=%v", status, body)
	}
	code, _ := body["code"].(string)

	// Exchange with the literal verifier — should succeed under plain.
	exStatus, exBody := exchangeWithVerifier(t, srv, code, validVerifier)
	if exStatus != http.StatusOK {
		t.Fatalf("exchange status = %d body=%v", exStatus, exBody)
	}
}

// ---------- exchange-side failures ----------

func TestPKCE_WrongVerifierRejected(t *testing.T) {
	srv := newPKCEServer(t, false)
	challenge := s256Challenge(validVerifier)
	_, body := requestCodeWithPKCE(t, srv, challenge, "S256")
	code, _ := body["code"].(string)

	wrong := strings.Repeat("z", 43) // valid length, wrong value
	status, exBody := exchangeWithVerifier(t, srv, code, wrong)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 invalid_grant", status)
	}
	if exBody["error"] != "invalid_grant" {
		t.Errorf("error = %v want invalid_grant", exBody["error"])
	}
}

func TestPKCE_MissingVerifierWhenChallengePresent(t *testing.T) {
	srv := newPKCEServer(t, false)
	challenge := s256Challenge(validVerifier)
	_, body := requestCodeWithPKCE(t, srv, challenge, "S256")
	code, _ := body["code"].(string)

	// Empty verifier → length check fails → invalid_grant.
	status, exBody := exchangeWithVerifier(t, srv, code, "")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 invalid_grant", status)
	}
	if exBody["error"] != "invalid_grant" {
		t.Errorf("error = %v want invalid_grant", exBody["error"])
	}
}

func TestPKCE_VerifierTooShortRejected(t *testing.T) {
	srv := newPKCEServer(t, false)
	challenge := s256Challenge(validVerifier)
	_, body := requestCodeWithPKCE(t, srv, challenge, "S256")
	code, _ := body["code"].(string)

	short := strings.Repeat("x", 42) // one char below minimum
	status, _ := exchangeWithVerifier(t, srv, code, short)
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 invalid_grant for too-short verifier", status)
	}
}

func TestPKCE_VerifierTooLongRejected(t *testing.T) {
	srv := newPKCEServer(t, false)
	challenge := s256Challenge(validVerifier)
	_, body := requestCodeWithPKCE(t, srv, challenge, "S256")
	code, _ := body["code"].(string)

	long := strings.Repeat("x", 129) // one char above maximum
	status, _ := exchangeWithVerifier(t, srv, code, long)
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 invalid_grant for too-long verifier", status)
	}
}

func TestPKCE_VerifierIgnoredWhenNoChallenge(t *testing.T) {
	// Backwards-compat path: confidential client that didn't use PKCE.
	// A verifier sent on the exchange is benign — the server skips PKCE
	// because no challenge was captured at issue.
	srv := newPKCEServer(t, false)
	_, body := requestCodeWithPKCE(t, srv, "", "")
	code, _ := body["code"].(string)

	status, exBody := exchangeWithVerifier(t, srv, code, validVerifier)
	if status != http.StatusOK {
		t.Fatalf("status = %d body=%v want 200 (verifier ignored)", status, exBody)
	}
}

// ---------- login-side failures ----------

func TestPKCE_UnsupportedMethodRejected(t *testing.T) {
	srv := newPKCEServer(t, false)
	status, body := requestCodeWithPKCE(t, srv, s256Challenge(validVerifier), "MD5")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d body=%v want 400 invalid_pkce_method", status, body)
	}
	if body["error"] != "invalid_pkce_method" {
		t.Errorf("error = %v want invalid_pkce_method", body["error"])
	}
}

func TestPKCE_ChallengeTooShortRejected(t *testing.T) {
	srv := newPKCEServer(t, false)
	status, body := requestCodeWithPKCE(t, srv, strings.Repeat("x", 42), "plain")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d body=%v want 400", status, body)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %v want invalid_request", body["error"])
	}
}

func TestPKCE_ChallengeTooLongRejected(t *testing.T) {
	srv := newPKCEServer(t, false)
	status, _ := requestCodeWithPKCE(t, srv, strings.Repeat("x", 129), "plain")
	if status != http.StatusBadRequest {
		t.Errorf("status = %d want 400 invalid_request for too-long challenge", status)
	}
}

// ---------- Client.RequirePKCE policy ----------

func TestPKCE_RequirePKCERejectsMissingChallenge(t *testing.T) {
	srv := newPKCEServer(t, true) // RequirePKCE = true
	status, body := requestCodeWithPKCE(t, srv, "", "")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d body=%v want 400 pkce_required", status, body)
	}
	if body["error"] != "pkce_required" {
		t.Errorf("error = %v want pkce_required", body["error"])
	}
}

func TestPKCE_RequirePKCEAcceptsValidChallenge(t *testing.T) {
	srv := newPKCEServer(t, true)
	status, body := requestCodeWithPKCE(t, srv, s256Challenge(validVerifier), "S256")
	if status != http.StatusOK {
		t.Fatalf("status = %d body=%v", status, body)
	}
	code, _ := body["code"].(string)
	if code == "" {
		t.Errorf("missing code: %v", body)
	}
}

// ---------- oauth.AuthCode storage round-trip for PKCE fields ----------

func TestPKCE_AuthCodeStoreRoundTripsChallengeFields(t *testing.T) {
	// Direct SPI check: the in-memory oauth.AuthCodeStore must preserve the
	// CodeChallenge + CodeChallengeMethod fields end-to-end.
	store := defaultimpl.NewMemoryAuthCodeStore()
	in := &oauth.AuthCode{
		UserID:              "u",
		ClientID:            "c",
		CodeChallenge:       "abc-challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(time.Minute),
	}
	if err := store.Issue(context.Background(), "code", in); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	out, err := store.Consume(context.Background(), "code")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if out.CodeChallenge != "abc-challenge" {
		t.Errorf("CodeChallenge lost: %q", out.CodeChallenge)
	}
	if out.CodeChallengeMethod != "S256" {
		t.Errorf("CodeChallengeMethod lost: %q", out.CodeChallengeMethod)
	}
}

// ---------- composition with refresh_token ----------

func TestPKCE_AuthCodeFollowedByRefreshGrantIgnoresPKCE(t *testing.T) {
	// PKCE binds the FIRST code exchange. Once the access + refresh
	// tokens are issued, subsequent refresh_token grants don't carry a
	// code_verifier — the refresh chain is independently bound by the
	// client_id check on the refresh token, not by PKCE.
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: pkceUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: pkceClient, Secret: pkceSecret,
		RedirectURIs:          []string{pkceRedirect},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt", Active: true,
		RequirePKCE: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: pkceUser}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	// 1: request code WITH PKCE.
	challenge := s256Challenge(validVerifier)
	loginBody, _ := json.Marshal(map[string]any{
		"provider":              "password",
		"client_id":             pkceClient,
		"credential":            map[string]string{"username": "x", "password": "y"},
		"response_type":         "code",
		"redirect_uri":          pkceRedirect,
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	})
	lresp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = lresp.Body.Close() }()
	var lOut map[string]any
	_ = json.NewDecoder(lresp.Body).Decode(&lOut)
	code, _ := lOut["code"].(string)

	// 2: exchange code + verifier → get access + refresh.
	exBody, _ := json.Marshal(map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     pkceClient,
		"client_secret": pkceSecret,
		"redirect_uri":  pkceRedirect,
		"code_verifier": validVerifier,
	})
	tresp, err := http.Post(httpSrv.URL+"/token", "application/json", bytes.NewReader(exBody))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer func() { _ = tresp.Body.Close() }()
	var tOut map[string]any
	_ = json.NewDecoder(tresp.Body).Decode(&tOut)
	refresh, _ := tOut["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh_token: %v", tOut)
	}

	// 3: refresh without any PKCE field → must succeed (PKCE binds the
	// first exchange only).
	rBody, _ := json.Marshal(map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
		"client_id":     pkceClient,
		"client_secret": pkceSecret,
	})
	rresp, err := http.Post(httpSrv.URL+"/token", "application/json", bytes.NewReader(rBody))
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	defer func() { _ = rresp.Body.Close() }()
	if rresp.StatusCode != http.StatusOK {
		var out map[string]any
		_ = json.NewDecoder(rresp.Body).Decode(&out)
		t.Errorf("refresh status = %d body=%v want 200", rresp.StatusCode, out)
	}
}
