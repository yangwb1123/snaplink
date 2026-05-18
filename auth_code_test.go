package sso_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	codeUser        = "u-code-alice"
	codeClient      = "code-client"
	codeSecret      = "secret-value"
	codeRedirectURI = "https://app.example.com/cb"
	codeUsername    = "alice"
	codePassword    = "pw"
)

// newCodeFlowServer wires the minimum surface for an authorization_code
// round trip: an AuthCodeStore + ClientStore + UserProvider + TokenIssuer
// + a password Authenticator.
func newCodeFlowServer(t *testing.T) (*httptest.Server, *defaultimpl.MemoryAuthCodeStore, *audit.MemorySink) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: codeUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    codeClient,
		Secret:                codeSecret,
		Name:                  "Code Flow",
		RedirectURIs:          []string{codeRedirectURI},
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		Active:                true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == codeUsername && p == codePassword {
				return &sso.AuthResult{
					UserID:     codeUser,
					Attributes: map[string]string{"role": "admin"},
				}, nil
			}
			return nil, errors.New("bad")
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	store := defaultimpl.NewMemoryAuthCodeStore()
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(store, 5*time.Minute),
		sso.WithAuditRecorder(rec),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, store, sink
}

// requestCode drives /auth/login with response_type=code and returns the
// returned code value (or fails the test).
func requestCode(t *testing.T, srv *httptest.Server, redirectURI string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     codeClient,
		"credential":    map[string]string{"username": codeUsername, "password": codePassword},
		"response_type": "code",
		"redirect_uri":  redirectURI,
		"state":         "xyz",
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login = %d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	code, _ := out["code"].(string)
	if code == "" {
		t.Fatalf("missing code in %s", raw)
	}
	if out["state"] != "xyz" {
		t.Errorf("state not echoed: %v", out["state"])
	}
	return code
}

// exchangeCode posts /token with grant_type=authorization_code and the
// supplied parameters. Returns the status + body.
func exchangeCode(t *testing.T, srv *httptest.Server, code, redirectURI, clientID, secret string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     clientID,
		"client_secret": secret,
		"redirect_uri":  redirectURI,
	})
	resp, err := http.Post(srv.URL+"/token", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// ---------- happy path ----------

func TestAuthCode_FullRoundTrip(t *testing.T) {
	srv, _, sink := newCodeFlowServer(t)
	code := requestCode(t, srv, codeRedirectURI)

	status, body := exchangeCode(t, srv, code, codeRedirectURI, codeClient, codeSecret)
	if status != http.StatusOK {
		t.Fatalf("exchange status = %d body=%v", status, body)
	}
	if body["access_token"] == "" {
		t.Errorf("access_token empty: %v", body)
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", body["token_type"])
	}
	if body["token_strategy"] != "jwt" {
		t.Errorf("token_strategy = %v", body["token_strategy"])
	}

	// Audit: one login success + one token_issued from the exchange.
	events, _ := sink.Query(context.Background(), audit.Query{Type: audit.EventTokenIssued})
	if len(events) != 1 {
		t.Errorf("token_issued events = %d, want 1", len(events))
	}
}

func TestAuthCode_SingleUseEnforced(t *testing.T) {
	srv, _, _ := newCodeFlowServer(t)
	code := requestCode(t, srv, codeRedirectURI)

	if status, _ := exchangeCode(t, srv, code, codeRedirectURI, codeClient, codeSecret); status != http.StatusOK {
		t.Fatalf("first exchange status = %d", status)
	}
	// Second exchange of the same code MUST fail with invalid_grant.
	status, body := exchangeCode(t, srv, code, codeRedirectURI, codeClient, codeSecret)
	if status != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want 400", status)
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("replay error = %v, want invalid_grant", body["error"])
	}
}

// ---------- login-side validation ----------

func TestAuthCode_LoginRequiresRedirectURI(t *testing.T) {
	srv, _, _ := newCodeFlowServer(t)
	body, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     codeClient,
		"credential":    map[string]string{"username": codeUsername, "password": codePassword},
		"response_type": "code",
		// redirect_uri omitted
	})
	resp, postErr := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if postErr != nil {
		t.Fatalf("POST: %v", postErr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "invalid_redirect_uri" {
		t.Errorf("error = %v", out["error"])
	}
}

func TestAuthCode_LoginRejectsUnregisteredRedirectURI(t *testing.T) {
	srv, _, _ := newCodeFlowServer(t)
	body, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     codeClient,
		"credential":    map[string]string{"username": codeUsername, "password": codePassword},
		"response_type": "code",
		"redirect_uri":  "https://attacker.example.com/cb",
	})
	resp, postErr := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if postErr != nil {
		t.Fatalf("POST: %v", postErr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAuthCode_LoginUnsupportedResponseType(t *testing.T) {
	srv, _, _ := newCodeFlowServer(t)
	body, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     codeClient,
		"credential":    map[string]string{"username": codeUsername, "password": codePassword},
		"response_type": "id_token", // not "code" or "" or "token"
		"redirect_uri":  codeRedirectURI,
	})
	resp, postErr := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if postErr != nil {
		t.Fatalf("POST: %v", postErr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "unsupported_response_type" {
		t.Errorf("error = %v", out["error"])
	}
}

func TestAuthCode_LoginWithoutStore_NotImplemented(t *testing.T) {
	// Build a server WITHOUT WithAuthCodeStore — response_type=code
	// should return 501.
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: codeClient, Secret: codeSecret, RedirectURIs: []string{codeRedirectURI},
		AllowedAuthenticators: []string{"password"}, Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: codeUser}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	body, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     codeClient,
		"credential":    map[string]string{"username": "x", "password": "y"},
		"response_type": "code",
		"redirect_uri":  codeRedirectURI,
	})
	resp, postErr := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if postErr != nil {
		t.Fatalf("POST: %v", postErr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", resp.StatusCode)
	}
}

// ---------- exchange-side validation ----------

func TestAuthCode_ExchangeRequiresCode(t *testing.T) {
	srv, _, _ := newCodeFlowServer(t)
	status, body := exchangeCode(t, srv, "", codeRedirectURI, codeClient, codeSecret)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestAuthCode_ExchangeUnknownCode(t *testing.T) {
	srv, _, _ := newCodeFlowServer(t)
	status, body := exchangeCode(t, srv, "made-up-code", codeRedirectURI, codeClient, codeSecret)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestAuthCode_ExchangeMismatchedClient(t *testing.T) {
	srv, _, _ := newCodeFlowServer(t)
	// Register a second client that has the same secret but a different ID,
	// then try to redeem A's code with B's credentials.
	// For simplicity, we just hit the existing client_id mismatch: code
	// was issued for codeClient, but we exchange with a bogus id (which
	// will 401 invalid_client before we even reach the binding check).
	// To exercise the binding branch specifically, send a code from
	// codeClient but use the redirect mismatch path below.
	code := requestCode(t, srv, codeRedirectURI)
	status, body := exchangeCode(t, srv, code, codeRedirectURI, "wrong-client", codeSecret)
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%v", status, body)
	}
}

func TestAuthCode_ExchangeRejectsRedirectURIMismatch(t *testing.T) {
	srv, _, _ := newCodeFlowServer(t)
	code := requestCode(t, srv, codeRedirectURI)
	// Exchange with a different redirect_uri than the one we issued the
	// code against. The exchange MUST fail with invalid_redirect_uri per
	// RFC 6749 §4.1.3.
	status, body := exchangeCode(t, srv, code, "https://different.example/cb", codeClient, codeSecret)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d body=%v", status, body)
	}
	if body["error"] != "invalid_redirect_uri" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestAuthCode_ExchangeWithoutStore_NotImplemented(t *testing.T) {
	// Server with /token wired but no AuthCodeStore.
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: codeClient, Secret: codeSecret, Active: true,
	})
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	body, _ := json.Marshal(map[string]any{
		"grant_type":    "authorization_code",
		"code":          "any",
		"client_id":     codeClient,
		"client_secret": codeSecret,
	})
	resp, postErr := http.Post(httpSrv.URL+"/token", "application/json", bytes.NewReader(body))
	if postErr != nil {
		t.Fatalf("POST: %v", postErr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", resp.StatusCode)
	}
}

// ---------- TTL expiry ----------

func TestAuthCode_ExpiredCodeRejected(t *testing.T) {
	// Build a server with a 1ns TTL — codes are stale by the time the
	// exchange runs.
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: codeUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: codeClient, Secret: codeSecret, RedirectURIs: []string{codeRedirectURI},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: codeUser}, nil
		},
	))
	store := defaultimpl.NewMemoryAuthCodeStore()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(store, time.Nanosecond),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	code := requestCode(t, httpSrv, codeRedirectURI)
	time.Sleep(2 * time.Millisecond)

	status, body := exchangeCode(t, httpSrv, code, codeRedirectURI, codeClient, codeSecret)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v", body["error"])
	}
}
