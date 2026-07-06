package ssotest

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

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// RFC 9449 §10 authorization-code DPoP binding: a client that presents a
// DPoP proof AT /auth/login binds the resulting code to that key; the
// /token authorization_code exchange must present a proof under the SAME
// key or the exchange fails. Constants kept distinct from dpop_test.go /
// pkce_test.go so the suites can run in parallel without clashing.
const (
	dpopACUser     = "u-dpop-ac"
	dpopACClient   = "dpop-ac-client"
	dpopACSecret   = "dpop-ac-secret"
	dpopACUsername = "alice"
	dpopACPassword = "pw"
	dpopACRedirect = "https://app.example.com/cb"
)

func newDPoPAuthCodeServer(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: dpopACUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    dpopACClient,
		Secret:                dpopACSecret,
		RedirectURIs:          []string{dpopACRedirect},
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		Active:                true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == dpopACUsername && p == dpopACPassword {
				return &sso.AuthResult{UserID: dpopACUser, Provider: "password"}, nil
			}
			return nil, errors.New("bad")
		},
	))
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.test"),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://sso.test"), defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// loginCodeWithDPoP drives /auth/login response_type=code, optionally
// carrying a DPoP proof header. Returns status + decoded body.
func loginCodeWithDPoP(t *testing.T, srv *httptest.Server, proof string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     dpopACClient,
		"credential":    map[string]string{"username": dpopACUsername, "password": dpopACPassword},
		"response_type": "code",
		"redirect_uri":  dpopACRedirect,
	})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/auth/login", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// exchangeCodeWithDPoP drives /token grant_type=authorization_code,
// optionally carrying a DPoP proof header.
func exchangeCodeWithDPoP(t *testing.T, srv *httptest.Server, code, proof string) (int, map[string]any) {
	t.Helper()
	form := "grant_type=authorization_code&code=" + code +
		"&client_id=" + dpopACClient + "&client_secret=" + dpopACSecret +
		"&redirect_uri=" + dpopACRedirect
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func TestDPoPAuthCode_HappyPath_SameKeyExchangeSucceeds(t *testing.T) {
	srv := newDPoPAuthCodeServer(t)
	priv, x := dpopGenKey(t)

	loginProof := signDPoPProof(t, priv, x, http.MethodPost, srv.URL+"/auth/login")
	status, body := loginCodeWithDPoP(t, srv, loginProof)
	if status != http.StatusOK {
		t.Fatalf("login status = %d body=%v", status, body)
	}
	code, _ := body["code"].(string)
	if code == "" {
		t.Fatalf("no code: %v", body)
	}

	// Same key, fresh proof (distinct jti/iat) targeting /token.
	exchangeProof := signDPoPProof(t, priv, x, http.MethodPost, srv.URL+"/token")
	exStatus, exBody := exchangeCodeWithDPoP(t, srv, code, exchangeProof)
	if exStatus != http.StatusOK {
		t.Fatalf("exchange status = %d body=%v", exStatus, exBody)
	}
	if exBody["access_token"] == "" || exBody["access_token"] == nil {
		t.Errorf("access_token empty: %v", exBody)
	}
}

func TestDPoPAuthCode_WrongKeyAtExchangeRejected(t *testing.T) {
	srv := newDPoPAuthCodeServer(t)
	priv1, x1 := dpopGenKey(t)
	priv2, x2 := dpopGenKey(t) // distinct key entirely for the wrong-key proof

	loginProof := signDPoPProof(t, priv1, x1, http.MethodPost, srv.URL+"/auth/login")
	_, body := loginCodeWithDPoP(t, srv, loginProof)
	code, _ := body["code"].(string)
	if code == "" {
		t.Fatalf("no code: %v", body)
	}

	// Present a DIFFERENT key at exchange — must be rejected even though the
	// proof itself is otherwise perfectly valid.
	wrongProof := signDPoPProof(t, priv2, x2, http.MethodPost, srv.URL+"/token")
	status, exBody := exchangeCodeWithDPoP(t, srv, code, wrongProof)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 invalid_grant, body=%v", status, exBody)
	}
	if exBody["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant (oracle-leak collapse)", exBody["error"])
	}
}

func TestDPoPAuthCode_MissingProofAtExchangeRejected(t *testing.T) {
	srv := newDPoPAuthCodeServer(t)
	priv, x := dpopGenKey(t)

	loginProof := signDPoPProof(t, priv, x, http.MethodPost, srv.URL+"/auth/login")
	_, body := loginCodeWithDPoP(t, srv, loginProof)
	code, _ := body["code"].(string)
	if code == "" {
		t.Fatalf("no code: %v", body)
	}

	// No DPoP header at all on the exchange — a bound code MUST reject.
	status, exBody := exchangeCodeWithDPoP(t, srv, code, "")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 invalid_grant, body=%v", status, exBody)
	}
	if exBody["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", exBody["error"])
	}
}

func TestDPoPAuthCode_UnboundCodeIgnoresDPoPAtExchange(t *testing.T) {
	// Backwards compatibility: a code issued WITHOUT a DPoP proof at
	// /auth/login is unbound — presenting ANY DPoP proof (or none) at
	// exchange must still succeed, exactly like the pre-feature behavior.
	srv := newDPoPAuthCodeServer(t)
	_, body := loginCodeWithDPoP(t, srv, "")
	code, _ := body["code"].(string)
	if code == "" {
		t.Fatalf("no code: %v", body)
	}

	priv, x := dpopGenKey(t)
	exchangeProof := signDPoPProof(t, priv, x, http.MethodPost, srv.URL+"/token")
	status, exBody := exchangeCodeWithDPoP(t, srv, code, exchangeProof)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (unbound code), body=%v", status, exBody)
	}
}

func TestDPoPAuthCode_LoginRejectsBadProof(t *testing.T) {
	// A malformed DPoP proof AT /auth/login fails the login outright
	// (fail-closed, mirrors the /token DPoP gate) instead of silently
	// issuing an unbound code.
	srv := newDPoPAuthCodeServer(t)
	priv, x := dpopGenKey(t)
	proof := signDPoPProof(t, priv, x, http.MethodPost, srv.URL+"/auth/login")
	parts := strings.Split(proof, ".")
	parts[2] = strings.Repeat("A", len(parts[2]))
	tampered := strings.Join(parts, ".")

	status, body := loginCodeWithDPoP(t, srv, tampered)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%v", status, body)
	}
	if body["error"] != sso.ErrInvalidDPoPProof {
		t.Errorf("error = %v, want %q", body["error"], sso.ErrInvalidDPoPProof)
	}
}
