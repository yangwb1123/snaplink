package ssotest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/security"
)

const (
	jfClient   = "jf-client"
	jfUser     = "u-jf"
	jfPassword = "pw"
	jfKid      = "jf-kid-1"
	jfISS      = "https://sso.test"
	jfRedirect = "https://app.example.com/cb"
)

// captureJARFetcher implements security.JARFetcher with an in-memory map
// — lets tests control exactly what the AS sees on fetch without
// standing up a real upstream HTTPS server.
type captureJARFetcher struct {
	bodies map[string][]byte
	calls  []string
	err    error
}

func newCaptureJARFetcher() *captureJARFetcher {
	return &captureJARFetcher{bodies: map[string][]byte{}}
}

func (f *captureJARFetcher) Fetch(_ context.Context, uri string) ([]byte, error) {
	f.calls = append(f.calls, uri)
	if f.err != nil {
		return nil, f.err
	}
	body, ok := f.bodies[uri]
	if !ok {
		return nil, errors.New("not found")
	}
	return body, nil
}

type jfHarness struct {
	srv     *httptest.Server
	signKey ed25519.PrivateKey
	fetcher *captureJARFetcher
}

func newJARFetchHarness(t *testing.T, allowedURIs []string) *jfHarness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: jfUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: jfClient, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{jfRedirect},
		AllowedRequestURIs:    allowedURIs,
		JWKS: []sso.JWK{{
			Kty: "OKP", Crv: "Ed25519",
			Kid: jfKid, Alg: "EdDSA", Use: "sig",
			X: base64.RawURLEncoding.EncodeToString(pub),
		}},
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != jfPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: jfUser}, nil
		},
	))
	fetcher := newCaptureJARFetcher()
	srv := sso.NewServer(
		sso.WithIssuer(jfISS),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
		sso.WithJARFetcher(fetcher),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return &jfHarness{srv: httpSrv, signKey: priv, fetcher: fetcher}
}

func (h *jfHarness) signJAR(t *testing.T, claims map[string]any) []byte {
	t.Helper()
	header := map[string]any{"alg": "EdDSA", "typ": "oauth-authz-req+jwt", "kid": jfKid}
	hraw, _ := json.Marshal(header)
	praw, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hraw) + "." + base64.RawURLEncoding.EncodeToString(praw)
	sig := ed25519.Sign(h.signKey, []byte(signingInput))
	return []byte(signingInput + "." + base64.RawURLEncoding.EncodeToString(sig))
}

func (h *jfHarness) login(t *testing.T, requestURI string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":    "password",
		"client_id":   jfClient,
		"credential":  map[string]string{"username": jfUser, "password": jfPassword},
		"request_uri": requestURI,
	})
	resp, err := http.Post(h.srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

func TestJARFetch_HappyPath(t *testing.T) {
	const fetchURL = "https://rp.example.com/request-objects/123.jwt"
	h := newJARFetchHarness(t, []string{fetchURL})
	now := time.Now().Unix()
	jwt := h.signJAR(t, map[string]any{
		"iss": jfClient, "aud": jfISS,
		"iat": now, "exp": now + 60,
		"client_id":             jfClient,
		"response_type":         "code",
		"redirect_uri":          jfRedirect,
		"code_challenge":        strings.Repeat("a", 43),
		"code_challenge_method": "plain",
	})
	h.fetcher.bodies[fetchURL] = jwt

	status, body := h.login(t, fetchURL)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["code"] == nil {
		t.Errorf("no code in response: %v", body)
	}
	if len(h.fetcher.calls) != 1 || h.fetcher.calls[0] != fetchURL {
		t.Errorf("fetcher calls = %v want [%q]", h.fetcher.calls, fetchURL)
	}
}

func TestJARFetch_RejectsURIOutsideAllowlist(t *testing.T) {
	const allowed = "https://rp.example.com/req.jwt"
	const evil = "https://internal.network/admin"
	h := newJARFetchHarness(t, []string{allowed})
	status, body := h.login(t, evil)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	if body["error"] != sso.ErrInvalidRequestURI {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidRequestURI)
	}
	// CRITICAL: the fetcher MUST NOT have been called for the
	// disallowed URI — the SSRF defense lives upstream of the
	// fetch, not downstream of it.
	if len(h.fetcher.calls) != 0 {
		t.Errorf("fetcher called with disallowed URI: %v", h.fetcher.calls)
	}
}

func TestJARFetch_RejectsHTTPScheme(t *testing.T) {
	// http:// (no TLS) MUST be rejected — even if the client had
	// it in its allowlist, the JAR-fetcher routing only triggers
	// on https:// URIs, so http:// gets routed to the PAR path,
	// where it gets ErrInvalidRequestURI from Consume since no
	// such PAR exists.
	h := newJARFetchHarness(t, []string{"http://rp.example.com/req.jwt"})
	status, body := h.login(t, "http://rp.example.com/req.jwt")
	if status != http.StatusNotImplemented && status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 or 501 body=%v", status, body)
	}
}

func TestJARFetch_NoFetcherWiredRejects(t *testing.T) {
	// Same wiring as the harness but without WithJARFetcher —
	// the AS rejects HTTPS request_uri with invalid_request_uri.
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: jfUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: jfClient, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		AllowedRequestURIs:    []string{"https://rp.example.com/req.jwt"},
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: jfUser}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	body, _ := json.Marshal(map[string]any{
		"provider":    "password",
		"client_id":   jfClient,
		"credential":  map[string]string{},
		"request_uri": "https://rp.example.com/req.jwt",
	})
	resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
}

func TestJARFetch_DiscoveryAdvertises(t *testing.T) {
	h := newJARFetchHarness(t, nil)
	resp, err := http.Get(h.srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if v, _ := doc["request_uri_parameter_supported"].(bool); !v {
		t.Errorf("request_uri_parameter_supported = %v want true (JAR fetcher wired)", doc["request_uri_parameter_supported"])
	}
}

func TestHTTPJARFetcher_RejectsNonHTTPSScheme(t *testing.T) {
	f := security.NewHTTPJARFetcher()
	_, err := f.Fetch(context.Background(), "http://example.com/req.jwt")
	if err == nil {
		t.Fatal("expected error on non-HTTPS URI")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("err = %v want HTTPS rejection", err)
	}
}

func TestHTTPJARFetcher_RejectsOversizedBody(t *testing.T) {
	// Stand up an upstream that returns a giant body; the
	// fetcher must reject without buffering the whole thing.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		// Write 100KB — well above the 16KB cap.
		big := bytes.Repeat([]byte("A"), 100*1024)
		_, _ = w.Write(big)
	}))
	defer upstream.Close()
	f := security.NewHTTPJARFetcher()
	// Override the client so it accepts the test server's self-
	// signed cert.
	f.Client = upstream.Client()
	f.Client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	f.Client.Timeout = 5 * time.Second
	_, err := f.Fetch(context.Background(), upstream.URL+"/req.jwt")
	if err == nil {
		t.Fatal("expected oversized-body rejection")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("err = %v want exceeds-body-cap", err)
	}
}
