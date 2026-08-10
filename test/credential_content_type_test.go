package ssotest

// B4-4 endpoint tests for the opt-in strict credential wire
// (server.require_form_content_type / sso.WithCredentialFormOnly):
// with the mode ON, /token, /token/introspect, /token/revoke and /par
// accept ONLY application/x-www-form-urlencoded and answer
// 415 {"error":"invalid_request"} (plain core.ErrorBody, byte-identical
// across the four endpoints and across rejection causes) before the
// body is read. With the mode OFF (the default), every legacy JSON
// request is byte-identical to today — pinned by the unchanged
// TestFormEncoded_* / TestSdkForm_* families.
//
// Oracle-safety pins D1-D4: exact 415 bytes, body-independence,
// credential-state independence, no-store on both headers.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	formOnlyClientID = "strict-client"
	formOnlySecret   = "strict-secret"
	formOnlyUserID   = "u-strict"
)

// mintCountingIssuer wraps a real JWT issuer and counts Issue calls so
// the tests can assert the 415 rows NEVER mint (T-8(a) "never mints").
type mintCountingIssuer struct {
	core.TokenIssuer
	mints atomic.Int32
}

func (m *mintCountingIssuer) Issue(ctx context.Context, subject *core.Subject, scopes []string) (*core.Token, error) {
	m.mints.Add(1)
	return m.TokenIssuer.Issue(ctx, subject, scopes)
}

// newStrictFormHarness mirrors newFormHarness (test/oauth_bind_test.go)
// with the strict credential wire enabled and an issuer spy. passPAR
// wires a PARStore so /par is enabled.
func newStrictFormHarness(t *testing.T, passPAR bool) (*httptest.Server, *mintCountingIssuer) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: formOnlyUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: formOnlyClientID, Secret: formOnlySecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{"https://app.example/callback"},
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: formOnlyUserID, Provider: "password"}, nil
		},
	))
	issuer := &mintCountingIssuer{
		TokenIssuer: defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute)),
	}
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), time.Minute),
		sso.WithCredentialFormOnly(true),
	}
	if passPAR {
		opts = append(opts, sso.WithPARStore(defaultimpl.NewMemoryPARStore(), 0))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, issuer
}

func strictLogin(t *testing.T, srv *httptest.Server) (access, refresh string) {
	t.Helper()
	jsonBody := `{"provider":"password","client_id":"` + formOnlyClientID +
		`","credential":{"username":"x","password":"y"}}`
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", strings.NewReader(jsonBody))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	access, _ = out["access_token"].(string)
	refresh, _ = out["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("missing tokens in login: %s", raw)
	}
	return access, refresh
}

// rawPost issues one raw request and returns status, raw body and the
// full header set (no-store assertions need the headers).
func rawPost(t *testing.T, srv *httptest.Server, path, ct, body string, setAuth func(*http.Request)) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if setAuth != nil {
		setAuth(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw), resp.Header
}

const exact415Body = "{\"error\":\"invalid_request\"}\n"

func assert415(t *testing.T, status int, raw string, hdr http.Header) {
	t.Helper()
	// D1: exact bytes — status 415, Content-Type application/json (no
	// charset), body {"error":"invalid_request"}\n (ctx.JSON encoder
	// newline), byte-identical on every endpoint and rejection row.
	if status != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415; body=%s", status, raw)
	}
	if ct := hdr.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if raw != exact415Body {
		t.Errorf("body = %q, want %q", raw, exact415Body)
	}
	// D4: no-store on BOTH headers on every 415 row.
	if cc := hdr.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if p := hdr.Get("Pragma"); p != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", p)
	}
}

// ---------- T-8(a): /token strict rows ----------

func TestStrictToken_JSONRejected(t *testing.T) {
	srv, spy := newStrictFormHarness(t, false)
	before := spy.mints.Load()

	status, raw, hdr := rawPost(t, srv, "/token", "application/json",
		`{"grant_type":"client_credentials","client_id":"`+formOnlyClientID+`","client_secret":"`+formOnlySecret+`"}`,
		nil)
	assert415(t, status, raw, hdr)
	if got := spy.mints.Load(); got != before {
		t.Fatalf("415 row minted %d tokens (before=%d) — never mints", got-before, before)
	}
}

func TestStrictToken_JSONRejectedCharsetVariant(t *testing.T) {
	srv, _ := newStrictFormHarness(t, false)
	status, raw, hdr := rawPost(t, srv, "/token", "application/json; charset=utf-8",
		`{"grant_type":"client_credentials","client_id":"`+formOnlyClientID+`","client_secret":"`+formOnlySecret+`"}`,
		nil)
	assert415(t, status, raw, hdr)
}

func TestStrictToken_MissingCTRejected(t *testing.T) {
	srv, spy := newStrictFormHarness(t, false)
	before := spy.mints.Load()

	// JSON body, no Content-Type — the legacy JSON default is dead on
	// the four sites under strict mode.
	status, raw, hdr := rawPost(t, srv, "/token", "",
		`{"grant_type":"client_credentials","client_id":"`+formOnlyClientID+`","client_secret":"`+formOnlySecret+`"}`,
		nil)
	assert415(t, status, raw, hdr)

	// Empty body, no Content-Type — also 415, never the JSON default.
	status2, raw2, hdr2 := rawPost(t, srv, "/token", "", "", nil)
	assert415(t, status2, raw2, hdr2)

	if got := spy.mints.Load(); got != before {
		t.Fatalf("missing-CT rows minted %d tokens (before=%d)", got-before, before)
	}
}

func TestStrictToken_BasicAuthStill415(t *testing.T) {
	// D3: a valid Basic credential does not change the 415 — the reject
	// fires before client auth, so the envelope is byte-identical to the
	// no-creds row (media-type-deterministic, never a credential oracle).
	srv, spy := newStrictFormHarness(t, false)
	before := spy.mints.Load()

	status, raw, hdr := rawPost(t, srv, "/token", "application/json",
		`{"grant_type":"client_credentials"}`,
		func(r *http.Request) { r.SetBasicAuth(formOnlyClientID, formOnlySecret) })
	assert415(t, status, raw, hdr)
	if got := spy.mints.Load(); got != before {
		t.Fatalf("Basic-auth 415 row minted %d tokens", got-before)
	}
}

func TestStrictToken_DPoPProofStill415(t *testing.T) {
	// D3: a valid DPoP proof header cannot rescue a JSON body — the 415
	// fires before captureSenderConstraint, so no nonce stamp, no
	// invalid_dpop_proof, byte-identical envelope.
	srv, _ := newStrictFormHarness(t, false)
	status, raw, hdr := rawPost(t, srv, "/token", "application/json",
		`{"grant_type":"client_credentials","client_id":"`+formOnlyClientID+`","client_secret":"`+formOnlySecret+`"}`,
		func(r *http.Request) { r.Header.Set("DPoP", "eyJhbGciOiJFUzI1NiJ9.eyJ0eXAiOiJkcG9wK2p3dCJ9.sig") })
	assert415(t, status, raw, hdr)
	if nonce := hdr.Get("DPoP-Nonce"); nonce != "" {
		t.Errorf("DPoP-Nonce stamped on 415: %q", nonce)
	}
}

func TestStrictToken_BodyIndependent415(t *testing.T) {
	// D2: the 415 envelope does not depend on body content — malformed
	// percent-encoding and a body that would otherwise bind both 415
	// identically under a wrong Content-Type (the body is never read).
	srv, _ := newStrictFormHarness(t, false)
	for _, body := range []string{"client_id=%ZZ", "grant_type=client_credentials&client_id=abc&client_secret=x", "\x00\xff"} {
		status, raw, hdr := rawPost(t, srv, "/token", "text/plain", body, nil)
		assert415(t, status, raw, hdr)
	}
}

func TestStrictToken_CharsetParamBinds(t *testing.T) {
	// T-8(a)/case 4: a charset parameter on the form Content-Type binds —
	// identical parameter tolerance to today (bind.go normalization).
	srv, _ := newStrictFormHarness(t, false)
	status, _, _ := rawPost(t, srv, "/token",
		"application/x-www-form-urlencoded; charset=UTF-8",
		url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {formOnlyClientID},
			"client_secret": {formOnlySecret},
			"scope":         {"read write"},
		}.Encode(), nil)
	if status != http.StatusOK {
		t.Fatalf("charset form status = %d, want 200", status)
	}
}

func TestStrictToken_FormByteIdentical(t *testing.T) {
	// T-8(b) arm: the full form family runs against the strict server
	// with the same assertions as the default server — including the
	// refresh-rotation arm with single-use of the old token.
	srv, _ := newStrictFormHarness(t, false)
	_, refresh := strictLogin(t, srv)

	status, body := postForm(t, srv, "/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {formOnlyClientID},
		"client_secret": {formOnlySecret},
		"refresh_token": {refresh},
	}, [2]string{"", ""})
	if status != http.StatusOK {
		t.Fatalf("refresh form: status=%d body=%v", status, body)
	}
	newRefresh, _ := body["refresh_token"].(string)
	if newRefresh == "" {
		t.Fatal("missing rotated refresh_token")
	}
	// Rotation works: the rotated token refreshes again.
	status3, body3 := postForm(t, srv, "/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {formOnlyClientID},
		"client_secret": {formOnlySecret},
		"refresh_token": {newRefresh},
	}, [2]string{"", ""})
	if status3 != http.StatusOK {
		t.Fatalf("rotated refresh: status=%d body=%v", status3, body3)
	}
	// Single-use: replaying the OLD refresh token must now fail (the
	// replay deletes the family and returns invalid_grant).
	status2, body2 := postForm(t, srv, "/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {formOnlyClientID},
		"client_secret": {formOnlySecret},
		"refresh_token": {refresh},
	}, [2]string{"", ""})
	if status2 != http.StatusBadRequest || body2["error"] != "invalid_grant" {
		t.Fatalf("old refresh replay: status=%d body=%v, want 400 invalid_grant", status2, body2)
	}
}

func TestStrictToken_FormMalformedPercentEncoding400(t *testing.T) {
	// F6/D2: %ZZ under a form Content-Type takes the EXISTING 400
	// bind-error path — never 415, never ErrFormOnly — and carries both
	// no-store headers (D4).
	srv, _ := newStrictFormHarness(t, false)
	status, raw, hdr := rawPost(t, srv, "/token", "application/x-www-form-urlencoded",
		"grant_type=client_credentials&client_id=%ZZ", nil)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", status, raw)
	}
	if raw != "{\"error\":\"invalid_request\"}\n" {
		t.Errorf("body = %q", raw)
	}
	if cc := hdr.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if p := hdr.Get("Pragma"); p != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", p)
	}
}

// ---------- T-8(c): /introspect, /revoke, /par strict rows ----------

func TestStrictIntrospect_JSONAndMissingCTRejected(t *testing.T) {
	srv, _ := newStrictFormHarness(t, false)
	access, _ := strictLogin(t, srv)

	status, raw, hdr := rawPost(t, srv, "/token/introspect", "application/json",
		`{"token":"`+access+`"}`, nil)
	assert415(t, status, raw, hdr)

	status2, raw2, hdr2 := rawPost(t, srv, "/token/introspect", "",
		`{"token":"`+access+`"}`, nil)
	assert415(t, status2, raw2, hdr2)
}

func TestStrictRevoke_JSONAndMissingCTRejected(t *testing.T) {
	srv, _ := newStrictFormHarness(t, false)
	_, refresh := strictLogin(t, srv)

	status, raw, hdr := rawPost(t, srv, "/token/revoke", "application/json",
		`{"token":"`+refresh+`"}`, nil)
	assert415(t, status, raw, hdr)

	status2, raw2, hdr2 := rawPost(t, srv, "/token/revoke", "",
		`{"token":"`+refresh+`"}`, nil)
	assert415(t, status2, raw2, hdr2)
}

func TestStrictPAR_JSONAndMissingCTRejected(t *testing.T) {
	srv, _ := newStrictFormHarness(t, true)

	status, raw, hdr := rawPost(t, srv, "/par", "application/json",
		`{"client_id":"`+formOnlyClientID+`","client_secret":"`+formOnlySecret+`","response_type":"code","redirect_uri":"https://app.example/callback"}`,
		nil)
	assert415(t, status, raw, hdr)

	status2, raw2, hdr2 := rawPost(t, srv, "/par", "",
		`{"client_id":"`+formOnlyClientID+`"}`, nil)
	assert415(t, status2, raw2, hdr2)
}

// TestStrictAllEndpoints_ContentTypeCombinations drives the twelve
// unexpected-Content-Type rows (3 CTs × 4 endpoints): every one 415s
// with the byte-identical envelope (D1) and no side effects.
func TestStrictAllEndpoints_ContentTypeCombinations(t *testing.T) {
	srv, spy := newStrictFormHarness(t, true)
	access, refresh := strictLogin(t, srv)
	before := spy.mints.Load()

	bodies := map[string]string{
		"/token":            `{"grant_type":"client_credentials"}`,
		"/token/introspect": `{"token":"` + access + `"}`,
		"/token/revoke":     `{"token":"` + refresh + `"}`,
		"/par":              `{"client_id":"` + formOnlyClientID + `","client_secret":"` + formOnlySecret + `","response_type":"code","redirect_uri":"https://app.example/callback"}`,
	}
	for _, ct := range []string{"application/json", "multipart/form-data; boundary=x", "text/plain"} {
		for path, body := range bodies {
			status, raw, hdr := rawPost(t, srv, path, ct, body, nil)
			assert415(t, status, raw, hdr)
		}
	}
	if got := spy.mints.Load(); got != before {
		t.Fatalf("CT-combination rows minted %d tokens", got-before)
	}
}

func TestStrictIntrospect_FormByteIdentical(t *testing.T) {
	srv, _ := newStrictFormHarness(t, false)
	access, _ := strictLogin(t, srv)

	status, body := postForm(t, srv, "/token/introspect", url.Values{
		"token":           {access},
		"token_type_hint": {"access_token"},
	}, [2]string{formOnlyClientID, formOnlySecret})
	if status != http.StatusOK {
		t.Fatalf("introspect form: status=%d body=%v", status, body)
	}
	if body["active"] != true {
		t.Errorf("expected active=true, got %v", body["active"])
	}
}

func TestStrictRevoke_FormByteIdentical(t *testing.T) {
	srv, _ := newStrictFormHarness(t, false)
	_, refresh := strictLogin(t, srv)

	status, _ := postForm(t, srv, "/token/revoke", url.Values{
		"token":           {refresh},
		"token_type_hint": {"refresh_token"},
	}, [2]string{formOnlyClientID, formOnlySecret})
	if status != http.StatusOK {
		t.Fatalf("revoke form: status=%d (want 200 idempotent)", status)
	}
	// Idempotent second revoke (§2.2) still 200.
	status2, _ := postForm(t, srv, "/token/revoke", url.Values{
		"token": {refresh},
	}, [2]string{formOnlyClientID, formOnlySecret})
	if status2 != http.StatusOK {
		t.Fatalf("second revoke status=%d", status2)
	}
}

func TestStrictPAR_FormByteIdentical(t *testing.T) {
	srv, _ := newStrictFormHarness(t, true)
	status, body := postForm(t, srv, "/par", url.Values{
		"client_id":     {formOnlyClientID},
		"client_secret": {formOnlySecret},
		"response_type": {"code"},
		"redirect_uri":  {"https://app.example/callback"},
		"scope":         {"openid"},
	}, [2]string{"", ""})
	if status != http.StatusCreated {
		t.Fatalf("par form: status=%d body=%v", status, body)
	}
	if uri, _ := body["request_uri"].(string); !strings.HasPrefix(uri, "urn:ietf:params:oauth:request_uri:") {
		t.Errorf("request_uri = %q", uri)
	}
}

func TestStrictIntrospect_UnauthenticatedFormStill401(t *testing.T) {
	// T-9 pin: every BINDABLE (form) request still reaches the
	// 401 invalid_client gate — strict mode never turns a form request
	// into a different status. (The T-8(a) 415 rows cover the parse-stage
	// reject for non-form requests.)
	srv, _ := newStrictFormHarness(t, false)
	access, _ := strictLogin(t, srv)

	status, body := postForm(t, srv, "/token/introspect", url.Values{
		"token": {access},
	}, [2]string{"", ""})
	if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("status=%d body=%v, want 401 invalid_client", status, body)
	}
}

func TestStrictToken_BasicAuthPrecedenceForm(t *testing.T) {
	// D3 arm: Basic-over-body precedence is media-type-independent — a
	// form body with wrong body creds + valid Basic still mints 200.
	srv, _ := newStrictFormHarness(t, false)
	status, body := postForm(t, srv, "/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"wrong"},
		"client_secret": {"also-wrong"},
	}, [2]string{formOnlyClientID, formOnlySecret})
	if status != http.StatusOK || body["access_token"] == nil {
		t.Fatalf("status=%d body=%v, want 200 + access_token", status, body)
	}
}

// ---------- T-8(d): config append-only-when-set ----------

func TestServerOptions_AppendOnlyWhenSet(t *testing.T) {
	// Case 15: nil (key absent) appends nothing — ServerOptions is
	// byte-identical to a pre-B4-4 build; true appends
	// WithCredentialFormOnly(true); false appends the explicit-legacy
	// spelling (same behavior as unset).
	load := func(yaml string) *config.Config {
		t.Helper()
		p := filepath.Join(t.TempDir(), "sso.yaml")
		if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.LoadFromSources(context.Background(), config.NewFileSource(p))
		if err != nil {
			t.Fatalf("LoadFromSources: %v", err)
		}
		return cfg
	}

	base := "server:\n  issuer: http://localhost:8080\n  listen: \":8080\"\n"

	cfg := load(base)
	baseline := len(cfg.ServerOptions())
	if baseline == 0 {
		t.Fatal("baseline ServerOptions unexpectedly empty")
	}

	cfg = load(base + "  require_form_content_type: true\n")
	if got := len(cfg.ServerOptions()); got != baseline+1 {
		t.Fatalf("true key: %d options, want %d", got, baseline+1)
	}

	cfg = load(base + "  require_form_content_type: false\n")
	if got := len(cfg.ServerOptions()); got != baseline+1 {
		t.Fatalf("false key: %d options, want %d (explicit-legacy spelling)", got, baseline+1)
	}
}
