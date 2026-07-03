package ssotest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/tokenusage"
	tokenusagememory "github.com/snaplink/sso/domains/tokenusage/memory"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/admin"
	"github.com/snaplink/sso/interfaces/sso"
)

const (
	tokUsageClient = "tok-usage-client"
	tokUsageSecret = "tok-usage-secret"
	tokUsageIssuer = "https://sso.tokusage.test"
)

// tokenUsageHarness wires a real Server + a real tokenusage.Recorder over a
// real in-memory Store (no mocks, per AGENTS.md §0.5) so /token issuance and
// /token/introspect can be exercised end-to-end and the aggregated buckets
// verified through the admin read API.
type tokenUsageHarness struct {
	hs  *httptest.Server
	rec *tokenusage.Recorder
}

func newTokenUsageHarness(t *testing.T) *tokenUsageHarness {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: tokUsageClient, Secret: tokUsageSecret, Active: true,
		TokenStrategy: "jwt",
	})
	rec := tokenusage.NewRecorder(tokenusagememory.New())
	rec.Start()

	srv := sso.NewServer(
		sso.WithIssuer(tokUsageIssuer),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(
			defaultimpl.WithEd25519Issuer(tokUsageIssuer),
			defaultimpl.WithEd25519TokenTTL(time.Minute),
		)),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithTokenUsageRecorder(rec),
	)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return &tokenUsageHarness{hs: hs, rec: rec}
}

// issueToken drives grant_type=client_credentials and returns the minted
// access token, the seam that Server.recordTokenIssued Offers through.
func (h *tokenUsageHarness) issueToken(t *testing.T) string {
	t.Helper()
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {tokUsageClient},
		"client_secret": {tokUsageSecret},
	}
	resp, err := http.PostForm(h.hs.URL+"/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/token status = %d, body = %s", resp.StatusCode, body)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if out.AccessToken == "" {
		t.Fatalf("empty access_token in response: %s", body)
	}
	return out.AccessToken
}

// introspect drives /token/introspect for the given token, the seam that
// introspectAccess Offers through on an ACTIVE result.
func (h *tokenUsageHarness) introspect(t *testing.T, token string) {
	t.Helper()
	form := url.Values{
		"token":         {token},
		"client_id":     {tokUsageClient},
		"client_secret": {tokUsageSecret},
	}
	resp, err := http.PostForm(h.hs.URL+"/token/introspect", form)
	if err != nil {
		t.Fatalf("POST /token/introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/token/introspect status = %d, body = %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode introspect response: %v", err)
	}
	if out["active"] != true {
		t.Fatalf("introspect active = %v, want true: %s", out["active"], body)
	}
}

// queryUsage drains the recorder (so async Offers land in the store) then
// hits the admin read API and returns the decoded buckets.
func (h *tokenUsageHarness) queryUsage(t *testing.T, qs string) []tokenusage.Bucket {
	t.Helper()
	if err := h.rec.Close(context.Background()); err != nil {
		t.Fatalf("recorder Close: %v", err)
	}
	resp, err := http.Get(h.hs.URL + "/api/v1/admin/tokens/usage" + qs)
	if err != nil {
		t.Fatalf("GET usage: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("usage status = %d, body = %s", resp.StatusCode, body)
	}
	var out struct {
		Buckets []tokenusage.Bucket `json:"buckets"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode usage response: %v", err)
	}
	return out.Buckets
}

// TestTokenUsageAdmin_IssuanceAndIntrospectionAggregate proves the whole
// Phase 1 pipeline end-to-end: a /token issuance and a /token/introspect
// call each Offer a usage event, and the admin read API reports both
// aggregated buckets for the issuing/introspecting client.
func TestTokenUsageAdmin_IssuanceAndIntrospectionAggregate(t *testing.T) {
	h := newTokenUsageHarness(t)
	token := h.issueToken(t)
	h.introspect(t, token)

	buckets := h.queryUsage(t, "?client_id="+tokUsageClient)
	var sawToken, sawIntrospect bool
	for _, b := range buckets {
		if b.ClientID != tokUsageClient || b.Kind != tokenusage.KindAccess {
			t.Errorf("unexpected bucket %+v, want client=%s kind=access", b, tokUsageClient)
			continue
		}
		switch b.Endpoint {
		case tokenusage.EndpointToken:
			sawToken = true
		case tokenusage.EndpointIntrospect:
			sawIntrospect = true
		}
	}
	if !sawToken {
		t.Errorf("no endpoint=token bucket — /token issuance did not Offer a usage event: %+v", buckets)
	}
	if !sawIntrospect {
		t.Errorf("no endpoint=introspect bucket — /token/introspect did not Offer a usage event: %+v", buckets)
	}
}

// TestTokenUsageAdmin_NotMountedWithoutRecorder proves the opt-in gate: a
// server built WITHOUT WithTokenUsageRecorder never mounts the admin usage
// route — byte-identical to a build without the feature.
func TestTokenUsageAdmin_NotMountedWithoutRecorder(t *testing.T) {
	srv := sso.NewServer(sso.WithIssuer(tokUsageIssuer))
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	resp, err := http.Get(hs.URL + "/api/v1/admin/tokens/usage")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (route must not be mounted without a recorder)", resp.StatusCode)
	}
}

// TestTokenUsageAdmin_BadQueryParamsAre400 proves malformed since/until
// query parameters fail the request rather than silently ignoring the filter.
func TestTokenUsageAdmin_BadQueryParamsAre400(t *testing.T) {
	h := newTokenUsageHarness(t)
	for _, qs := range []string{"?since=nope", "?until=nope"} {
		resp, err := http.Get(h.hs.URL + "/api/v1/admin/tokens/usage" + qs)
		if err != nil {
			t.Fatalf("GET %s: %v", qs, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s status = %d, want 400", qs, resp.StatusCode)
		}
	}
}

// TestTokenUsageAdmin_RouteResolvesAtDocumentedPath guards the group-prefix
// double-up regression this codebase has hit before (see
// TestTenantUsageRoute_ResolvesAtDocumentedPath): a full "/api/v1/..." path
// constant mounted on the /api/v1 router group double-prefixes to
// /api/v1/api/v1/... — unreachable at the documented path.
func TestTokenUsageAdmin_RouteResolvesAtDocumentedPath(t *testing.T) {
	h := newTokenUsageHarness(t)
	resp, err := http.Get(h.hs.URL + "/api/v1/admin/tokens/usage")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		t.Fatal("token-usage 404 at documented path — route mis-registered (group double-prefix)")
	}

	resp2, err := http.Get(h.hs.URL + "/api/v1/api/v1/admin/tokens/usage")
	if err != nil {
		t.Fatalf("GET doubled: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("doubled path resolved (status %d), want 404", resp2.StatusCode)
	}
}

// TestTokenUsageAdmin_PathIsAdminProtected proves the endpoint lives under
// the admin-gated prefix, so any deployment wiring AdminMiddleware (see
// test/admin_middleware_test.go) automatically requires an admin:read
// bearer for it — no per-route auth wiring needed.
func TestTokenUsageAdmin_PathIsAdminProtected(t *testing.T) {
	path := "/api/v1" + sso.PathAdminTokenUsage
	if !admin.IsProtectedPath(path) {
		t.Fatalf("IsProtectedPath(%q) = false, want true", path)
	}
}
