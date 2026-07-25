package federation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

)

// tmDeps implements TrustMarkStatusDeps for testing.
type tmDeps struct {
	fetcher EntityStatementFetcher
}

func (d *tmDeps) FederationFetcher() EntityStatementFetcher { return d.fetcher }
func (d *tmDeps) LogError(msg string, args ...any)          {}

// tmCtx is a minimal core.HandlerContext for testing.
type tmCtx struct {
	w        http.ResponseWriter
	r        *http.Request
	status   int
	jsonOut  any
}

func (c *tmCtx) ResponseWriter() http.ResponseWriter { return c.w }
func (c *tmCtx) Request() *http.Request               { return c.r }
func (c *tmCtx) Query(name string) string             { return c.r.URL.Query().Get(name) }
func (c *tmCtx) JSON(code int, v any) {
	c.status = code
	c.jsonOut = v
	if rw, ok := c.w.(*httptest.ResponseRecorder); ok {
		rw.WriteHeader(code)
	}
}
func (c *tmCtx) Param(string) string  { return "" }
func (c *tmCtx) Bind(any) error       { return nil }
func (c *tmCtx) Redirect(int, string) {}
func (c *tmCtx) Set(string, any)      {}
func (c *tmCtx) Get(string) any       { return nil }

type mockFetcher struct{}

func (f *mockFetcher) FetchEntityConfiguration(ctx context.Context, entityID string) ([]byte, error) {
	return nil, nil // Will cause parse error
}

func (f *mockFetcher) FetchSubordinateStatement(ctx context.Context, fetchEndpoint, issuer, subordinate string) ([]byte, error) {
	return nil, nil
}

func TestHandleTrustMarkStatus_MissingTrustMark(t *testing.T) {
	deps := &tmDeps{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-federation-trust-mark-status", nil)
	ctx := &tmCtx{w: rec, r: req}

	HandleTrustMarkStatus(deps, ctx)

	if ctx.status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", ctx.status, http.StatusBadRequest)
	}
}

func TestHandleTrustMarkStatus_BadJWT(t *testing.T) {
	deps := &tmDeps{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/.well-known/openid-federation-trust-mark-status?trust_mark=not-a-valid-jwt", nil)
	ctx := &tmCtx{w: rec, r: req}

	HandleTrustMarkStatus(deps, ctx)

	if ctx.status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", ctx.status, http.StatusBadRequest)
	}
}

func TestHandleTrustMarkStatus_WithIssuer_FetchFails(t *testing.T) {
	deps := &tmDeps{fetcher: &mockFetcher{}}
	rec := httptest.NewRecorder()
	// A structurally valid JWT that will fail signature verification
	req := httptest.NewRequest(http.MethodGet,
		"/.well-known/openid-federation-trust-mark-status?trust_mark=eyJ0eXAiOiJ0cnVzdC1tYXJrK2p3dCIsImFsZyI6IkVkRFNBIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6Imh0dHBzOi8vcnAuZXhhbXBsZS5jb20iLCJ0cnVzdF9tYXJrX3R5cGUiOiJodHRwczovL2V4YW1wbGUuY29tL3RydXN0bWFyay90ZXN0In0.fakesignature&issuer=https://issuer.example.com", nil)
	ctx := &tmCtx{w: rec, r: req}

	HandleTrustMarkStatus(deps, ctx)

	// Should return 200 OK with valid=false since we couldn't verify
	if ctx.status != http.StatusOK {
		t.Errorf("status = %d, want %d (expected OK with valid=false)", ctx.status, http.StatusOK)
	}
	result, ok := ctx.jsonOut.(TrustMarkStatus)
	if !ok {
		t.Fatalf("response type = %T, want TrustMarkStatus", ctx.jsonOut)
	}
	if result.Valid {
		t.Error("expected Valid=false when fetch fails")
	}
}

func TestTrustMarkStatus_Fields(t *testing.T) {
	result := TrustMarkStatus{
		Valid: true, Issuer: "https://issuer.example.com",
		Subject: "https://rp.example.com", TrustMarkType: "test-type",
	}
	if !result.Valid {
		t.Error("Valid should be true")
	}
	if result.Issuer != "https://issuer.example.com" {
		t.Errorf("Issuer = %q", result.Issuer)
	}
	if result.Subject != "https://rp.example.com" {
		t.Errorf("Subject = %q", result.Subject)
	}
}

func TestResolveTMIssuer_FromQuery(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/?issuer=https://example.com", nil)
	ctx := &tmCtx{w: rec, r: req}
	claims := trustMarkClaims{Iss: "https://from-jwt.example.com"}

	issuerID := resolveTMIssuer(ctx, claims)
	if issuerID != "https://example.com" {
		t.Errorf("issuerID = %q, want https://example.com", issuerID)
	}
}

func TestResolveTMIssuer_FromClaims(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := &tmCtx{w: rec, r: req}
	claims := trustMarkClaims{Iss: "https://from-jwt.example.com"}

	issuerID := resolveTMIssuer(ctx, claims)
	if issuerID != "https://from-jwt.example.com" {
		t.Errorf("issuerID = %q, want https://from-jwt.example.com", issuerID)
	}
}

func TestCheckTMExpiry_Valid(t *testing.T) {
	claims := trustMarkClaims{Iat: 100000, Exp: 9999999999}
	if err := checkTMExpiry(claims); err != nil {
		t.Errorf("expected no error for valid dates, got: %v", err)
	}
}

func TestCheckTMExpiry_Expired(t *testing.T) {
	claims := trustMarkClaims{Exp: 1} // expired long ago
	if err := checkTMExpiry(claims); err == nil {
		t.Error("expected error for expired trust mark")
	}
}

func TestCheckTMExpiry_FutureIat(t *testing.T) {
	claims := trustMarkClaims{Iat: 9999999999} // far in the future
	if err := checkTMExpiry(claims); err == nil {
		t.Error("expected error for future iat")
	}
}
