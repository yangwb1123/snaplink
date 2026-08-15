package caep

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

// ssfConfigDeps implements SSFConfigDeps for testing.
type ssfConfigDeps struct{}

func (d *ssfConfigDeps) ResolveIssuer(ctx core.HandlerContext) string {
	return "https://sso.example.com"
}

// ssfCtx is a minimal core.HandlerContext for testing.
type ssfCtx struct {
	w      http.ResponseWriter
	r      *http.Request
	status int
	body   any
}

func (c *ssfCtx) ResponseWriter() http.ResponseWriter { return c.w }
func (c *ssfCtx) Request() *http.Request              { return c.r }
func (c *ssfCtx) Query(name string) string            { return c.r.URL.Query().Get(name) }
func (c *ssfCtx) JSON(code int, v any) {
	c.status = code
	c.body = v
	if rw, ok := c.w.(*httptest.ResponseRecorder); ok {
		rw.WriteHeader(code)
	}
}
func (c *ssfCtx) Param(string) string                     { return "" }
func (c *ssfCtx) Bind(any) error                          { return nil }
func (c *ssfCtx) Redirect(int, string)                    {}
func (c *ssfCtx) Set(string, any)                         {}
func (c *ssfCtx) Get(string) any                          { return nil }
func (c *ssfCtx) Abort()                                  {}
func (c *ssfCtx) Aborted() bool                           { return false }
func (c *ssfCtx) Written() bool                           { return false }
func (c *ssfCtx) SetResponseWriter(w http.ResponseWriter) { c.w = w }

func TestHandleSSFConfiguration(t *testing.T) {
	deps := &ssfConfigDeps{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/ssf-configuration", nil)
	ctx := &ssfCtx{w: rec, r: req}

	HandleSSFConfiguration(deps, ctx)

	if ctx.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", ctx.status, http.StatusOK)
	}
	cfg, ok := ctx.body.(SSFConfiguration)
	if !ok {
		t.Fatalf("body type = %T, want SSFConfiguration", ctx.body)
	}
	if cfg.Issuer != "https://sso.example.com" {
		t.Errorf("Issuer = %q, want https://sso.example.com", cfg.Issuer)
	}
	if cfg.JWKSURI != "https://sso.example.com/.well-known/jwks.json" {
		t.Errorf("JWKSURI = %q", cfg.JWKSURI)
	}
	if len(cfg.DeliveryMethods) == 0 {
		t.Error("DeliveryMethods is empty")
	}
	if len(cfg.SupportedEvents) == 0 {
		t.Error("SupportedEvents is empty")
	}
}

func TestHandleSSFConfiguration_IncludesConfigEndpoint(t *testing.T) {
	deps := &ssfConfigDeps{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/ssf-configuration", nil)
	ctx := &ssfCtx{w: rec, r: req}

	HandleSSFConfiguration(deps, ctx)

	cfg := ctx.body.(SSFConfiguration)
	if cfg.ConfigurationEndpoint == "" {
		t.Error("ConfigurationEndpoint should be set")
	}
}

func TestDefaultSSFSupportedEvents(t *testing.T) {
	if len(DefaultSSFSupportedEvents) == 0 {
		t.Error("DefaultSSFSupportedEvents should not be empty")
	}
	expectedEvents := []string{
		"https://schemas.openid.net/secevent/caep/event-type/token-revocation",
		"https://schemas.openid.net/secevent/caep/event-type/session-revoked",
		"https://schemas.openid.net/secevent/caep/event-type/credential-change",
		"https://schemas.openid.net/secevent/risc/event-type/account-disabled",
		"https://schemas.openid.net/secevent/risc/event-type/account-enabled",
	}
	for _, expected := range expectedEvents {
		found := false
		for _, e := range DefaultSSFSupportedEvents {
			if e == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected event %q not found in DefaultSSFSupportedEvents", expected)
		}
	}
}
