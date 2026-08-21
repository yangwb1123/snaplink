package oauth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// parDeps is a thin test adapter wiring the real in-memory PARStore +
// ClientStore into the PARDeps surface (production adapter: *sso.Server).
type parDeps struct {
	clients       core.ClientStore
	par           PARStore
	ttl           time.Duration
	verifyCA      func(ctx context.Context, assertion, formClientID, asIssuer string) (string, error)
	rarLimits     RARLimits
	maxScopeCount int
	catalog       permissions.ResourceProvider
}

func (d *parDeps) ClientStoreAccessor() core.ClientStore    { return d.clients }
func (d *parDeps) JTIReplayStore() security.JTIReplayStore  { return nil }
func (d *parDeps) PARStore() PARStore                       { return d.par }
func (d *parDeps) PARTTL() time.Duration                    { return d.ttl }
func (d *parDeps) ResolveIssuer(core.HandlerContext) string { return "https://issuer.test" }
func (d *parDeps) VerifyJWTClientAssertion(ctx context.Context, a, f, i string) (string, error) {
	return d.verifyCA(ctx, a, f, i)
}
func (d *parDeps) SrvLogger() spi.Logger                         { return spi.NopLogger{} }
func (d *parDeps) RARLimits() RARLimits                          { return d.rarLimits }
func (d *parDeps) MaxScopeCount() int                            { return d.maxScopeCount }
func (d *parDeps) ResourceCatalog() permissions.ResourceProvider { return d.catalog }

// RequireFormContentType returns false — the legacy dual-mode posture —
// so every existing JSON-post unit test in this file stays on the
// byte-identical binder path.
func (d *parDeps) RequireFormContentType() bool { return false }

var _ PARDeps = (*parDeps)(nil)

func newPARDeps(cs core.ClientStore, ps PARStore) *parDeps {
	return &parDeps{
		clients: cs,
		par:     ps,
		verifyCA: func(context.Context, string, string, string) (string, error) {
			return "", errTestInvalidClient
		},
	}
}

func TestHandlePAR(t *testing.T) {
	t.Parallel()
	t.Run("no PAR store 501", func(t *testing.T) {
		d := &parDeps{clients: newMemClientStore()}
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		HandlePAR(d, ctx)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("status = %d, want 501", rec.Code)
		}
	})

	t.Run("nil client store 500", func(t *testing.T) {
		d := &parDeps{par: newMemPARStore()}
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		HandlePAR(d, ctx)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})

	t.Run("bad body 400", func(t *testing.T) {
		d := newPARDeps(newMemClientStore(), newMemPARStore())
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{bad`)
		HandlePAR(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("missing client_id 401", func(t *testing.T) {
		d := newPARDeps(newMemClientStore(), newMemPARStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, "scope=openid")
		HandlePAR(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrMissingClientID {
			t.Fatalf("error = %v, want %s", got, core.ErrMissingClientID)
		}
	})

	t.Run("unknown client invalid_client", func(t *testing.T) {
		d := newPARDeps(newMemClientStore(), newMemPARStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=ghost&client_secret=x")
		HandlePAR(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("inactive client 403", func(t *testing.T) {
		cs := newMemClientStore()
		c := activeClient("rp")
		c.Active = false
		cs.put(c, "s")
		d := newPARDeps(cs, newMemPARStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s")
		HandlePAR(d, ctx)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrInactiveClient {
			t.Fatalf("error = %v, want %s", got, core.ErrInactiveClient)
		}
	})

	t.Run("bad secret invalid_client", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "right")
		d := newPARDeps(cs, newMemPARStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=wrong")
		HandlePAR(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	// F1 regression: a fresh-node-restored confidential client has an
	// EMPTY stored secret (snapshot artifacts never carry secrets). An
	// empty presented secret against that state must be rejected — RFC
	// 9126 §2 requires confidential clients to authenticate before push,
	// and accepting ("","") would let anyone who knows a client_id push
	// authorization requests as that client.
	t.Run("restored confidential client with empty secret 401", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "")
		d := newPARDeps(cs, newMemPARStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=")
		HandlePAR(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (empty-secret confidential client must not push)", rec.Code)
		}
	})

	// F1 negative: a PUBLIC client (token_endpoint_auth_method="none")
	// pushes PAR without a secret by design — the auth-method-aware guard
	// must skip secret validation exactly like /token does.
	t.Run("public client empty secret 201", func(t *testing.T) {
		cs := newMemClientStore()
		c := activeClient("spa")
		c.TokenEndpointAuthMethod = "none"
		cs.put(c, "")
		d := newPARDeps(cs, newMemPARStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=spa&redirect_uri=https://rp.test/cb")
		HandlePAR(d, ctx)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (public client push must keep working)", rec.Code)
		}
	})

	t.Run("disallowed redirect_uri 400", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newPARDeps(cs, newMemPARStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s&redirect_uri=https://evil.test/cb")
		HandlePAR(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrInvalidRedirectURI {
			t.Fatalf("error = %v, want %s", got, core.ErrInvalidRedirectURI)
		}
	})

	t.Run("disallowed resource invalid_target", func(t *testing.T) {
		cs := newMemClientStore()
		c := activeClient("rp")
		c.AllowedResources = []string{"https://api.test"}
		cs.put(c, "s")
		d := newPARDeps(cs, newMemPARStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s&resource=https://other.test")
		HandlePAR(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrInvalidTarget {
			t.Fatalf("error = %v, want %s", got, core.ErrInvalidTarget)
		}
	})

	t.Run("invalid response_mode 400", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newPARDeps(cs, newMemPARStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s&response_mode=bogus")
		HandlePAR(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("invalid authorization_details 400", func(t *testing.T) {
		cs := newMemClientStore()
		c := activeClient("rp")
		c.AllowedAuthorizationDetailsTypes = []string{"payment"}
		cs.put(c, "s")
		ps := newMemPARStore()
		d := newPARDeps(cs, ps)
		body := `{"client_id":"rp","client_secret":"s","authorization_details":[{"type":"unauthorized"}]}`
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, body)
		HandlePAR(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != ErrInvalidAuthorizationDetails {
			t.Fatalf("error = %v, want %s", got, ErrInvalidAuthorizationDetails)
		}
	})

	t.Run("catalog-backed authorization_details valid", func(t *testing.T) {
		cs := newMemClientStore()
		c := activeClient("rp")
		c.AllowedAuthorizationDetailsTypes = []string{"http_api"}
		cs.put(c, "s")
		catalog := permissions.NewMemoryProvider()
		if err := catalog.RegisterResource(context.Background(), &permissions.Resource{
			ID: "users", ClientID: "rp", Type: permissions.ResourceTypeHTTPAPI, Name: "users",
			Attributes: map[string]string{"method": "GET", "path": "/api/users/:id"},
		}); err != nil {
			t.Fatal(err)
		}
		d := newPARDeps(cs, newMemPARStore())
		d.catalog = catalog
		body := `{"client_id":"rp","client_secret":"s","authorization_details":[{"type":"http_api","method":"GET","path":"/api/users/42"}]}`
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, body)
		HandlePAR(d, ctx)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201", rec.Code)
		}
	})

	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "catalog-backed authorization_details unknown", path: "/api/other/42"},
		{name: "catalog-backed authorization_details mismatch", path: "/api/users/42/extra"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := newMemClientStore()
			c := activeClient("rp")
			c.AllowedAuthorizationDetailsTypes = []string{"http_api"}
			cs.put(c, "s")
			catalog := permissions.NewMemoryProvider()
			if err := catalog.RegisterResource(context.Background(), &permissions.Resource{
				ID: "users", ClientID: "rp", Type: permissions.ResourceTypeHTTPAPI, Name: "users",
				Attributes: map[string]string{"method": "GET", "path": "/api/users/:id"},
			}); err != nil {
				t.Fatal(err)
			}
			d := newPARDeps(cs, newMemPARStore())
			d.catalog = catalog
			body := `{"client_id":"rp","client_secret":"s","authorization_details":[{"type":"http_api","method":"GET","path":"` + tc.path + `"}]}`
			ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, body)
			HandlePAR(d, ctx)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if got := decodeBody(t, rec)["error"]; got != ErrInvalidAuthorizationDetails {
				t.Fatalf("error = %v, want %s", got, ErrInvalidAuthorizationDetails)
			}
		})
	}

	t.Run("scope count exceeded", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newPARDeps(cs, newMemPARStore())
		d.maxScopeCount = 2
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s&scope=a%20b%20c")
		HandlePAR(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrInvalidScope {
			t.Fatalf("error = %v, want %s", got, core.ErrInvalidScope)
		}
	})

	t.Run("scope count within configured cap ok", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newPARDeps(cs, newMemPARStore())
		d.maxScopeCount = 3
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s&scope=a%20b%20c&redirect_uri=https://rp.test/cb")
		HandlePAR(d, ctx)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201", rec.Code)
		}
	})

	t.Run("authorization_details exceeds configured element limit", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newPARDeps(cs, newMemPARStore())
		d.rarLimits = RARLimits{MaxElements: 1}
		body := `{"client_id":"rp","client_secret":"s","authorization_details":[{"type":"a"},{"type":"b"}]}`
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, body)
		HandlePAR(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != ErrInvalidAuthorizationDetails {
			t.Fatalf("error = %v, want %s", got, ErrInvalidAuthorizationDetails)
		}
	})

	t.Run("authorization_details unconfigured limits stay unbounded", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		ps := newMemPARStore()
		d := newPARDeps(cs, ps)
		body := `{"client_id":"rp","client_secret":"s","authorization_details":[{"type":"a"},{"type":"b"},{"type":"c"}]}`
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, body)
		HandlePAR(d, ctx)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (zero-value RARLimits must be unbounded)", rec.Code)
		}
	})

	t.Run("success returns request_uri and stores entry", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		ps := newMemPARStore()
		d := newPARDeps(cs, ps)
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s&scope=openid%20profile&state=xyz&redirect_uri=https://rp.test/cb")
		HandlePAR(d, ctx)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201", rec.Code)
		}
		body := decodeBody(t, rec)
		uri, _ := body["request_uri"].(string)
		if uri == "" {
			t.Fatal("request_uri missing")
		}
		// the stored entry is single-use and round-trips the params
		got, err := ps.Consume(context.Background(), uri)
		if err != nil {
			t.Fatalf("consume issued uri: %v", err)
		}
		if got.ClientID != "rp" || got.State != "xyz" {
			t.Errorf("stored entry = %+v", got)
		}
		if len(got.Scope) != 2 {
			t.Errorf("scope split = %v, want 2 entries", got.Scope)
		}
		// second consume fails (single-use)
		if _, err := ps.Consume(context.Background(), uri); !errors.Is(err, ErrPARNotFound) {
			t.Errorf("second consume err = %v, want ErrPARNotFound", err)
		}
	})

	t.Run("default TTL applied when deps TTL non-positive", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newPARDeps(cs, newMemPARStore())
		d.ttl = 0
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s")
		HandlePAR(d, ctx)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201", rec.Code)
		}
		if got := decodeBody(t, rec)["expires_in"]; got != float64(int(DefaultPARTTL.Seconds())) {
			t.Fatalf("expires_in = %v, want %d", got, int(DefaultPARTTL.Seconds()))
		}
	})

	t.Run("store issue error 500", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		ps := newMemPARStore()
		ps.issErr = errors.New("boom")
		d := newPARDeps(cs, ps)
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s")
		HandlePAR(d, ctx)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})

	t.Run("client assertion wrong type 400", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newPARDeps(cs, newMemPARStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_assertion=x&client_assertion_type=urn:wrong")
		HandlePAR(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("client assertion verify failure 401", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newPARDeps(cs, newMemPARStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_assertion=bad&client_assertion_type="+ClientAssertionTypeJWTBearer)
		HandlePAR(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("client assertion success skips secret check", func(t *testing.T) {
		cs := newMemClientStore()
		// Client has a secret, but the assertion path must NOT require it.
		cs.put(activeClient("rp"), "the-secret")
		ps := newMemPARStore()
		d := newPARDeps(cs, ps)
		d.verifyCA = func(context.Context, string, string, string) (string, error) {
			return "rp", nil
		}
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_assertion=good&client_assertion_type="+ClientAssertionTypeJWTBearer+"&scope=openid")
		HandlePAR(d, ctx)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201", rec.Code)
		}
	})

	t.Run("HTTP Basic beats body creds", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "basic-secret")
		d := newPARDeps(cs, newMemPARStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=wrong")
		ctx.Request().SetBasicAuth("rp", "basic-secret")
		HandlePAR(d, ctx)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (basic should win)", rec.Code)
		}
	})
}
