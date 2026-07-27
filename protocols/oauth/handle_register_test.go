package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// registerDeps is a thin test adapter wiring the real in-memory ClientStore
// into the RegisterDeps surface (production adapter: *sso.Server). Auditor()
// returns nil — audit.Recorder.Record is nil-safe, exactly as the contract
// documents.
type registerDeps struct {
	policy      *DCRPolicy
	clients     core.ClientStore
	reqErr      error    // forced RequireClientStore error
	invalidated []string // client IDs passed to InvalidateClientCache

	// quotaCharged, when true, makes CheckClientCreateQuota report a charge
	// (as if a real quota store were wired) so tests can exercise the
	// release-on-failure path. releasedQuota records ReleaseClientCreateQuota
	// calls (tenant IDs) for assertions.
	quotaCharged  bool
	releasedQuota []string
}

func (d *registerDeps) DCRPolicy() *DCRPolicy                                          { return d.policy }
func (d *registerDeps) ClientStoreAccessor() core.ClientStore                          { return d.clients }
func (d *registerDeps) SrvLogger() spi.Logger                                          { return spi.NopLogger{} }
func (d *registerDeps) ResolveIssuer(core.HandlerContext) string                       { return "https://issuer.test" }
func (d *registerDeps) SetBearerChallenge(core.HandlerContext, string, string, string) {}
func (d *registerDeps) RequireClientStore() error                                      { return d.reqErr }
func (d *registerDeps) Auditor() *audit.Recorder                                       { return nil }
func (d *registerDeps) InvalidateClientCache(id string)                                { d.invalidated = append(d.invalidated, id) }
func (d *registerDeps) CheckClientCreateQuota(core.HandlerContext, string) (bool, bool) {
	return d.quotaCharged, false
}
func (d *registerDeps) ReleaseClientCreateQuota(_ context.Context, tenantID string) {
	d.releasedQuota = append(d.releasedQuota, tenantID)
}

var _ RegisterDeps = (*registerDeps)(nil)

func newRegisterDeps(policy *DCRPolicy) (*registerDeps, *memClientStore) {
	cs := newMemClientStore()
	return &registerDeps{policy: policy, clients: cs}, cs
}

// serveMgmt drives an RFC 7592 management handler through a real
// core.StdRouter so the ":client_id" path param is extracted exactly as in
// production (core.Context.params is unexported — routing is the only seam
// that sets it). handler picks the GET/PUT/DELETE entrypoint.
func serveMgmt(d RegisterDeps, handler core.HandlerFunc, method, body, clientID, bearer string) *httptest.ResponseRecorder {
	r := core.NewStdRouter()
	register := func(p string, h core.HandlerFunc) {
		switch method {
		case http.MethodGet:
			r.GET(p, h)
		case http.MethodPut:
			r.PUT(p, h)
		case http.MethodDelete:
			r.DELETE(p, h)
		}
	}
	register("/register/:client_id", handler)

	// clientID == "" yields "/register/", which the router matches as the
	// ":client_id" pattern with an empty param — the "missing client_id"
	// branch.
	path := "/register/" + clientID
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set(core.HeaderContentType, core.ContentTypeJSON)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// mgmtHandler binds a RegisterDeps to a HandlerFunc for serveMgmt.
func mgmtHandler(d RegisterDeps, fn func(RegisterDeps, core.HandlerContext)) core.HandlerFunc {
	return func(ctx core.HandlerContext) { fn(d, ctx) }
}

func TestHandleRegister(t *testing.T) {
	t.Parallel()
	t.Run("nil policy 501", func(t *testing.T) {
		d := &registerDeps{clients: newMemClientStore()}
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		HandleRegister(d, ctx)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("status = %d, want 501", rec.Code)
		}
	})

	t.Run("require client store failure 500", func(t *testing.T) {
		d, _ := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true})
		d.reqErr = errors.New("no store")
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		HandleRegister(d, ctx)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})

	t.Run("closed registration without IAT 500", func(t *testing.T) {
		d, _ := newRegisterDeps(&DCRPolicy{}) // not open, no IAT configured
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		HandleRegister(d, ctx)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})

	t.Run("wrong initial access token 401", func(t *testing.T) {
		d, _ := newRegisterDeps(&DCRPolicy{InitialAccessToken: "secret-iat"})
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		ctx.Request().Header.Set("Authorization", "Bearer wrong")
		HandleRegister(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("bad body invalid_client_metadata", func(t *testing.T) {
		d, _ := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true})
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{bad json`)
		HandleRegister(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != ErrInvalidClientMetadata {
			t.Fatalf("error = %v, want %s", got, ErrInvalidClientMetadata)
		}
	})

	t.Run("open registration confidential client success", func(t *testing.T) {
		d, cs := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true, DefaultActive: true})
		body := `{"client_name":"acme","redirect_uris":["https://rp.test/cb"],"scope":"openid profile"}`
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, body)
		HandleRegister(d, ctx)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201", rec.Code)
		}
		resp := decodeBody(t, rec)
		id, _ := resp["client_id"].(string)
		if id == "" {
			t.Fatal("client_id missing")
		}
		if resp["client_secret"] == "" || resp["client_secret"] == nil {
			t.Fatal("confidential client must get a secret")
		}
		if resp["registration_access_token"] == nil {
			t.Fatal("registration_access_token missing")
		}
		// the client really got persisted
		stored, err := cs.Get(ctx.Request().Context(), id)
		if err != nil || stored == nil {
			t.Fatalf("client not persisted: %v", err)
		}
		if !stored.Active {
			t.Error("DefaultActive should make the client active")
		}
		// DCR MUST invalidate the client cache (evict local + publish
		// KindClientChange) so peer replicas don't serve a stale/missing client.
		if len(d.invalidated) != 1 || d.invalidated[0] != id {
			t.Errorf("InvalidateClientCache not called for the new client: got %v", d.invalidated)
		}
	})

	t.Run("public client gets no secret and forced PKCE", func(t *testing.T) {
		d, cs := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true})
		body := `{"token_endpoint_auth_method":"none","redirect_uris":["https://spa.test/cb"]}`
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, body)
		HandleRegister(d, ctx)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201", rec.Code)
		}
		resp := decodeBody(t, rec)
		if s, ok := resp["client_secret"]; ok && s != "" {
			t.Errorf("public client must NOT get a secret, got %v", s)
		}
		id, _ := resp["client_id"].(string)
		stored, _ := cs.Get(ctx.Request().Context(), id)
		if !stored.RequirePKCE {
			t.Error("public client must require PKCE")
		}
	})

	t.Run("valid IAT authorizes registration", func(t *testing.T) {
		d, _ := newRegisterDeps(&DCRPolicy{InitialAccessToken: "the-iat"})
		body := `{"client_name":"x","redirect_uris":["https://rp.test/cb"]}`
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, body)
		ctx.Request().Header.Set("Authorization", "Bearer the-iat")
		HandleRegister(d, ctx)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201", rec.Code)
		}
	})

	t.Run("missing redirect_uris for code flow rejected", func(t *testing.T) {
		d, _ := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true})
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"client_name":"x"}`)
		HandleRegister(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != ErrInvalidClientMetadata {
			t.Fatalf("error = %v, want %s", got, ErrInvalidClientMetadata)
		}
	})
}

func TestHandleRegistrationGet(t *testing.T) {
	t.Parallel()
	t.Run("nil policy 501", func(t *testing.T) {
		d := &registerDeps{clients: newMemClientStore()}
		rec := serveMgmt(d, mgmtHandler(d, HandleRegistrationGet), http.MethodGet, "", "c1", "tok")
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("status = %d, want 501", rec.Code)
		}
	})

	t.Run("require client store failure 500", func(t *testing.T) {
		d, _ := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true})
		d.reqErr = errors.New("no store")
		rec := serveMgmt(d, mgmtHandler(d, HandleRegistrationGet), http.MethodGet, "", "c1", "tok")
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})

	t.Run("missing client_id 400", func(t *testing.T) {
		d, _ := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true})
		rec := serveMgmt(d, mgmtHandler(d, HandleRegistrationGet), http.MethodGet, "", "", "tok")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("unknown client 401 invalid_token (anti-enumeration)", func(t *testing.T) {
		d, _ := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true})
		rec := serveMgmt(d, mgmtHandler(d, HandleRegistrationGet), http.MethodGet, "", "ghost", "tok")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrInvalidToken {
			t.Fatalf("error = %v, want %s", got, core.ErrInvalidToken)
		}
	})

	t.Run("wrong bearer 401", func(t *testing.T) {
		d, cs := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true})
		cs.put(&core.Client{ID: "c1", RegistrationAccessToken: "right-rat"}, "")
		rec := serveMgmt(d, mgmtHandler(d, HandleRegistrationGet), http.MethodGet, "", "c1", "wrong-rat")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("missing bearer 401", func(t *testing.T) {
		d, cs := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true})
		cs.put(&core.Client{ID: "c1", RegistrationAccessToken: "right-rat"}, "")
		rec := serveMgmt(d, mgmtHandler(d, HandleRegistrationGet), http.MethodGet, "", "c1", "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("client without RAT 401 (no management possible)", func(t *testing.T) {
		d, cs := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true})
		cs.put(&core.Client{ID: "c1"}, "") // empty RegistrationAccessToken
		rec := serveMgmt(d, mgmtHandler(d, HandleRegistrationGet), http.MethodGet, "", "c1", "anything")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("valid bearer returns metadata without secret", func(t *testing.T) {
		d, cs := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true})
		cs.put(&core.Client{
			ID: "c1", Name: "acme", RegistrationAccessToken: "right-rat",
			AllowedScopes: []string{"openid", "profile"},
			RedirectURIs:  []string{"https://rp.test/cb"},
		}, "")
		rec := serveMgmt(d, mgmtHandler(d, HandleRegistrationGet), http.MethodGet, "", "c1", "right-rat")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		resp := decodeBody(t, rec)
		if resp["client_id"] != "c1" {
			t.Errorf("client_id = %v", resp["client_id"])
		}
		if resp["scope"] != "openid profile" {
			t.Errorf("scope = %v", resp["scope"])
		}
		// GET MUST NOT re-emit the registration_access_token
		if _, ok := resp["registration_access_token"]; ok {
			t.Error("GET must not echo registration_access_token")
		}
	})
}

func TestHandleRegistrationPut(t *testing.T) {
	t.Parallel()
	t.Run("valid bearer updates metadata", func(t *testing.T) {
		d, cs := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true})
		cs.put(&core.Client{ID: "c1", Name: "old", RegistrationAccessToken: "rat", Active: true}, "")
		body := `{"client_name":"new","redirect_uris":["https://rp.test/cb"],"scope":"openid"}`
		rec := serveMgmt(d, mgmtHandler(d, HandleRegistrationPut), http.MethodPut, body, "c1", "rat")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		stored, _ := cs.Get(t.Context(), "c1")
		if stored.Name != "new" {
			t.Errorf("name = %q, want new", stored.Name)
		}
		if !stored.Active {
			t.Error("Active flag must be preserved across update")
		}
	})

	t.Run("bad body 400", func(t *testing.T) {
		d, cs := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true})
		cs.put(&core.Client{ID: "c1", RegistrationAccessToken: "rat"}, "")
		rec := serveMgmt(d, mgmtHandler(d, HandleRegistrationPut), http.MethodPut, `{bad`, "c1", "rat")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("rotate registration access token reveals new token once", func(t *testing.T) {
		d, cs := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true, RotateRegistrationAccessToken: true})
		cs.put(&core.Client{ID: "c1", RegistrationAccessToken: "rat", Active: true}, "")
		body := `{"client_name":"n","redirect_uris":["https://rp.test/cb"]}`
		rec := serveMgmt(d, mgmtHandler(d, HandleRegistrationPut), http.MethodPut, body, "c1", "rat")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		resp := decodeBody(t, rec)
		newRAT, _ := resp["registration_access_token"].(string)
		if newRAT == "" || newRAT == "rat" {
			t.Fatalf("expected a fresh rotated token, got %q", newRAT)
		}
		// the store now holds the rotated token
		stored, _ := cs.Get(t.Context(), "c1")
		if stored.RegistrationAccessToken != newRAT {
			t.Error("store should hold the rotated token")
		}
	})

	t.Run("unauthorized put 401", func(t *testing.T) {
		d, cs := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true})
		cs.put(&core.Client{ID: "c1", RegistrationAccessToken: "rat"}, "")
		rec := serveMgmt(d, mgmtHandler(d, HandleRegistrationPut), http.MethodPut, `{}`, "c1", "wrong")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}

func TestHandleRegistrationDelete(t *testing.T) {
	t.Parallel()
	t.Run("valid bearer deletes 204", func(t *testing.T) {
		d, cs := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true})
		cs.put(&core.Client{ID: "c1", RegistrationAccessToken: "rat"}, "")
		rec := serveMgmt(d, mgmtHandler(d, HandleRegistrationDelete), http.MethodDelete, "", "c1", "rat")
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
		if _, err := cs.Get(t.Context(), "c1"); err == nil {
			t.Fatal("client should be deleted")
		}
	})

	t.Run("unauthorized delete 401", func(t *testing.T) {
		d, cs := newRegisterDeps(&DCRPolicy{AllowOpenRegistration: true})
		cs.put(&core.Client{ID: "c1", RegistrationAccessToken: "rat"}, "")
		rec := serveMgmt(d, mgmtHandler(d, HandleRegistrationDelete), http.MethodDelete, "", "c1", "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}
