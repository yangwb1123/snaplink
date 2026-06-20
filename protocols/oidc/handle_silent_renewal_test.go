package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// silentDeps is a no-mock SilentRenewalDeps. ValidateAnyToken / IssuerForClient
// / IDTokenIssuerForClient all route through real Ed25519 issuers, and the
// session manager is the real MemorySessionManager. The error-body and
// record-login callbacks are server-side seams of this dep interface.
type silentDeps struct {
	sessions    core.SessionManager
	issuer      *defaultimpl.Ed25519JWTIssuer
	idEmit      bool
	idErr       error
	strategyErr error
	recorded    bool
}

func (d *silentDeps) SessionMgr() core.SessionManager   { return d.sessions }
func (d *silentDeps) IDTokenIssuer() oidc.IDTokenIssuer { return d.issuer }
func (d *silentDeps) IDTokenIssuerForClient(*core.Client) (oidc.IDTokenIssuer, bool, error) {
	if d.idErr != nil {
		return nil, false, d.idErr
	}
	return d.issuer, d.idEmit, nil
}
func (d *silentDeps) SrvLogger() spi.Logger { return spi.NopLogger{} }
func (d *silentDeps) ValidateAnyToken(ctx context.Context, token string) (*core.TokenClaims, string, error) {
	c, err := d.issuer.Validate(ctx, token)
	if err != nil {
		return nil, "", err
	}
	return c, "jwt", nil
}
func (d *silentDeps) ResolveIssuer(core.HandlerContext) string { return "https://as.example" }
func (d *silentDeps) AuthzErrorBody(_ core.HandlerContext, code string) map[string]string {
	return map[string]string{core.KeyError: code}
}
func (d *silentDeps) AuthzErrorBodyDesc(_ core.HandlerContext, code, desc string) map[string]string {
	return map[string]string{core.KeyError: code, "error_description": desc}
}
func (d *silentDeps) IssuerForClient(*core.Client) (string, core.TokenIssuer, error) {
	if d.strategyErr != nil {
		return "", nil, d.strategyErr
	}
	return "jwt", d.issuer, nil
}
func (d *silentDeps) RecordLoginSuccess(core.HandlerContext, string, string, string, string, string) {
	d.recorded = true
}
func (d *silentDeps) EncryptIDTokenForClient(_ context.Context, _ *core.Client, signed string) (string, bool) {
	return signed, true
}

func newSilentDeps(t *testing.T) *silentDeps {
	t.Helper()
	return &silentDeps{
		sessions: defaultimpl.NewMemorySessionManager(time.Hour),
		issuer:   defaultimpl.NewEd25519JWTIssuer(),
		idEmit:   true,
	}
}

func mintHint(t *testing.T, d *silentDeps, sub, clientID string, scopes ...string) string {
	t.Helper()
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	tok, err := d.issuer.Issue(context.Background(), &core.Subject{
		ID: sub, ClientID: clientID, AuthTime: time.Now(),
	}, scopes)
	if err != nil {
		t.Fatalf("mint hint: %v", err)
	}
	return tok.AccessToken
}

func decodeBody(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode body: %v\n%s", err, b)
	}
	return m
}

func TestHandleSilentRenewal_NotPromptNonePassThrough(t *testing.T) {
	d := newSilentDeps(t)
	ctx, _ := newCtx(http.MethodGet, "/auth/login")
	if oidc.HandleSilentRenewal(d, ctx, []string{"login"}, oidc.SilentRenewalRequest{}, &core.Client{ID: "c"}) {
		t.Error("non-prompt-none must return false (caller continues)")
	}
}

func TestHandleSilentRenewal_PromptNoneCombinedInvalidRequest(t *testing.T) {
	d := newSilentDeps(t)
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	handled := oidc.HandleSilentRenewal(d, ctx, []string{"none", "consent"}, oidc.SilentRenewalRequest{}, &core.Client{ID: "c"})
	if !handled {
		t.Fatal("must handle prompt=none+other")
	}
	if got := decodeBody(t, rec.Body.Bytes())[core.KeyError]; got != core.ErrInvalidRequest {
		t.Errorf("error = %v, want invalid_request", got)
	}
}

func TestHandleSilentRenewal_NoHintLoginRequired(t *testing.T) {
	d := newSilentDeps(t)
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	oidc.HandleSilentRenewal(d, ctx, []string{"none"}, oidc.SilentRenewalRequest{}, &core.Client{ID: "c"})
	if got := decodeBody(t, rec.Body.Bytes())[core.KeyError]; got != core.ErrLoginRequired {
		t.Errorf("error = %v, want login_required", got)
	}
}

func TestHandleSilentRenewal_BadHintLoginRequired(t *testing.T) {
	d := newSilentDeps(t)
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	oidc.HandleSilentRenewal(d, ctx, []string{"none"}, oidc.SilentRenewalRequest{IDTokenHint: "garbage"}, &core.Client{ID: "c"})
	if got := decodeBody(t, rec.Body.Bytes())[core.KeyError]; got != core.ErrLoginRequired {
		t.Errorf("error = %v, want login_required (unverifiable hint)", got)
	}
}

func TestHandleSilentRenewal_ClientMismatchLoginRequired(t *testing.T) {
	d := newSilentDeps(t)
	hint := mintHint(t, d, "user-1", "client-A")
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	// Hint minted for client-A redeemed by client-B → login_required.
	oidc.HandleSilentRenewal(d, ctx, []string{"none"}, oidc.SilentRenewalRequest{IDTokenHint: hint}, &core.Client{ID: "client-B"})
	if got := decodeBody(t, rec.Body.Bytes())[core.KeyError]; got != core.ErrLoginRequired {
		t.Errorf("error = %v, want login_required (cross-RP)", got)
	}
}

func TestHandleSilentRenewal_MaxAgeExceededLoginRequired(t *testing.T) {
	d := newSilentDeps(t)
	// Mint a hint whose auth_time is in the past.
	tok, _ := d.issuer.Issue(context.Background(), &core.Subject{
		ID: "user-1", ClientID: "c", AuthTime: time.Now().Add(-time.Hour),
	}, []string{"openid"})
	maxAge := int64(60)
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	oidc.HandleSilentRenewal(d, ctx, []string{"none"},
		oidc.SilentRenewalRequest{IDTokenHint: tok.AccessToken, MaxAge: &maxAge}, &core.Client{ID: "c"})
	if got := decodeBody(t, rec.Body.Bytes())[core.KeyError]; got != core.ErrLoginRequired {
		t.Errorf("error = %v, want login_required (max_age exceeded)", got)
	}
}

func TestHandleSilentRenewal_NoSessionManagerLoginRequired(t *testing.T) {
	d := newSilentDeps(t)
	d.sessions = nil
	hint := mintHint(t, d, "user-1", "c")
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	oidc.HandleSilentRenewal(d, ctx, []string{"none"}, oidc.SilentRenewalRequest{IDTokenHint: hint}, &core.Client{ID: "c"})
	if got := decodeBody(t, rec.Body.Bytes())[core.KeyError]; got != core.ErrLoginRequired {
		t.Errorf("error = %v, want login_required (no session manager)", got)
	}
}

func TestHandleSilentRenewal_NoLiveSessionLoginRequired(t *testing.T) {
	d := newSilentDeps(t)
	// No session created for user-1 → ListByUser empty → login_required.
	hint := mintHint(t, d, "user-1", "c")
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	oidc.HandleSilentRenewal(d, ctx, []string{"none"}, oidc.SilentRenewalRequest{IDTokenHint: hint}, &core.Client{ID: "c"})
	if got := decodeBody(t, rec.Body.Bytes())[core.KeyError]; got != core.ErrLoginRequired {
		t.Errorf("error = %v, want login_required (no live session)", got)
	}
}

func TestHandleSilentRenewal_SuccessWithIDToken(t *testing.T) {
	d := newSilentDeps(t)
	if _, err := d.sessions.Create(context.Background(), "user-1"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	hint := mintHint(t, d, "user-1", "c")
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	handled := oidc.HandleSilentRenewal(d, ctx, []string{"none"},
		oidc.SilentRenewalRequest{IDTokenHint: hint, Scope: []string{"openid"}, State: "st"},
		&core.Client{ID: "c", AccessTokenTTL: time.Hour})

	if !handled {
		t.Fatal("success path must return true")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := decodeBody(t, rec.Body.Bytes())
	if body[core.KeyAccessToken] == nil || body[core.KeyAccessToken] == "" {
		t.Error("access_token missing in silent renewal response")
	}
	if body[core.KeyIDToken] == nil {
		t.Error("id_token missing (openid scope + issuer wired)")
	}
	if body[core.KeyState] != "st" {
		t.Errorf("state = %v, want st", body[core.KeyState])
	}
	if !d.recorded {
		t.Error("silent renewal must record a login-success audit event")
	}
}

func TestHandleSilentRenewal_SuccessNoOpenIDOmitsIDToken(t *testing.T) {
	d := newSilentDeps(t)
	_, _ = d.sessions.Create(context.Background(), "user-1")
	// Hint carries only a non-openid scope; the renewed token preserves it,
	// so no id_token is minted.
	hint := mintHint(t, d, "user-1", "c", "profile")
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	oidc.HandleSilentRenewal(d, ctx, []string{"none"},
		oidc.SilentRenewalRequest{IDTokenHint: hint, Scope: []string{"profile"}},
		&core.Client{ID: "c", AccessTokenTTL: time.Hour})

	body := decodeBody(t, rec.Body.Bytes())
	if _, ok := body[core.KeyIDToken]; ok {
		t.Error("id_token must be omitted without openid scope")
	}
}

func TestHandleSilentRenewal_StrategyErrorServerError(t *testing.T) {
	d := newSilentDeps(t)
	_, _ = d.sessions.Create(context.Background(), "user-1")
	hint := mintHint(t, d, "user-1", "c")
	d.strategyErr = context.DeadlineExceeded // any non-nil error
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	handled := oidc.HandleSilentRenewal(d, ctx, []string{"none"},
		oidc.SilentRenewalRequest{IDTokenHint: hint}, &core.Client{ID: "c"})
	if !handled {
		t.Fatal("must handle (return true) on strategy error")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (no token strategy)", rec.Code)
	}
}

func TestHandleSilentRenewal_IDTokenResolutionErrorOmitsIDToken(t *testing.T) {
	d := newSilentDeps(t)
	_, _ = d.sessions.Create(context.Background(), "user-1")
	hint := mintHint(t, d, "user-1", "c")
	// A misconfigured tenant id_token issuer → omit the id_token but still
	// return the access token (fail-closed on the id_token only).
	d.idErr = context.DeadlineExceeded
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	oidc.HandleSilentRenewal(d, ctx, []string{"none"},
		oidc.SilentRenewalRequest{IDTokenHint: hint, Scope: []string{"openid"}},
		&core.Client{ID: "c", AccessTokenTTL: time.Hour})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (access token still issued)", rec.Code)
	}
	body := decodeBody(t, rec.Body.Bytes())
	if _, ok := body[core.KeyIDToken]; ok {
		t.Error("id_token must be omitted when the tenant issuer resolution errors")
	}
	if body[core.KeyAccessToken] == nil {
		t.Error("access_token must still be present")
	}
}
