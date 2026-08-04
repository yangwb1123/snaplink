package oidc_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/shared/core"
)

// endSessionDeps is a no-mock EndSessionDeps. ValidateAnyToken delegates to a
// real Ed25519 issuer (genuine signature verification); the orchestration
// callbacks (BCL/FCL fan-out, logout recording) are part of THIS dep
// interface — server-side seams — so recording their invocations is the
// in-test composition, not a mocked SPI.
type endSessionDeps struct {
	clients   *defaultimpl.MemoryClientStore
	refresh   oauth.RefreshTokenStore
	issuer    *defaultimpl.Ed25519JWTIssuer
	fclIfr    []string
	bclCalled bool
	logoutRec bool
	revoked   []string
	failed    []string

	// sessionHubCalled + sessionHubArgs record TriggerSessionHubLogout
	// invocations (subject, sid pairs) for assertions.
	sessionHubCalled bool
	sessionHubArgs   [2]string
}

func (d *endSessionDeps) ClientStoreAccessor() core.ClientStore { return d.clients }
func (d *endSessionDeps) SubjectRefreshRevoker() oidc.SubjectRefreshRevoker {
	if idx, ok := d.refresh.(oauth.RefreshTokenSubjectIndex); ok {
		return idx
	}
	return nil
}
func (d *endSessionDeps) ValidateAnyToken(ctx context.Context, token string) (*core.TokenClaims, string, error) {
	c, err := d.issuer.Validate(ctx, token)
	if err != nil {
		return nil, "", err
	}
	return c, "jwt", nil
}
func (d *endSessionDeps) ResolveLocalSubject(_ context.Context, sub string) (string, error) {
	return sub, nil
}
func (d *endSessionDeps) RevokeAcrossIssuers(_ context.Context, _ string) ([]string, []string) {
	return d.revoked, d.failed
}
func (d *endSessionDeps) AuditPartialRevokeFailure(core.HandlerContext, []string, []string) {}
func (d *endSessionDeps) GatherFrontchannelLogoutIframes(core.HandlerContext, string, *core.Client, string) []string {
	return d.fclIfr
}
func (d *endSessionDeps) FanOutBackchannelLogout(core.HandlerContext, *core.Client, string, string) {
	d.bclCalled = true
}
func (d *endSessionDeps) TriggerSessionHubLogout(_ context.Context, subject, sid string) {
	d.sessionHubCalled = true
	d.sessionHubArgs = [2]string{subject, sid}
}
func (d *endSessionDeps) RenderFrontchannelLogout(ctx core.HandlerContext, iframeURIs []string, redirectURI string) {
	w := ctx.ResponseWriter()
	w.Header().Set("X-FCL-Iframes", strings.Join(iframeURIs, ","))
	w.Header().Set("X-FCL-Redirect", redirectURI)
	w.WriteHeader(http.StatusOK)
}
func (d *endSessionDeps) RecordLogout(core.HandlerContext, string, []string) { d.logoutRec = true }
func (d *endSessionDeps) DestroySession(_ context.Context, _ string) error   { return nil }
func (d *endSessionDeps) ClearSessionManagementCookie(core.HandlerContext)   {}

// mintIDToken issues a genuine signed JWT carrying the given subject and
// client binding, so the id_token_hint path exercises real verification.
func mintIDToken(t *testing.T, iss *defaultimpl.Ed25519JWTIssuer, sub, clientID string) string {
	t.Helper()
	tok, err := iss.IssueIDToken(context.Background(), &oidc.IDTokenRequest{
		Subject: sub, Audience: clientID, GrantedScopes: []string{"openid"},
	})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return tok
}

func newEndSessionDeps(t *testing.T) *endSessionDeps {
	t.Helper()
	return &endSessionDeps{
		clients: defaultimpl.NewMemoryClientStore(),
		refresh: defaultimpl.NewMemoryRefreshTokenStore(),
		issuer:  defaultimpl.NewEd25519JWTIssuer(),
	}
}

func TestHandleEndSession_InvalidHint400(t *testing.T) {
	t.Parallel()
	d := newEndSessionDeps(t)
	ctx, rec := newCtx(http.MethodGet, "/end_session?id_token_hint=not-a-jwt")
	oidc.HandleEndSession(d, ctx)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for bad id_token_hint", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), core.ErrInvalidToken) {
		t.Errorf("body = %q, want invalid_token", rec.Body.String())
	}
}

func TestHandleEndSession_ValidHintRedirectsWhenAllowlisted(t *testing.T) {
	t.Parallel()
	d := newEndSessionDeps(t)
	_ = d.clients.Add(context.Background(), &core.Client{
		ID:                     "rp-1",
		PostLogoutRedirectURIs: []string{"https://rp.example/bye"},
	})
	hint := mintIDToken(t, d.issuer, "user-1", "rp-1")

	q := url.Values{}
	q.Set("id_token_hint", hint)
	q.Set("post_logout_redirect_uri", "https://rp.example/bye")
	q.Set("state", "xyz")
	ctx, rec := newCtx(http.MethodGet, "/end_session?"+q.Encode())
	oidc.HandleEndSession(d, ctx)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("state") != "xyz" {
		t.Errorf("state not echoed: %q", rec.Header().Get("Location"))
	}
	if !d.bclCalled {
		t.Error("BCL fan-out must run for the hinted client")
	}
	if !d.logoutRec {
		t.Error("logout must be recorded")
	}
}

func TestHandleEndSession_RejectedRedirect204(t *testing.T) {
	t.Parallel()
	d := newEndSessionDeps(t)
	_ = d.clients.Add(context.Background(), &core.Client{
		ID:                     "rp-1",
		PostLogoutRedirectURIs: []string{"https://rp.example/allowed"},
	})
	hint := mintIDToken(t, d.issuer, "user-1", "rp-1")

	q := url.Values{}
	q.Set("id_token_hint", hint)
	// Not in the allowlist → must NOT redirect (phishing defense) → 204.
	q.Set("post_logout_redirect_uri", "https://evil.example")
	ctx, rec := newCtx(http.MethodGet, "/end_session?"+q.Encode())
	oidc.HandleEndSession(d, ctx)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 for non-allowlisted redirect", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Error("must not emit a Location for a rejected redirect")
	}
}

func TestHandleEndSession_NoRedirectURI204(t *testing.T) {
	t.Parallel()
	d := newEndSessionDeps(t)
	_ = d.clients.Add(context.Background(), &core.Client{ID: "rp-1"})
	hint := mintIDToken(t, d.issuer, "user-1", "rp-1")
	ctx, rec := newCtx(http.MethodGet, "/end_session?id_token_hint="+url.QueryEscape(hint))
	oidc.HandleEndSession(d, ctx)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 when no redirect supplied", rec.Code)
	}
}

func TestHandleEndSession_FrontchannelLogoutRendered(t *testing.T) {
	t.Parallel()
	d := newEndSessionDeps(t)
	d.fclIfr = []string{"https://rp.example/fcl"}
	_ = d.clients.Add(context.Background(), &core.Client{
		ID:                     "rp-1",
		PostLogoutRedirectURIs: []string{"https://rp.example/bye"},
	})
	hint := mintIDToken(t, d.issuer, "user-1", "rp-1")
	q := url.Values{}
	q.Set("id_token_hint", hint)
	q.Set("post_logout_redirect_uri", "https://rp.example/bye")
	ctx, rec := newCtx(http.MethodGet, "/end_session?"+q.Encode())
	oidc.HandleEndSession(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (FCL page)", rec.Code)
	}
	if rec.Header().Get("X-FCL-Iframes") == "" {
		t.Error("FCL iframes must be passed to the renderer")
	}
	if rec.Header().Get("X-FCL-Redirect") != "https://rp.example/bye" {
		t.Errorf("FCL redirect = %q, want the allowlisted target", rec.Header().Get("X-FCL-Redirect"))
	}
}

func TestHandleEndSession_ClientIDHintOnlyNoSessionKill(t *testing.T) {
	t.Parallel()
	d := newEndSessionDeps(t)
	_ = d.clients.Add(context.Background(), &core.Client{
		ID:                     "rp-1",
		PostLogoutRedirectURIs: []string{"https://rp.example/bye"},
	})
	// No id_token_hint → no signed identity → no BCL fan-out, but a
	// client_id-validated redirect is still honored.
	q := url.Values{}
	q.Set("client_id", "rp-1")
	q.Set("post_logout_redirect_uri", "https://rp.example/bye")
	ctx, rec := newCtx(http.MethodGet, "/end_session?"+q.Encode())
	oidc.HandleEndSession(d, ctx)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (client_id-validated redirect)", rec.Code)
	}
	if d.bclCalled {
		t.Error("BCL must NOT run without a signed id_token_hint")
	}
	if d.logoutRec {
		t.Error("logout must NOT be recorded without a signed identity")
	}
}

func TestHandleEndSession_NoParamsNoClient204(t *testing.T) {
	t.Parallel()
	d := newEndSessionDeps(t)
	ctx, rec := newCtx(http.MethodGet, "/end_session")
	oidc.HandleEndSession(d, ctx)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 for a bare end_session", rec.Code)
	}
}

func TestHandleEndSession_RefreshTokensPurged(t *testing.T) {
	t.Parallel()
	d := newEndSessionDeps(t)
	_ = d.clients.Add(context.Background(), &core.Client{ID: "rp-1"})
	// Seed a refresh token for (user-1, rp-1); after logout it must be gone.
	_ = d.refresh.Issue(context.Background(), "rt-1", &oauth.RefreshToken{
		UserID: "user-1", ClientID: "rp-1",
	})
	hint := mintIDToken(t, d.issuer, "user-1", "rp-1")
	ctx, _ := newCtx(http.MethodGet, "/end_session?id_token_hint="+url.QueryEscape(hint))
	oidc.HandleEndSession(d, ctx)

	if _, err := d.refresh.Consume(context.Background(), "rt-1"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("refresh token should have been purged on logout, Consume err = %v", err)
	}
}

func TestHandleEndSession_RejectsAccessTokenHint(t *testing.T) {
	t.Parallel()
	d := newEndSessionDeps(t)
	tok, err := d.issuer.Issue(context.Background(), &core.Subject{ID: "user-1", ClientID: "rp-1"}, []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, rec := newCtx(http.MethodGet, "/end_session?id_token_hint="+url.QueryEscape(tok.AccessToken))
	oidc.HandleEndSession(d, ctx)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), core.ErrInvalidToken) {
		t.Fatalf("access-token hint status/body = %d/%q, want 400 invalid_token", rec.Code, rec.Body.String())
	}
}
