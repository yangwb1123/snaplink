package oidc_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// erroringUserProvider is a core.UserProvider whose GetByID always returns a
// caller-supplied error — used to simulate a transient backend failure (DB
// timeout, connection reset) as opposed to the canonical core.ErrNoSuchUser
// "definitively absent" sentinel.
type erroringUserProvider struct{ err error }

func (p *erroringUserProvider) GetByID(context.Context, string) (*core.User, error) {
	return nil, p.err
}
func (p *erroringUserProvider) GetByExternalID(context.Context, string, string) (*core.User, error) {
	return nil, p.err
}
func (p *erroringUserProvider) CreateOrUpdate(context.Context, *core.User) error { return nil }
func (p *erroringUserProvider) List(context.Context) ([]*core.User, error)       { return nil, nil }
func (p *erroringUserProvider) Delete(context.Context, string) error             { return nil }

// userinfoHandlerDeps is a minimal, no-mock oidc.UserInfoDeps: every security
// gate (DPoP/mTLS/residency/pairwise) is a pass-through no-op so the test can
// isolate the UserProvider.GetByID error-handling branch under test.
type userinfoHandlerDeps struct {
	claims *core.TokenClaims
	users  core.UserProvider
}

func (d *userinfoHandlerDeps) RequireUserInfoDeps() error              { return nil }
func (d *userinfoHandlerDeps) TokenNoStoreHeaders(core.HandlerContext) {}
func (d *userinfoHandlerDeps) BearerToken(*http.Request) string        { return "tok" }
func (d *userinfoHandlerDeps) SetResourceBearerChallenge(core.HandlerContext, string, string, string) {
}
func (d *userinfoHandlerDeps) ResolveIssuer(core.HandlerContext) string { return "https://as.example" }
func (d *userinfoHandlerDeps) ValidateAnyToken(context.Context, string) (*core.TokenClaims, string, error) {
	return d.claims, "jwt", nil
}
func (d *userinfoHandlerDeps) VerifyDPoPBearer(core.HandlerContext, *core.TokenClaims) error {
	return nil
}
func (d *userinfoHandlerDeps) IsDPoPNonceRequired(error) bool     { return false }
func (d *userinfoHandlerDeps) StampDPoPNonce(core.HandlerContext) {}
func (d *userinfoHandlerDeps) VerifyMTLSBearer(core.HandlerContext, *core.TokenClaims) error {
	return nil
}
func (d *userinfoHandlerDeps) ResidencyDeniedForAccess(core.HandlerContext, *core.TokenClaims) (string, bool) {
	return "", false
}
func (d *userinfoHandlerDeps) ResolveLocalSubject(_ context.Context, sub string) (string, error) {
	return sub, nil
}
func (d *userinfoHandlerDeps) UserProvider() core.UserProvider { return d.users }
func (d *userinfoHandlerDeps) MaybeSignUserInfo(core.HandlerContext, string, map[string]any) bool {
	return false
}
func (d *userinfoHandlerDeps) LogErrorCtx(core.HandlerContext, string, ...any) {}
func (d *userinfoHandlerDeps) SrvLogger() spi.Logger                           { return spi.NopLogger{} }

// TestHandleUserInfo_TransientLookupErrorIsNotUserNotFound guards against
// conflating "definitively absent" with "the backend hiccuped": a bearer
// token was JUST cryptographically validated (the subject unquestionably
// exists), so a non-ErrNoSuchUser GetByID failure MUST surface as a 500 —
// never as the same 404 user_not_found a genuinely deleted account gets.
// Reporting user_not_found here would tell a well-behaved RP to treat a live
// user as deleted during a mere storage blip.
func TestHandleUserInfo_TransientLookupErrorIsNotUserNotFound(t *testing.T) {
	t.Parallel()
	d := &userinfoHandlerDeps{
		claims: &core.TokenClaims{Subject: "user-1", Scopes: []string{"openid"}},
		users:  &erroringUserProvider{err: errors.New("connection reset by peer")},
	}
	ctx, rec := newCtx(http.MethodGet, "/userinfo")
	oidc.HandleUserInfo(d, ctx)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 on a transient (non-ErrNoSuchUser) lookup failure", rec.Code)
	}
	body := decodeBody(t, rec.Body.Bytes())
	if got := body[core.KeyError]; got == core.ErrUserNotFound {
		t.Errorf("error = %q, must NOT be user_not_found for a transient backend error", got)
	}
}

// TestHandleUserInfo_GenuinelyMissingUserIsNotFound is the control: the
// canonical core.ErrNoSuchUser sentinel must still map to 404 user_not_found
// (unchanged behavior for a genuinely deleted/unknown subject).
func TestHandleUserInfo_GenuinelyMissingUserIsNotFound(t *testing.T) {
	t.Parallel()
	d := &userinfoHandlerDeps{
		claims: &core.TokenClaims{Subject: "user-1", Scopes: []string{"openid"}},
		users:  &erroringUserProvider{err: core.ErrNoSuchUser},
	}
	ctx, rec := newCtx(http.MethodGet, "/userinfo")
	oidc.HandleUserInfo(d, ctx)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for the genuine core.ErrNoSuchUser sentinel", rec.Code)
	}
	body := decodeBody(t, rec.Body.Bytes())
	if got := body[core.KeyError]; got != core.ErrUserNotFound {
		t.Errorf("error = %q, want %q", got, core.ErrUserNotFound)
	}
}
