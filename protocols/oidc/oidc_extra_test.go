package oidc_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
)

// failingSigner is a real IDTokenIssuer + UserinfoSigner whose SignUserInfo
// fails — exercising MaybeSignUserInfo's sign-error branches without faking an
// in-memory SPI (this IS the dep contract under test).
type failingSigner struct{}

func (failingSigner) IssueIDToken(context.Context, *oidc.IDTokenRequest) (string, error) {
	return "id.tok.sig", nil
}
func (failingSigner) SignUserInfo(context.Context, string, map[string]any) (string, error) {
	return "", errors.New("sign boom")
}

func TestMaybeSignUserInfo_SignFailureSignOnlyFallsThrough(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	_ = store.Add(context.Background(), &core.Client{ID: "rp", UserinfoSignedResponseAlg: oidc.UserinfoSignedAlgEdDSA})
	d := &userinfoDeps{issuer: failingSigner{}, clients: store, algs: []string{"EdDSA"}, selectorOK: true}
	ctx, _ := newCtx(http.MethodGet, "/userinfo")
	// Sign-only client whose signer fails → fall through to JSON.
	if oidc.MaybeSignUserInfo(d, ctx, "rp", map[string]any{"sub": "u"}) {
		t.Error("sign failure on a sign-only client must fall through to JSON")
	}
}

func TestMaybeSignUserInfo_SignFailureWithEncryptServerError(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	_ = store.Add(context.Background(), &core.Client{
		ID:                           "rp",
		UserinfoSignedResponseAlg:    oidc.UserinfoSignedAlgEdDSA,
		UserinfoEncryptedResponseAlg: "RSA-OAEP-256",
		JWKS:                         []core.JWK{rsaEncJWK(t)},
	})
	d := &userinfoDeps{
		issuer:     failingSigner{},
		clients:    store,
		algs:       []string{"EdDSA"},
		selectorOK: true,
		encrypter:  defaultimpl.NewRSAJWEResponseEncrypter(),
	}
	ctx, rec := newCtx(http.MethodGet, "/userinfo")
	// Opted into encryption: a sign failure must NOT downgrade to cleartext;
	// it returns the undifferentiated server_error.
	if !oidc.MaybeSignUserInfo(d, ctx, "rp", map[string]any{"sub": "u"}) {
		t.Fatal("must be handled (fail closed)")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (sign failure on encrypt-opted client)", rec.Code)
	}
}

func TestRenderJARMResponse_EmptyExistingQuery(t *testing.T) {
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	// redirect_uri with NO existing query → RawQuery starts empty.
	oidc.RenderJARMResponse(ctx, &fakeSigner{}, oidc.ResponseModeQueryJWT, "https://rp.example/cb", "iss", "c", "code", "st")
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("response") == "" {
		t.Errorf("response param missing: %q", rec.Header().Get("Location"))
	}
	if rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Error("JARM redirect must set Referrer-Policy: no-referrer")
	}
}

func TestRenderJARMResponse_UnparseableRedirectURI(t *testing.T) {
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	// A control character makes url.Parse fail → 400 with a plain body
	// (no broken Location header leaked).
	handled := oidc.RenderJARMResponse(ctx, &fakeSigner{}, oidc.ResponseModeJWT, "http://\x7f/cb", "iss", "c", "code", "")
	if !handled {
		t.Fatal("RenderJARMResponse must report it handled the response")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 on unparseable redirect_uri", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Error("must not emit a Location on parse failure")
	}
}

func TestHandleSilentRenewal_MaxAgeZeroAuthTimeLoginRequired(t *testing.T) {
	d := newSilentDeps(t)
	// Mint a hint with a zero auth_time (no RFC 9068 population) — freshness
	// is unverifiable, so any max_age constraint forces login_required.
	tok, _ := d.issuer.Issue(context.Background(), &core.Subject{ID: "user-1", ClientID: "c"}, []string{"openid"})
	maxAge := int64(3600)
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	oidc.HandleSilentRenewal(d, ctx, []string{"none"},
		oidc.SilentRenewalRequest{IDTokenHint: tok.AccessToken, MaxAge: &maxAge}, &core.Client{ID: "c"})
	if got := decodeBody(t, rec.Body.Bytes())[core.KeyError]; got != core.ErrLoginRequired {
		t.Errorf("error = %v, want login_required (zero auth_time + max_age)", got)
	}
}

func TestHandleSilentRenewal_RevokedSessionLoginRequired(t *testing.T) {
	d := newSilentDeps(t)
	sess, err := d.sessions.Create(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := d.sessions.Destroy(context.Background(), sess.ID); err != nil {
		t.Fatalf("destroy session: %v", err)
	}
	hint := mintHint(t, d, "user-1", "c")
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	oidc.HandleSilentRenewal(d, ctx, []string{"none"}, oidc.SilentRenewalRequest{IDTokenHint: hint}, &core.Client{ID: "c"})
	if got := decodeBody(t, rec.Body.Bytes())[core.KeyError]; got != core.ErrLoginRequired {
		t.Errorf("error = %v, want login_required (only a destroyed session)", got)
	}
}

func TestHandleSilentRenewal_ScopeFallbackToHintScopes(t *testing.T) {
	d := newSilentDeps(t)
	_, _ = d.sessions.Create(context.Background(), "user-1")
	// Hint carries openid; the request omits Scope, so the handler must
	// preserve the hint's scopes (and therefore still mint an id_token).
	hint := mintHint(t, d, "user-1", "c", "openid", "profile")
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	oidc.HandleSilentRenewal(d, ctx, []string{"none"},
		oidc.SilentRenewalRequest{IDTokenHint: hint}, &core.Client{ID: "c", AccessTokenTTL: time.Hour})
	body := decodeBody(t, rec.Body.Bytes())
	if _, ok := body[core.KeyIDToken]; !ok {
		t.Error("hint-scope fallback must preserve openid → id_token expected")
	}
}

func TestHandleEndSession_StateAppendedToExistingQuery(t *testing.T) {
	d := newEndSessionDeps(t)
	_ = d.clients.Add(context.Background(), &core.Client{
		ID:                     "rp-1",
		PostLogoutRedirectURIs: []string{"https://rp.example/bye?ref=1"},
	})
	hint := mintAccessToken(t, d.issuer, "user-1", "rp-1")
	q := url.Values{}
	q.Set("id_token_hint", hint)
	q.Set("post_logout_redirect_uri", "https://rp.example/bye?ref=1")
	q.Set("state", "s&s")
	ctx, rec := newCtx(http.MethodGet, "/end_session?"+q.Encode())
	oidc.HandleEndSession(d, ctx)

	loc := rec.Header().Get("Location")
	// Existing query present → state must be appended with '&', and the
	// original parameter preserved.
	if !strings.Contains(loc, "ref=1") || !strings.Contains(loc, "state=") {
		t.Errorf("Location = %q, want both ref=1 and an appended state", loc)
	}
	if !strings.Contains(loc, "&state=") {
		t.Errorf("state must be appended with '&' to an existing query: %q", loc)
	}
}
