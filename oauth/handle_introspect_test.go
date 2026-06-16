package oauth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/security"
)

// errTestInvalidToken stands in for a validation failure from the
// ValidateAnyToken seam (the production server returns a real verifier
// error here). The wire mapping is asserted via the handler's response.
var errTestInvalidToken = errors.New("oauth_test: invalid token")

// errTestInvalidClient stands in for a client-assertion verification
// failure from the VerifyJWTClientAssertion seam.
var errTestInvalidClient = errors.New("oauth_test: invalid client assertion")

// introspectDeps is a thin test adapter that wires the real in-memory
// stores into the IntrospectDeps surface. The production adapter is
// *sso.Server (accessors.go); it can't be reached here without a cycle, so
// this re-implements the same delegation with real stores.
type introspectDeps struct {
	clients  core.ClientStore
	refresh  RefreshTokenStore
	issuers  map[string]core.TokenIssuer
	validate func(ctx context.Context, token string) (*core.TokenClaims, string, error)
	verifyCA func(ctx context.Context, assertion, formClientID, asIssuer string) (string, error)
}

func (d *introspectDeps) ClientStoreAccessor() core.ClientStore     { return d.clients }
func (d *introspectDeps) JTIReplayStore() security.JTIReplayStore   { return nil }
func (d *introspectDeps) TokenIssuers() map[string]core.TokenIssuer { return d.issuers }
func (d *introspectDeps) RefreshTokenStore() RefreshTokenStore      { return d.refresh }
func (d *introspectDeps) ResolveIssuer(core.HandlerContext) string  { return "https://issuer.test" }
func (d *introspectDeps) ValidateAnyToken(ctx context.Context, token string) (*core.TokenClaims, string, error) {
	return d.validate(ctx, token)
}
func (d *introspectDeps) VerifyJWTClientAssertion(ctx context.Context, a, f, i string) (string, error) {
	return d.verifyCA(ctx, a, f, i)
}

var _ IntrospectDeps = (*introspectDeps)(nil)

// dummyIssuer satisfies map[string]core.TokenIssuer membership so
// len(TokenIssuers()) > 0 — only the count matters in introspectAccess /
// revokeAccess. Validation is short-circuited through the deps' validate hook.
type dummyIssuer struct{}

func (dummyIssuer) Issue(context.Context, *core.Subject, []string) (*core.Token, error) {
	return nil, nil
}
func (dummyIssuer) Validate(context.Context, string) (*core.TokenClaims, error) { return nil, nil }
func (dummyIssuer) Revoke(context.Context, string) error                        { return nil }

var _ core.TokenIssuer = dummyIssuer{}

func newIntrospectDeps(cs core.ClientStore, rs RefreshTokenStore) *introspectDeps {
	return &introspectDeps{
		clients: cs,
		refresh: rs,
		issuers: map[string]core.TokenIssuer{"jwt": dummyIssuer{}},
		validate: func(context.Context, string) (*core.TokenClaims, string, error) {
			return nil, "", errTestInvalidToken
		},
		verifyCA: func(context.Context, string, string, string) (string, error) {
			return "", errTestInvalidClient
		},
	}
}

func activeClient(id string) *core.Client {
	return &core.Client{ID: id, Active: true, RedirectURIs: []string{"https://rp.test/cb"}}
}

func TestHandleIntrospect(t *testing.T) {
	t.Run("misconfigured nil client store", func(t *testing.T) {
		d := &introspectDeps{}
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		HandleIntrospect(d, ctx)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})

	t.Run("bad body", func(t *testing.T) {
		cs := newMemClientStore()
		d := newIntrospectDeps(cs, newMemRefreshStore())
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{not json`)
		HandleIntrospect(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("unknown client invalid_client", func(t *testing.T) {
		cs := newMemClientStore()
		d := newIntrospectDeps(cs, newMemRefreshStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=abc&client_id=ghost&client_secret=x")
		HandleIntrospect(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrInvalidClient {
			t.Fatalf("error = %v, want %s", got, core.ErrInvalidClient)
		}
	})

	t.Run("bad secret invalid_client", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "right")
		d := newIntrospectDeps(cs, newMemRefreshStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=abc&client_id=rp&client_secret=wrong")
		HandleIntrospect(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("inactive client rejected", func(t *testing.T) {
		cs := newMemClientStore()
		c := activeClient("rp")
		c.Active = false
		cs.put(c, "s")
		d := newIntrospectDeps(cs, newMemRefreshStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=abc&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("empty token invalid_request after auth", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newIntrospectDeps(cs, newMemRefreshStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("unknown token inactive false", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newIntrospectDeps(cs, newMemRefreshStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=nope&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if got := decodeBody(t, rec)["active"]; got != false {
			t.Fatalf("active = %v, want false", got)
		}
	})

	t.Run("active access token metadata", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newIntrospectDeps(cs, newMemRefreshStore())
		now := time.Now()
		d.validate = func(context.Context, string) (*core.TokenClaims, string, error) {
			return &core.TokenClaims{
				Subject:   "user-1",
				Issuer:    "https://issuer.test",
				Audience:  []string{"rp"},
				ClientID:  "rp",
				Scopes:    []string{"openid", "profile"},
				JTI:       "jti-1",
				ExpiresAt: now.Add(time.Hour),
				IssuedAt:  now,
				NotBefore: now,
				AuthTime:  now,
				ACR:       "urn:acr:1",
				AMR:       []string{"pwd"},
			}, "jwt", nil
		}
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=valid&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		body := decodeBody(t, rec)
		if body["active"] != true {
			t.Fatalf("active = %v, want true", body["active"])
		}
		if body["sub"] != "user-1" {
			t.Errorf("sub = %v", body["sub"])
		}
		if body["client_id"] != "rp" {
			t.Errorf("client_id = %v", body["client_id"])
		}
		if body["scope"] != "openid profile" {
			t.Errorf("scope = %v", body["scope"])
		}
		if body["acr"] != "urn:acr:1" {
			t.Errorf("acr = %v", body["acr"])
		}
	})

	t.Run("active access falls back to first aud when no client_id", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newIntrospectDeps(cs, newMemRefreshStore())
		d.validate = func(context.Context, string) (*core.TokenClaims, string, error) {
			return &core.TokenClaims{Subject: "u", Audience: []string{"aud-rp"}}, "jwt", nil
		}
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=valid&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		if got := decodeBody(t, rec)["client_id"]; got != "aud-rp" {
			t.Fatalf("client_id = %v, want aud-rp", got)
		}
	})

	t.Run("refresh token via inspector with hint", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		rs := newMemRefreshStore()
		now := time.Now()
		_ = rs.Issue(context.Background(), "rtok", &RefreshToken{
			UserID: "user-9", ClientID: "rp", Scopes: []string{"offline_access"},
			IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour),
		})
		d := newIntrospectDeps(cs, rs)
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=rtok&token_type_hint=refresh_token&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		body := decodeBody(t, rec)
		if body["active"] != true {
			t.Fatalf("active = %v, want true", body["active"])
		}
		if body["sub"] != "user-9" {
			t.Errorf("sub = %v, want user-9", body["sub"])
		}
		if body["token_type_hint"] != "refresh_token" {
			t.Errorf("token_type_hint = %v", body["token_type_hint"])
		}
	})

	t.Run("bare store refresh hint falls through to inactive", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newIntrospectDeps(cs, newBareRefresh())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=x&token_type_hint=refresh_token&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		if got := decodeBody(t, rec)["active"]; got != false {
			t.Fatalf("active = %v, want false (no inspector extension)", got)
		}
	})

	t.Run("HTTP Basic beats body credentials", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "basic-secret")
		d := newIntrospectDeps(cs, newMemRefreshStore())
		// Body carries a WRONG secret; Basic carries the right one and must win.
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=x&client_id=rp&client_secret=wrong")
		ctx.Request().SetBasicAuth("rp", "basic-secret")
		HandleIntrospect(d, ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (basic creds should win)", rec.Code)
		}
	})

	t.Run("client assertion wrong type bad request", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newIntrospectDeps(cs, newMemRefreshStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=x&client_assertion=jwt&client_assertion_type=urn:wrong")
		HandleIntrospect(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("client assertion verify failure invalid_client", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newIntrospectDeps(cs, newMemRefreshStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=x&client_assertion=bad&client_assertion_type="+ClientAssertionTypeJWTBearer)
		HandleIntrospect(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("client assertion success authenticates and introspects", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newIntrospectDeps(cs, newMemRefreshStore())
		d.verifyCA = func(context.Context, string, string, string) (string, error) {
			return "rp", nil
		}
		d.validate = func(context.Context, string) (*core.TokenClaims, string, error) {
			return &core.TokenClaims{Subject: "u", ClientID: "rp"}, "jwt", nil
		}
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=valid&client_assertion=good&client_assertion_type="+ClientAssertionTypeJWTBearer)
		HandleIntrospect(d, ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if got := decodeBody(t, rec)["active"]; got != true {
			t.Fatalf("active = %v, want true", got)
		}
	})
}
