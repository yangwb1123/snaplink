package oauth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystorecredential"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
)

// revokeDeps is a thin test adapter wiring the real in-memory stores into
// the RevokeDeps surface. The production adapter is *sso.Server
// (accessors.go) — unreachable here (cycle), so this replicates the same
// delegation with real stores + seam hooks for the crypto-backed methods.
type revokeDeps struct {
	clients      core.ClientStore
	refresh      RefreshTokenStore
	issuers      map[string]core.TokenIssuer
	validate     func(ctx context.Context, token string) (*core.TokenClaims, string, error)
	verifyCA     func(ctx context.Context, assertion, formClientID, asIssuer string) (string, error)
	resolveLocal func(ctx context.Context, sub string) (string, error)
	revokeAcross func(ctx context.Context, token string) (revoked, failed []string)
	authCreds    func(ctx core.HandlerContext, id, secret string) error
	trustedDevs  core.TrustedDeviceStore
}

func (d *revokeDeps) ClientStoreAccessor() core.ClientStore     { return d.clients }
func (d *revokeDeps) JTIReplayStore() security.JTIReplayStore   { return nil }
func (d *revokeDeps) TokenIssuers() map[string]core.TokenIssuer { return d.issuers }
func (d *revokeDeps) RefreshTokenStore() RefreshTokenStore      { return d.refresh }
func (d *revokeDeps) ResolveIssuer(core.HandlerContext) string  { return "https://issuer.test" }
func (d *revokeDeps) ValidateAnyToken(ctx context.Context, t string) (*core.TokenClaims, string, error) {
	return d.validate(ctx, t)
}
func (d *revokeDeps) VerifyJWTClientAssertion(ctx context.Context, a, f, i string) (string, error) {
	return d.verifyCA(ctx, a, f, i)
}
func (d *revokeDeps) AuthenticateClientCreds(ctx core.HandlerContext, id, secret string) error {
	return d.authCreds(ctx, id, secret)
}
func (d *revokeDeps) ResolveLocalSubject(ctx context.Context, sub string) (string, error) {
	return d.resolveLocal(ctx, sub)
}
func (d *revokeDeps) RevokeAcrossIssuers(ctx context.Context, t string) ([]string, []string) {
	return d.revokeAcross(ctx, t)
}
func (d *revokeDeps) AuditPartialRevokeFailure(core.HandlerContext, []string, []string) {}
func (d *revokeDeps) SetBearerChallenge(core.HandlerContext, string, string, string)    {}
func (d *revokeDeps) SrvLogger() spi.Logger                                             { return spi.NopLogger{} }
func (d *revokeDeps) TrustedDeviceStore() core.TrustedDeviceStore                       { return d.trustedDevs }

var _ RevokeDeps = (*revokeDeps)(nil)

// validateClientSecret mirrors the production AuthenticateClientCreds: look
// up the client, require active + valid secret. Real store, no mock.
func validateClientSecret(cs core.ClientStore) func(core.HandlerContext, string, string) error {
	return func(ctx core.HandlerContext, id, secret string) error {
		c, err := cs.Get(ctx.Request().Context(), id)
		if err != nil || c == nil || !c.Active {
			return core.ErrNoSuchClient
		}
		return cs.ValidateSecret(ctx.Request().Context(), id, secret)
	}
}

func newRevokeDeps(cs core.ClientStore, rs RefreshTokenStore) *revokeDeps {
	return &revokeDeps{
		clients: cs,
		refresh: rs,
		issuers: map[string]core.TokenIssuer{"jwt": dummyIssuer{}},
		validate: func(context.Context, string) (*core.TokenClaims, string, error) {
			return nil, "", errTestInvalidToken
		},
		verifyCA: func(context.Context, string, string, string) (string, error) {
			return "", errTestInvalidClient
		},
		resolveLocal: func(_ context.Context, sub string) (string, error) { return sub, nil },
		revokeAcross: func(context.Context, string) ([]string, []string) { return []string{"jwt"}, nil },
		authCreds:    validateClientSecret(cs),
	}
}

func TestHandleRevoke(t *testing.T) {
	t.Parallel()
	t.Run("misconfigured nil client store", func(t *testing.T) {
		d := &revokeDeps{}
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		HandleRevoke(d, ctx)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})

	t.Run("bad body", func(t *testing.T) {
		cs := newMemClientStore()
		d := newRevokeDeps(cs, newMemRefreshStore())
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{nope`)
		HandleRevoke(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("bad client creds invalid_client", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "right")
		d := newRevokeDeps(cs, newMemRefreshStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=t&client_id=rp&client_secret=wrong")
		HandleRevoke(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("empty token after auth invalid_request", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newRevokeDeps(cs, newMemRefreshStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s")
		HandleRevoke(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("valid creds unknown token still 200 (RFC 7009 §2.2)", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newRevokeDeps(cs, newMemRefreshStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=does-not-exist&client_id=rp&client_secret=s")
		HandleRevoke(d, ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (anti-enumeration)", rec.Code)
		}
	})

	t.Run("refresh token deleted via inspector", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		rs := newMemRefreshStore()
		_ = rs.Issue(context.Background(), "rtok", &RefreshToken{
			UserID: "u", ClientID: "rp", ExpiresAt: time.Now().Add(time.Hour),
		})
		d := newRevokeDeps(cs, rs)
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=rtok&client_id=rp&client_secret=s")
		HandleRevoke(d, ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if _, err := rs.Inspect(context.Background(), "rtok"); err == nil {
			t.Fatal("refresh token should have been deleted")
		}
	})

	t.Run("refresh hint reverses tier order", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		rs := newMemRefreshStore()
		_ = rs.Issue(context.Background(), "rtok", &RefreshToken{
			UserID: "u", ClientID: "rp", ExpiresAt: time.Now().Add(time.Hour),
		})
		d := newRevokeDeps(cs, rs)
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=rtok&token_type_hint=refresh_token&client_id=rp&client_secret=s")
		HandleRevoke(d, ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("bare refresh store revoke is a no-op (no inspector)", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newRevokeDeps(cs, newBareRefresh())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=anything&client_id=rp&client_secret=s")
		HandleRevoke(d, ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("HTTP Basic beats body creds", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "basic-secret")
		d := newRevokeDeps(cs, newMemRefreshStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=t&client_id=rp&client_secret=wrong")
		ctx.Request().SetBasicAuth("rp", "basic-secret")
		HandleRevoke(d, ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (basic should win)", rec.Code)
		}
	})

	t.Run("client assertion wrong type bad request", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newRevokeDeps(cs, newMemRefreshStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=t&client_assertion=x&client_assertion_type=urn:wrong")
		HandleRevoke(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("client assertion verify failure invalid_client", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newRevokeDeps(cs, newMemRefreshStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=t&client_assertion=bad&client_assertion_type="+ClientAssertionTypeJWTBearer)
		HandleRevoke(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("client assertion success revokes", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newRevokeDeps(cs, newMemRefreshStore())
		d.verifyCA = func(context.Context, string, string, string) (string, error) {
			return "rp", nil
		}
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=t&client_assertion=good&client_assertion_type="+ClientAssertionTypeJWTBearer)
		HandleRevoke(d, ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})
}

func TestHandleRevokeAll(t *testing.T) {
	t.Parallel()
	t.Run("no issuers misconfigured", func(t *testing.T) {
		d := &revokeDeps{issuers: map[string]core.TokenIssuer{}}
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		HandleRevokeAll(d, ctx)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})

	t.Run("store without subject index returns 501", func(t *testing.T) {
		cs := newMemClientStore()
		d := newRevokeDeps(cs, newBareRefresh())
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		HandleRevokeAll(d, ctx)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("status = %d, want 501", rec.Code)
		}
	})

	t.Run("missing bearer 401", func(t *testing.T) {
		cs := newMemClientStore()
		d := newRevokeDeps(cs, newMemRefreshStore())
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		HandleRevokeAll(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrMissingToken {
			t.Fatalf("error = %v, want %s", got, core.ErrMissingToken)
		}
	})

	t.Run("invalid bearer 401 invalid_token", func(t *testing.T) {
		cs := newMemClientStore()
		d := newRevokeDeps(cs, newMemRefreshStore())
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		ctx.Request().Header.Set("Authorization", "Bearer bad")
		HandleRevokeAll(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrInvalidToken {
			t.Fatalf("error = %v, want %s", got, core.ErrInvalidToken)
		}
	})

	t.Run("valid bearer kills family for subject+client", func(t *testing.T) {
		cs := newMemClientStore()
		rs := newMemRefreshStore()
		ctxbg := context.Background()
		_ = rs.Issue(ctxbg, "rt1", &RefreshToken{UserID: "u", ClientID: "rp", ExpiresAt: time.Now().Add(time.Hour)})
		_ = rs.Issue(ctxbg, "rt2", &RefreshToken{UserID: "u", ClientID: "rp", ExpiresAt: time.Now().Add(time.Hour)})
		_ = rs.Issue(ctxbg, "rt3", &RefreshToken{UserID: "other", ClientID: "rp", ExpiresAt: time.Now().Add(time.Hour)})
		// Same subject, DIFFERENT client — must survive (proves per-client scoping
		// keys on the client, not the subject alone).
		_ = rs.Issue(ctxbg, "rt4", &RefreshToken{UserID: "u", ClientID: "other-client", ExpiresAt: time.Now().Add(time.Hour)})
		d := newRevokeDeps(cs, rs)
		// Real access tokens carry the client in the RFC 9068 client_id claim;
		// aud holds RFC 8707 resource indicators, NOT the client.
		d.validate = func(context.Context, string) (*core.TokenClaims, string, error) {
			return &core.TokenClaims{Subject: "u", ClientID: "rp", Audience: []string{"https://api.example.com"}}, "jwt", nil
		}
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		ctx.Request().Header.Set("Authorization", "Bearer good")
		HandleRevokeAll(d, ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		body := decodeBody(t, rec)
		// Must revoke rt1+rt2 (u+rp) — and NOT silently 0 just because aud holds a
		// resource URI instead of the client_id (the round-9 HIGH bug).
		if body["refresh_tokens_revoked"] != float64(2) {
			t.Fatalf("revoked = %v, want 2 (resource-scoped token must still revoke by client_id)", body["refresh_tokens_revoked"])
		}
		if _, err := rs.Inspect(ctxbg, "rt3"); err != nil {
			t.Fatal("other subject's token must not be revoked")
		}
		if _, err := rs.Inspect(ctxbg, "rt4"); err != nil {
			t.Fatal("same subject's OTHER-client token must not be revoked (per-client scope)")
		}
	})

	t.Run("pairwise resolve failure 401", func(t *testing.T) {
		cs := newMemClientStore()
		d := newRevokeDeps(cs, newMemRefreshStore())
		d.validate = func(context.Context, string) (*core.TokenClaims, string, error) {
			return &core.TokenClaims{Subject: "pairwise-sub", Audience: []string{"rp"}}, "jwt", nil
		}
		d.resolveLocal = func(context.Context, string) (string, error) {
			return "", errTestInvalidToken
		}
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		ctx.Request().Header.Set("Authorization", "Bearer good")
		HandleRevokeAll(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	// TestHandleRevokeAll_CascadesToTrustedDevices is the failing-test-first
	// proof for the /token/revoke-all cascade: an attacker who minted a
	// trusted-device grant off a transiently-stolen already-MFA'd bearer
	// token must lose that standing MFA-skip the moment the legitimate user
	// calls "logout everywhere" — mirrors
	// TestRcovTrustedDevices_PasswordChangeRevokesGrants at the
	// interfaces/sso layer, but exercised directly against HandleRevokeAll
	// since that's the actual /token/revoke-all choke point.
	t.Run("cascades to trusted-device grants", func(t *testing.T) {
		cs := newMemClientStore()
		rs := newMemRefreshStore()
		tds := memorystorecredential.NewMemoryTrustedDeviceStore()
		ctxbg := context.Background()

		token, _, err := tds.Trust(ctxbg, "u", "rp", "laptop", time.Hour)
		if err != nil {
			t.Fatalf("seed trust: %v", err)
		}
		if ok, _ := tds.Verify(ctxbg, "u", "rp", token); !ok {
			t.Fatal("seed grant should verify before revoke-all")
		}

		d := newRevokeDeps(cs, rs)
		d.trustedDevs = tds
		d.validate = func(context.Context, string) (*core.TokenClaims, string, error) {
			return &core.TokenClaims{Subject: "u", ClientID: "rp", Audience: []string{"https://api.example.com"}}, "jwt", nil
		}
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		ctx.Request().Header.Set("Authorization", "Bearer good")
		HandleRevokeAll(d, ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		body := decodeBody(t, rec)
		if body["trusted_devices_revoked"] != float64(1) {
			t.Errorf("trusted_devices_revoked = %v, want 1", body["trusted_devices_revoked"])
		}
		if ok, err := tds.Verify(ctxbg, "u", "rp", token); ok || err != nil {
			t.Fatalf("grant still verifies after revoke-all: ok=%v err=%v, want ok=false", ok, err)
		}
	})

	t.Run("no-op when TrustedDeviceStore unwired", func(t *testing.T) {
		cs := newMemClientStore()
		rs := newMemRefreshStore()
		_ = rs.Issue(context.Background(), "rt1", &RefreshToken{UserID: "u", ClientID: "rp", ExpiresAt: time.Now().Add(time.Hour)})
		d := newRevokeDeps(cs, rs)
		d.validate = func(context.Context, string) (*core.TokenClaims, string, error) {
			return &core.TokenClaims{Subject: "u", ClientID: "rp", Audience: []string{"https://api.example.com"}}, "jwt", nil
		}
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		ctx.Request().Header.Set("Authorization", "Bearer good")
		HandleRevokeAll(d, ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (byte-identical without a store wired)", rec.Code)
		}
		body := decodeBody(t, rec)
		if body["trusted_devices_revoked"] != float64(0) {
			t.Errorf("trusted_devices_revoked = %v, want 0", body["trusted_devices_revoked"])
		}
	})
}
