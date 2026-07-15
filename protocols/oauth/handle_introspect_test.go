package oauth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/tokenusage"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
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
	clients       core.ClientStore
	refresh       RefreshTokenStore
	issuers       map[string]core.TokenIssuer
	validate      func(ctx context.Context, token string) (*core.TokenClaims, string, error)
	verifyCA      func(ctx context.Context, assertion, formClientID, asIssuer string) (string, error)
	usageRecorder *tokenusage.Recorder
	// renewExceeded stands in for the token-policy require_renew seam. Nil =
	// default-off (never exceeded), so an unset hook keeps introspection
	// byte-identical to a build without a wired policy.
	renewExceeded func(ctx context.Context, clientID string, scopes []string, issuedAt, expiresAt time.Time) bool
	// signer / batchMaxSize stand in for WithIntrospectionSigner /
	// WithIntrospectionBatch. Zero values (nil / 0) reproduce the default-off
	// byte-identical behavior every other test in this file relies on.
	signer       IntrospectionSigner
	batchMaxSize int
	// sessionMgr stands in for the session-liveness gate. Nil (the zero
	// value every other test in this file relies on) reproduces the
	// default-off, byte-identical behavior of an unwired SessionManager.
	sessionMgr core.SessionManager
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

func (d *introspectDeps) IntrospectionCache() IntrospectionCache   { return nil }
func (d *introspectDeps) IntrospectionCacheTTL() time.Duration     { return 0 }
func (d *introspectDeps) TokenUsageRecorder() *tokenusage.Recorder { return d.usageRecorder }
func (d *introspectDeps) IntrospectionRenewExceeded(ctx context.Context, clientID string, scopes []string, issuedAt, expiresAt time.Time) bool {
	if d.renewExceeded == nil {
		return false
	}
	return d.renewExceeded(ctx, clientID, scopes, issuedAt, expiresAt)
}

func (d *introspectDeps) IntrospectionSigner() IntrospectionSigner { return d.signer }
func (d *introspectDeps) IntrospectionBatchMaxSize() int           { return d.batchMaxSize }
func (d *introspectDeps) SessionManager() core.SessionManager      { return d.sessionMgr }

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
	t.Parallel()
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

// fakeIntrospectionSigner is a real, non-cryptographic IntrospectionSigner
// stand-in — it never touches key material, only records/replays claims, so
// tests exercise the HandleIntrospect wiring without pulling in defaultimpl
// (which imports oauth; a reverse import would cycle).
type fakeIntrospectionSigner struct {
	err        error
	lastClaims map[string]any
}

func (f *fakeIntrospectionSigner) SignIntrospectionJWT(_ context.Context, claims map[string]any) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.lastClaims = claims
	return "fake.jwt.token", nil
}

var _ IntrospectionSigner = (*fakeIntrospectionSigner)(nil)

// TestHandleIntrospect_SessionLiveness covers introspectSessionActive: a
// token whose claims carry a sid must reflect the underlying session's
// liveness (active/expired/revoked), a store error must fail CLOSED
// (oracle-safe, matching MeshAuthorize's meshCheckSession), and a nil sid or
// an unwired SessionManager must skip the check entirely (byte-identical to
// before this gate existed).
func TestHandleIntrospect_SessionLiveness(t *testing.T) {
	t.Parallel()

	validatingClaims := func(sid string) func(context.Context, string) (*core.TokenClaims, string, error) {
		return func(context.Context, string) (*core.TokenClaims, string, error) {
			return &core.TokenClaims{
				Subject:   "user-1",
				ClientID:  "rp",
				SID:       sid,
				ExpiresAt: time.Now().Add(time.Hour),
			}, "jwt", nil
		}
	}

	t.Run("live session reports active", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		sm := newMemSessionManager()
		sess, err := sm.Create(context.Background(), "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		d := newIntrospectDeps(cs, newMemRefreshStore())
		d.sessionMgr = sm
		d.validate = validatingClaims(sess.ID)
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, "token=valid&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		if got := decodeBody(t, rec)["active"]; got != true {
			t.Fatalf("active = %v, want true (live session)", got)
		}
	})

	t.Run("destroyed session reports inactive", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		sm := newMemSessionManager()
		sess, _ := sm.Create(context.Background(), "user-1")
		_ = sm.Destroy(context.Background(), sess.ID)
		d := newIntrospectDeps(cs, newMemRefreshStore())
		d.sessionMgr = sm
		d.validate = validatingClaims(sess.ID)
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, "token=valid&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		if got := decodeBody(t, rec)["active"]; got != false {
			t.Fatalf("active = %v, want false (destroyed session)", got)
		}
	})

	t.Run("revoked session reports inactive", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		sm := newMemSessionManager()
		sess, _ := sm.Create(context.Background(), "user-1")
		sm.revoke(sess.ID)
		d := newIntrospectDeps(cs, newMemRefreshStore())
		d.sessionMgr = sm
		d.validate = validatingClaims(sess.ID)
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, "token=valid&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		if got := decodeBody(t, rec)["active"]; got != false {
			t.Fatalf("active = %v, want false (revoked session)", got)
		}
	})

	t.Run("session store error fails closed", func(t *testing.T) {
		// Oracle-safe collapse, matching MeshAuthorize's meshCheckSession:
		// a store error is indistinguishable from "session gone" here
		// because every built-in Get() already collapses not-found/
		// revoked/expired into the same error, so there is no reliable way
		// to tell a genuine outage apart from a legitimately dead session.
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newIntrospectDeps(cs, newMemRefreshStore())
		d.sessionMgr = &erroringSessionManager{}
		d.validate = validatingClaims("some-sid")
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, "token=valid&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		if got := decodeBody(t, rec)["active"]; got != false {
			t.Fatalf("active = %v, want false (store error collapses to inactive)", got)
		}
	})

	t.Run("no sid claim skips the check even when wired", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		sm := newMemSessionManager()
		d := newIntrospectDeps(cs, newMemRefreshStore())
		d.sessionMgr = sm
		d.validate = validatingClaims("") // no sid
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, "token=valid&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		if got := decodeBody(t, rec)["active"]; got != true {
			t.Fatalf("active = %v, want true (no sid, nothing to check)", got)
		}
	})
}

// erroringSessionManager.Get always errors, to prove introspectSessionActive
// fails open (treats a transient store outage as "still active" rather than
// silently revoking every live token).
type erroringSessionManager struct{ memSessionManager }

func (e *erroringSessionManager) Get(context.Context, string) (*core.Session, error) {
	return nil, errors.New("oauth_test: session store unavailable")
}

var _ core.SessionManager = (*erroringSessionManager)(nil)

// TestHandleIntrospect_RFC9701JWTResponse covers the opt-in JWT-response
// content-negotiation surface: default-off, per-request Accept-header
// opt-in, graceful degrade when unwired, and fail-closed on a signing error.
func TestHandleIntrospect_RFC9701JWTResponse(t *testing.T) {
	t.Parallel()

	newActiveDeps := func(signer IntrospectionSigner) *introspectDeps {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newIntrospectDeps(cs, newMemRefreshStore())
		d.signer = signer
		d.validate = func(context.Context, string) (*core.TokenClaims, string, error) {
			return &core.TokenClaims{Subject: "u", ClientID: "rp"}, "jwt", nil
		}
		return d
	}

	t.Run("no signer wired: Accept header ignored, stays JSON", func(t *testing.T) {
		d := newActiveDeps(nil)
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, "token=valid&client_id=rp&client_secret=s")
		ctx.Request().Header.Set("Accept", core.ContentTypeTokenIntrospectionJWT)
		HandleIntrospect(d, ctx)
		if ct := rec.Header().Get(core.HeaderContentType); ct != core.ContentTypeJSON {
			t.Fatalf("Content-Type = %q, want %q (feature off by default)", ct, core.ContentTypeJSON)
		}
	})

	t.Run("signer wired but no Accept header: stays JSON", func(t *testing.T) {
		signer := &fakeIntrospectionSigner{}
		d := newActiveDeps(signer)
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, "token=valid&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		if ct := rec.Header().Get(core.HeaderContentType); ct != core.ContentTypeJSON {
			t.Fatalf("Content-Type = %q, want %q (no opt-in signal)", ct, core.ContentTypeJSON)
		}
		if signer.lastClaims != nil {
			t.Error("signer must not be invoked without the Accept opt-in")
		}
	})

	t.Run("signer wired + Accept header: signed JWT response", func(t *testing.T) {
		signer := &fakeIntrospectionSigner{}
		d := newActiveDeps(signer)
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, "token=valid&client_id=rp&client_secret=s")
		ctx.Request().Header.Set("Accept", core.ContentTypeTokenIntrospectionJWT)
		HandleIntrospect(d, ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if ct := rec.Header().Get(core.HeaderContentType); ct != core.ContentTypeTokenIntrospectionJWT {
			t.Fatalf("Content-Type = %q, want %q", ct, core.ContentTypeTokenIntrospectionJWT)
		}
		if got := rec.Body.String(); got != "fake.jwt.token" {
			t.Fatalf("body = %q, want the raw signed JWT (not JSON-wrapped)", got)
		}
		nested, ok := signer.lastClaims[core.KeyTokenIntrospection].(map[string]any)
		if !ok {
			t.Fatalf("no nested %s claim: %v", core.KeyTokenIntrospection, signer.lastClaims)
		}
		if nested[core.KeyActive] != true {
			t.Errorf("nested active = %v, want true", nested[core.KeyActive])
		}
		if _, present := signer.lastClaims[core.KeySub]; present {
			t.Error("top-level sub MUST NOT be set (RFC 9701 §8 substitution-attack defense)")
		}
		if _, present := signer.lastClaims[core.KeyExp]; present {
			t.Error("top-level exp MUST NOT be set (RFC 9701 §8 substitution-attack defense)")
		}
		if signer.lastClaims[core.KeyAud] != "rp" {
			t.Errorf("aud = %v, want the introspecting client id", signer.lastClaims[core.KeyAud])
		}
	})

	t.Run("signing failure fails closed with 500", func(t *testing.T) {
		signer := &fakeIntrospectionSigner{err: errors.New("kms unreachable")}
		d := newActiveDeps(signer)
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, "token=valid&client_id=rp&client_secret=s")
		ctx.Request().Header.Set("Accept", core.ContentTypeTokenIntrospectionJWT)
		HandleIntrospect(d, ctx)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 (never silently downgrade to JSON on signing failure)", rec.Code)
		}
	})

	t.Run("inactive token is also wrapped when requested", func(t *testing.T) {
		signer := &fakeIntrospectionSigner{}
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newIntrospectDeps(cs, newMemRefreshStore())
		d.signer = signer
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, "token=nope&client_id=rp&client_secret=s")
		ctx.Request().Header.Set("Accept", core.ContentTypeTokenIntrospectionJWT)
		HandleIntrospect(d, ctx)
		if ct := rec.Header().Get(core.HeaderContentType); ct != core.ContentTypeTokenIntrospectionJWT {
			t.Fatalf("Content-Type = %q, want %q even for an inactive token", ct, core.ContentTypeTokenIntrospectionJWT)
		}
		nested := signer.lastClaims[core.KeyTokenIntrospection].(map[string]any)
		if nested[core.KeyActive] != false {
			t.Errorf("nested active = %v, want false", nested[core.KeyActive])
		}
	})
}

// TestIntrospectionEmitsCnf is the RFC 7662 §2.2 regression guard: introspection
// MUST echo the sender-constraint confirmation so a resource server can enforce
// RFC 8705 §3.3 (mTLS) / RFC 9449 §7 (DPoP) binding. Previously omitted entirely.
// TestHandleIntrospect_RequireRenew proves the token-policy require_renew seam:
// default-off (nil hook) an active token introspects ACTIVE, byte-identical; a
// token past its renew threshold is reported {active:false} (the oracle-safe
// RFC 7662 §2.2 governance signal, not a metadata leak); and a token within its
// threshold stays active (governance is not a blanket deny). It also asserts the
// owning client_id reaches the seam so a per-client require_renew rule can select.
func TestHandleIntrospect_RequireRenew(t *testing.T) {
	t.Parallel()
	now := time.Now()
	claims := func() (*core.TokenClaims, string, error) {
		return &core.TokenClaims{
			Subject: "user-1", Issuer: "https://issuer.test", ClientID: "rp",
			Scopes: []string{"openid"}, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
		}, "jwt", nil
	}
	newDeps := func() *introspectDeps {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newIntrospectDeps(cs, newMemRefreshStore())
		d.validate = func(context.Context, string) (*core.TokenClaims, string, error) { return claims() }
		return d
	}

	t.Run("default-off reports active (byte-identical)", func(t *testing.T) {
		d := newDeps() // renewExceeded hook left nil
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, "token=valid&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		if got := decodeBody(t, rec)["active"]; got != true {
			t.Fatalf("active = %v, want true (no policy wired)", got)
		}
	})

	t.Run("past renew threshold reports inactive", func(t *testing.T) {
		d := newDeps()
		var sawClient string
		d.renewExceeded = func(_ context.Context, clientID string, _ []string, _, _ time.Time) bool {
			sawClient = clientID
			return true
		}
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, "token=valid&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		body := decodeBody(t, rec)
		if body["active"] != false {
			t.Fatalf("active = %v, want false (past renew threshold)", body["active"])
		}
		// §2.2: an inactive response carries active only, no metadata leak.
		if len(body) != 1 {
			t.Fatalf("inactive body leaked metadata: %v", body)
		}
		if sawClient != "rp" {
			t.Fatalf("seam saw client_id %q, want rp", sawClient)
		}
	})

	t.Run("within renew threshold stays active", func(t *testing.T) {
		d := newDeps()
		d.renewExceeded = func(context.Context, string, []string, time.Time, time.Time) bool { return false }
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, "token=valid&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		if got := decodeBody(t, rec)["active"]; got != true {
			t.Fatalf("active = %v, want true (within threshold)", got)
		}
	})
}

func TestIntrospectionEmitsCnf(t *testing.T) {
	t.Parallel()
	// mTLS-bound token -> cnf.x5t#S256.
	body := map[string]any{}
	populateAccessIntrospectionBody(body, &core.TokenClaims{Subject: "u", ConfirmationX5TS256: "thumb-abc"})
	cnf, ok := body[core.KeyCnf].(map[string]any)
	if !ok {
		t.Fatalf("no cnf in introspection body for an mTLS-bound token: %v", body[core.KeyCnf])
	}
	if cnf[core.KeyCnfX5TS256] != "thumb-abc" {
		t.Errorf("cnf x5t#S256 = %v, want thumb-abc", cnf[core.KeyCnfX5TS256])
	}

	// DPoP-bound token -> cnf.jkt.
	body = map[string]any{}
	populateAccessIntrospectionBody(body, &core.TokenClaims{Subject: "u", ConfirmationJKT: "jkt-xyz"})
	cnf, ok = body[core.KeyCnf].(map[string]any)
	if !ok {
		t.Fatalf("no cnf for a DPoP-bound token: %v", body[core.KeyCnf])
	}
	if cnf[core.KeyCnfJKT] != "jkt-xyz" {
		t.Errorf("cnf jkt = %v, want jkt-xyz", cnf[core.KeyCnfJKT])
	}

	// Unbound bearer token -> NO cnf member.
	body = map[string]any{}
	populateAccessIntrospectionBody(body, &core.TokenClaims{Subject: "u"})
	if _, present := body[core.KeyCnf]; present {
		t.Errorf("cnf emitted for an unbound token: %v", body[core.KeyCnf])
	}
}

// TestIntrospectionTokenTypeReflectsDPoPBinding is the RFC 9449 §7 regression
// guard: a DPoP-bound token (cnf.jkt present) MUST introspect with
// token_type=DPoP, not Bearer — mirroring the /token endpoint's
// DPoPTokenTypeOr behavior (interfaces/sso/server_dpop.go). A resource
// server that trusts introspection's token_type to decide whether to demand
// a DPoP proof would otherwise treat a sender-constrained token as a plain
// bearer credential, defeating the entire point of the binding.
func TestIntrospectionTokenTypeReflectsDPoPBinding(t *testing.T) {
	t.Parallel()

	t.Run("access token", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newIntrospectDeps(cs, newMemRefreshStore())
		d.validate = func(context.Context, string) (*core.TokenClaims, string, error) {
			return &core.TokenClaims{Subject: "u", ClientID: "rp", ConfirmationJKT: "jkt-abc"}, "jwt", nil
		}
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=valid&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		body := decodeBody(t, rec)
		if got := body[core.KeyTokenType]; got != core.TokenTypeNameDPoP {
			t.Fatalf("token_type = %v, want %s for a DPoP-bound access token", got, core.TokenTypeNameDPoP)
		}
	})

	t.Run("access token without binding stays Bearer", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newIntrospectDeps(cs, newMemRefreshStore())
		d.validate = func(context.Context, string) (*core.TokenClaims, string, error) {
			return &core.TokenClaims{Subject: "u", ClientID: "rp"}, "jwt", nil
		}
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=valid&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		body := decodeBody(t, rec)
		if got := body[core.KeyTokenType]; got != core.TokenTypeBearer {
			t.Fatalf("token_type = %v, want %s for an unbound access token", got, core.TokenTypeBearer)
		}
	})

	t.Run("refresh token", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		rs := newMemRefreshStore()
		now := time.Now()
		_ = rs.Issue(context.Background(), "rtok", &RefreshToken{
			UserID: "user-9", ClientID: "rp", Scopes: []string{"offline_access"},
			IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour),
			ConfirmationJKT: "jkt-xyz",
		})
		d := newIntrospectDeps(cs, rs)
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"token=rtok&token_type_hint=refresh_token&client_id=rp&client_secret=s")
		HandleIntrospect(d, ctx)
		body := decodeBody(t, rec)
		if got := body[core.KeyTokenType]; got != core.TokenTypeNameDPoP {
			t.Fatalf("token_type = %v, want %s for a DPoP-bound refresh token", got, core.TokenTypeNameDPoP)
		}
	})
}
