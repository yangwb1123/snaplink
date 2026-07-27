package oauth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// cibaDeps is a thin test adapter wiring the real in-memory CIBAStore +
// ClientStore into the CIBADeps surface (production adapter: *sso.Server).
// resolveHint + deliver replicate the seams the Server implements over its
// own hint resolver + push transport.
type cibaDeps struct {
	clients     core.ClientStore
	store       CIBAStore
	ttl         time.Duration
	interval    time.Duration
	verifyCA    func(ctx context.Context, assertion, formClientID, asIssuer string) (string, error)
	resolveHint func(ctx context.Context, loginHint, idTokenHint, loginHintToken string) (string, string, error)
	deliver     func(ctx context.Context, authReqID, subjectID, bindingMessage string) error
}

func (d *cibaDeps) ClientStoreAccessor() core.ClientStore    { return d.clients }
func (d *cibaDeps) CIBAStore() CIBAStore                     { return d.store }
func (d *cibaDeps) CIBARequestTTL() time.Duration            { return d.ttl }
func (d *cibaDeps) CIBAPollInterval() time.Duration          { return d.interval }
func (d *cibaDeps) ResolveIssuer(core.HandlerContext) string { return "https://issuer.test" }
func (d *cibaDeps) VerifyJWTClientAssertion(ctx context.Context, a, f, i string) (string, error) {
	return d.verifyCA(ctx, a, f, i)
}
func (d *cibaDeps) SrvLogger() spi.Logger { return spi.NopLogger{} }
func (d *cibaDeps) ResolveCIBAHint(ctx context.Context, lh, ith, lht string) (string, string, error) {
	return d.resolveHint(ctx, lh, ith, lht)
}
func (d *cibaDeps) DeliverCIBAChallenge(ctx context.Context, id, sub, bm string) error {
	return d.deliver(ctx, id, sub, bm)
}
func (d *cibaDeps) RecordCIBAAuthRequest(core.HandlerContext, string, string, string) {}

var _ CIBADeps = (*cibaDeps)(nil)

func newCIBADeps(cs core.ClientStore, store CIBAStore) *cibaDeps {
	return &cibaDeps{
		clients: cs,
		store:   store,
		verifyCA: func(context.Context, string, string, string) (string, error) {
			return "", errTestInvalidClient
		},
		resolveHint: func(_ context.Context, lh, _, _ string) (string, string, error) {
			if lh == "known@user" {
				return "user-1", "password", nil
			}
			return "", "", nil // unresolved
		},
		deliver: func(context.Context, string, string, string) error { return nil },
	}
}

func TestHandleBackchannelAuth(t *testing.T) {
	t.Parallel()
	t.Run("no store 501", func(t *testing.T) {
		d := &cibaDeps{clients: newMemClientStore()}
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		HandleBackchannelAuth(d, ctx)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("status = %d, want 501", rec.Code)
		}
	})

	t.Run("nil client store 500", func(t *testing.T) {
		d := &cibaDeps{store: newMemCIBAStore()}
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{}`)
		HandleBackchannelAuth(d, ctx)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})

	t.Run("bad body 400", func(t *testing.T) {
		d := newCIBADeps(newMemClientStore(), newMemCIBAStore())
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{bad`)
		HandleBackchannelAuth(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("missing client_id 401", func(t *testing.T) {
		d := newCIBADeps(newMemClientStore(), newMemCIBAStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded, "login_hint=known@user")
		HandleBackchannelAuth(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrMissingClientID {
			t.Fatalf("error = %v, want %s", got, core.ErrMissingClientID)
		}
	})

	t.Run("unknown client invalid_client", func(t *testing.T) {
		d := newCIBADeps(newMemClientStore(), newMemCIBAStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=ghost&client_secret=x&login_hint=known@user")
		HandleBackchannelAuth(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("inactive client 403", func(t *testing.T) {
		cs := newMemClientStore()
		c := activeClient("rp")
		c.Active = false
		cs.put(c, "s")
		d := newCIBADeps(cs, newMemCIBAStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s&login_hint=known@user")
		HandleBackchannelAuth(d, ctx)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("bad secret invalid_client", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "right")
		d := newCIBADeps(cs, newMemCIBAStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=wrong&login_hint=known@user")
		HandleBackchannelAuth(d, ctx)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("disallowed resource invalid_target", func(t *testing.T) {
		cs := newMemClientStore()
		c := activeClient("rp")
		c.AllowedResources = []string{"https://api.test"}
		cs.put(c, "s")
		d := newCIBADeps(cs, newMemCIBAStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s&login_hint=known@user&resource=https://other.test")
		HandleBackchannelAuth(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrInvalidTarget {
			t.Fatalf("error = %v, want %s", got, core.ErrInvalidTarget)
		}
	})

	t.Run("missing hint unknown_user_id (anti-enumeration)", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newCIBADeps(cs, newMemCIBAStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s")
		HandleBackchannelAuth(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrUnknownUserID {
			t.Fatalf("error = %v, want %s", got, core.ErrUnknownUserID)
		}
	})

	t.Run("unresolvable hint unknown_user_id", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newCIBADeps(cs, newMemCIBAStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s&login_hint=ghost@user")
		HandleBackchannelAuth(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrUnknownUserID {
			t.Fatalf("error = %v, want %s", got, core.ErrUnknownUserID)
		}
	})

	t.Run("hint resolver error also unknown_user_id", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newCIBADeps(cs, newMemCIBAStore())
		d.resolveHint = func(context.Context, string, string, string) (string, string, error) {
			return "", "", errors.New("resolver down")
		}
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s&login_hint=known@user")
		HandleBackchannelAuth(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrUnknownUserID {
			t.Fatalf("error = %v, want %s", got, core.ErrUnknownUserID)
		}
	})

	t.Run("disallowed scope invalid_scope", func(t *testing.T) {
		cs := newMemClientStore()
		c := activeClient("rp")
		c.AllowedScopes = []string{"profile"}
		cs.put(c, "s")
		d := newCIBADeps(cs, newMemCIBAStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s&login_hint=known@user&scope=admin")
		HandleBackchannelAuth(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrInvalidScope {
			t.Fatalf("error = %v, want %s", got, core.ErrInvalidScope)
		}
	})

	t.Run("store issue error 500", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		store := newMemCIBAStore()
		store.issErr = errors.New("boom")
		d := newCIBADeps(cs, store)
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s&login_hint=known@user")
		HandleBackchannelAuth(d, ctx)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})

	t.Run("delivery failure 500 and request cleaned up", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		store := newMemCIBAStore()
		d := newCIBADeps(cs, store)
		d.deliver = func(context.Context, string, string, string) error {
			return errors.New("transport refused")
		}
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s&login_hint=known@user")
		HandleBackchannelAuth(d, ctx)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
		// the dangling pending request must have been deleted
		if len(store.entries) != 0 {
			t.Fatalf("expected store cleaned up, %d entries remain", len(store.entries))
		}
	})

	t.Run("success returns auth_req_id + interval + expires_in", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		store := newMemCIBAStore()
		d := newCIBADeps(cs, store)
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s&login_hint=known@user&binding_message=4821")
		HandleBackchannelAuth(d, ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		body := decodeBody(t, rec)
		id, _ := body["auth_req_id"].(string)
		if id == "" {
			t.Fatal("auth_req_id missing")
		}
		if body["expires_in"] != float64(int(DefaultCIBARequestTTL.Seconds())) {
			t.Errorf("expires_in = %v", body["expires_in"])
		}
		if body["interval"] != float64(int(DefaultCIBAPollInterval.Seconds())) {
			t.Errorf("interval = %v", body["interval"])
		}
		// the pending request was persisted with the resolved subject
		got, err := store.Get(context.Background(), id)
		if err != nil {
			t.Fatalf("get issued request: %v", err)
		}
		if got.SubjectID != "user-1" || got.Status != CIBAPending {
			t.Errorf("stored request = %+v", got)
		}
	})

	t.Run("client assertion wrong type 400", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newCIBADeps(cs, newMemCIBAStore())
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"login_hint=known@user&client_assertion=x&client_assertion_type=urn:wrong")
		HandleBackchannelAuth(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("client assertion success skips secret check", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "the-secret")
		d := newCIBADeps(cs, newMemCIBAStore())
		d.verifyCA = func(context.Context, string, string, string) (string, error) {
			return "rp", nil
		}
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"login_hint=known@user&client_assertion=good&client_assertion_type="+ClientAssertionTypeJWTBearer)
		HandleBackchannelAuth(d, ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("custom TTL and interval honored", func(t *testing.T) {
		cs := newMemClientStore()
		cs.put(activeClient("rp"), "s")
		d := newCIBADeps(cs, newMemCIBAStore())
		d.ttl = 30 * time.Second
		d.interval = 3 * time.Second
		ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
			"client_id=rp&client_secret=s&login_hint=known@user")
		HandleBackchannelAuth(d, ctx)
		body := decodeBody(t, rec)
		if body["expires_in"] != float64(30) {
			t.Errorf("expires_in = %v, want 30", body["expires_in"])
		}
		if body["interval"] != float64(3) {
			t.Errorf("interval = %v, want 3", body["interval"])
		}
	})
}
