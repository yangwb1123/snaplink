package selfserviceaccount

import (
	"net/http"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystorecredential"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
)

// trustedDeviceTestDeps augments testDeps with a real, wired
// memorystorecredential.MemoryTrustedDeviceStore. testhelpers_test.go's
// TrustedDeviceStore()/TrustedDeviceTTL() are hardcoded stubs (nil store, 0
// TTL) because no other test file in this package needed one before this
// file — embedding *testDeps and overriding just those two accessors keeps
// that shared harness untouched for every other _test.go in the package.
type trustedDeviceTestDeps struct {
	*testDeps
	store core.TrustedDeviceStore
	ttl   time.Duration
}

// newTrustedDeviceTestDeps defaults the caller to a session that has
// already completed MFA for client-a (amr contains "mfa") — the precondition
// HandleTrustMyDevice enforces (trusted_devices.go's load-bearing "steal a
// live session, silently upgrade to a standing MFA bypass" guard) — so most
// tests can call HandleTrustMyDevice directly as a seeding step without
// re-stating claims.
func newTrustedDeviceTestDeps() *trustedDeviceTestDeps {
	d := &trustedDeviceTestDeps{
		testDeps: newTestDeps(),
		store:    memorystorecredential.NewMemoryTrustedDeviceStore(),
	}
	d.authClaims = &core.TokenClaims{Subject: "user-1", ClientID: "client-a", AMR: []string{"pwd", "mfa"}}
	return d
}

func (d *trustedDeviceTestDeps) TrustedDeviceStore() core.TrustedDeviceStore { return d.store }
func (d *trustedDeviceTestDeps) TrustedDeviceTTL() time.Duration             { return d.ttl }

var _ Deps = (*trustedDeviceTestDeps)(nil)

func TestHandleTrustMyDevice(t *testing.T) {
	t.Parallel()

	t.Run("happy path mints a token and lists it back", func(t *testing.T) {
		t.Parallel()
		d := newTrustedDeviceTestDeps()
		sink := audit.NewMemorySink(10)
		d.auditor = audit.New(sink)

		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"label":"Chrome on macOS"}`)
		HandleTrustMyDevice(d, ctx)

		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
		}
		resp := decodeBody(t, rec)
		token, _ := resp["device_token"].(string)
		if token == "" {
			t.Fatal("device_token missing from response")
		}
		deviceID, _ := resp["device_id"].(string)
		if deviceID == "" {
			t.Fatal("device_id missing from response")
		}
		if resp["label"] != "Chrome on macOS" {
			t.Errorf("label = %v, want %q", resp["label"], "Chrome on macOS")
		}

		devices, err := d.store.ListByUser(t.Context(), "user-1")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(devices) != 1 || devices[0].ClientID != "client-a" {
			t.Fatalf("ListByUser = %+v, want a single client-a device", devices)
		}

		events, err := sink.Query(t.Context(), audit.Query{})
		if err != nil {
			t.Fatalf("query sink: %v", err)
		}
		if len(events) != 1 || events[0].Type != audit.EventDeviceTrusted {
			t.Fatalf("audit events = %+v, want one EventDeviceTrusted", events)
		}
		if events[0].Metadata["device_id"] != deviceID {
			t.Errorf("audit device_id = %q, want %q", events[0].Metadata["device_id"], deviceID)
		}
	})

	t.Run("missing mfa in amr -> 403 insufficient_user_authentication, no grant minted", func(t *testing.T) {
		t.Parallel()
		d := newTrustedDeviceTestDeps()
		d.authClaims = &core.TokenClaims{Subject: "user-1", ClientID: "client-a", AMR: []string{"pwd"}}

		ctx, rec := newCtx(http.MethodPost, "", "")
		HandleTrustMyDevice(d, ctx)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		resp := decodeBody(t, rec)
		if resp[core.KeyError] != security.ErrInsufficientUserAuthentication {
			t.Errorf("error = %v, want %s", resp[core.KeyError], security.ErrInsufficientUserAuthentication)
		}
		devices, _ := d.store.ListByUser(t.Context(), "user-1")
		if len(devices) != 0 {
			t.Error("a bearer token without a live mfa step-up must never mint a trust grant")
		}
	})

	t.Run("residency write gate denies -> 403, no grant minted", func(t *testing.T) {
		t.Parallel()
		d := newTrustedDeviceTestDeps()
		d.residencyWriteDeny = "region_not_allowed"

		ctx, rec := newCtx(http.MethodPost, "", "")
		HandleTrustMyDevice(d, ctx)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		devices, _ := d.store.ListByUser(t.Context(), "user-1")
		if len(devices) != 0 {
			t.Error("a residency-denied request must not mint a grant")
		}
	})

	t.Run("no store configured -> 404", func(t *testing.T) {
		t.Parallel()
		d := newTestDeps() // shared harness: TrustedDeviceStore() returns nil
		d.authClaims = &core.TokenClaims{Subject: "user-1", ClientID: "client-a", AMR: []string{"mfa"}}

		ctx, rec := newCtx(http.MethodPost, "", "")
		HandleTrustMyDevice(d, ctx)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestTrustedDevice_AllowsMFASkipOnSubsequentLogin proves a handler-minted
// grant satisfies the exact call the login path makes to decide whether to
// skip the risk-scorer's MFA step-up: interfaces/sso's
// trustedDeviceAllowsSkip (server_login_client.go) calls precisely
// TrustedDeviceStore.Verify(ctx, userID, clientID, token) and treats true as
// "skip the challenge". That function lives in interfaces/sso, which this
// package cannot import without an interfaces/sso -> protocols/selfservice
// -> selfserviceaccount cycle (the same constraint testhelpers_test.go's
// package doc documents for the MFA store), so this test drives the real
// Verify call instead of re-implementing the login handler.
func TestTrustedDevice_AllowsMFASkipOnSubsequentLogin(t *testing.T) {
	t.Parallel()
	d := newTrustedDeviceTestDeps()

	ctx, rec := newCtx(http.MethodPost, "", "")
	HandleTrustMyDevice(d, ctx)
	if rec.Code != http.StatusCreated {
		t.Fatalf("trust: status = %d, want 201", rec.Code)
	}
	token, _ := decodeBody(t, rec)["device_token"].(string)
	if token == "" {
		t.Fatal("no device_token minted")
	}

	ok, err := d.store.Verify(t.Context(), "user-1", "client-a", token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("a freshly trusted device must verify true — the login path would wrongly re-demand MFA")
	}
}

// TestTrustedDevice_ExpiredGrantFallsBackToMFA proves the expiry half of
// core.TrustedDeviceStore.Verify's documented contract ("Verify reports
// whether token is a live, UNEXPIRED grant") actually holds for a token
// minted through the handler this file exposes, not just the store in
// isolation (infrastructure/defaultimpl/memorystorecredential/
// trusted_device_test.go already covers the store directly).
func TestTrustedDevice_ExpiredGrantFallsBackToMFA(t *testing.T) {
	t.Parallel()
	d := newTrustedDeviceTestDeps()
	d.ttl = time.Millisecond // TrustedDeviceTTL() feeds straight into store.Trust's ttl arg

	ctx, rec := newCtx(http.MethodPost, "", "")
	HandleTrustMyDevice(d, ctx)
	if rec.Code != http.StatusCreated {
		t.Fatalf("trust: status = %d, want 201", rec.Code)
	}
	token, _ := decodeBody(t, rec)["device_token"].(string)
	if token == "" {
		t.Fatal("no device_token minted")
	}

	time.Sleep(5 * time.Millisecond)

	ok, err := d.store.Verify(t.Context(), "user-1", "client-a", token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("an expired grant must not verify — the login path must fall back to requiring MFA again")
	}
}

// TestTrustedDevice_CrossUserAndCrossClientIsolation covers
// core.TrustedDeviceStore's documented scoping: a grant is good for EXACTLY
// (userID, clientID) — never a different user, and never a different OAuth
// client. There is no separate "session id" dimension in the store's
// contract (see shared/core/recovery_code.go's TrustedDeviceStore doc
// comment), so cross-client is the scoping boundary that stands in for
// "cross-session" here — trusting a device while signed into one
// application must not silently cover a login to a different one.
func TestTrustedDevice_CrossUserAndCrossClientIsolation(t *testing.T) {
	t.Parallel()

	t.Run("token does not verify for a different user", func(t *testing.T) {
		t.Parallel()
		d := newTrustedDeviceTestDeps() // subject "user-1"
		ctx, rec := newCtx(http.MethodPost, "", "")
		HandleTrustMyDevice(d, ctx)
		token, _ := decodeBody(t, rec)["device_token"].(string)

		if ok, _ := d.store.Verify(t.Context(), "mallory", "client-a", token); ok {
			t.Fatal("user-1's trusted-device token verified for a different user")
		}
		// Still valid for its actual owner.
		if ok, _ := d.store.Verify(t.Context(), "user-1", "client-a", token); !ok {
			t.Fatal("regression: same-user verify should still succeed")
		}
	})

	t.Run("token does not verify for a different client", func(t *testing.T) {
		t.Parallel()
		d := newTrustedDeviceTestDeps() // claims.ClientID == "client-a"
		ctx, rec := newCtx(http.MethodPost, "", "")
		HandleTrustMyDevice(d, ctx)
		token, _ := decodeBody(t, rec)["device_token"].(string)

		if ok, _ := d.store.Verify(t.Context(), "user-1", "client-b", token); ok {
			t.Fatal("a device trusted for client-a verified for an unrelated client-b login")
		}
		// Still valid for the client it was actually minted under.
		if ok, _ := d.store.Verify(t.Context(), "user-1", "client-a", token); !ok {
			t.Fatal("regression: same-client verify should still succeed")
		}
	})

	t.Run("self-service device list never surfaces another user's grant", func(t *testing.T) {
		t.Parallel()
		d := newTrustedDeviceTestDeps()
		if _, _, err := d.store.Trust(t.Context(), "user-1", "client-a", "", time.Hour); err != nil {
			t.Fatalf("seed user-1: %v", err)
		}
		if _, _, err := d.store.Trust(t.Context(), "mallory", "client-a", "", time.Hour); err != nil {
			t.Fatalf("seed mallory: %v", err)
		}

		d.authSubject = "mallory"
		ctx, rec := newCtx(http.MethodGet, "", "")
		HandleMyTrustedDevices(d, ctx)

		resp := decodeBody(t, rec)
		devices, _ := resp["devices"].([]any)
		if len(devices) != 1 {
			t.Fatalf("mallory's device list returned %d devices, want 1 (must not include user-1's)", len(devices))
		}
	})
}

func TestHandleMyTrustedDevices(t *testing.T) {
	t.Parallel()

	t.Run("no devices yet -> empty array, not null", func(t *testing.T) {
		t.Parallel()
		d := newTrustedDeviceTestDeps()
		ctx, rec := newCtx(http.MethodGet, "", "")
		HandleMyTrustedDevices(d, ctx)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		resp := decodeBody(t, rec)
		devices, ok := resp["devices"].([]any)
		if !ok {
			t.Fatalf("devices field missing or wrong type: %+v", resp)
		}
		if len(devices) != 0 {
			t.Errorf("got %d devices, want 0", len(devices))
		}
	})

	t.Run("no store configured -> 404", func(t *testing.T) {
		t.Parallel()
		d := newTestDeps()
		ctx, rec := newCtx(http.MethodGet, "", "")
		HandleMyTrustedDevices(d, ctx)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestHandleRevokeMyTrustedDevice(t *testing.T) {
	t.Parallel()

	t.Run("owner revoke succeeds, kills the grant, and audits", func(t *testing.T) {
		t.Parallel()
		d := newTrustedDeviceTestDeps()
		sink := audit.NewMemorySink(10)
		d.auditor = audit.New(sink)
		token, dev, err := d.store.Trust(t.Context(), "user-1", "client-a", "", time.Hour)
		if err != nil {
			t.Fatalf("seed trust: %v", err)
		}

		rec := servePath(http.MethodDelete, "/me/trusted-devices/:id", "/me/trusted-devices/"+dev.ID, "",
			func(ctx core.HandlerContext) { HandleRevokeMyTrustedDevice(d, ctx) })
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
		if ok, _ := d.store.Verify(t.Context(), "user-1", "client-a", token); ok {
			t.Error("device still verifies after revoke")
		}

		events, err := sink.Query(t.Context(), audit.Query{})
		if err != nil {
			t.Fatalf("query sink: %v", err)
		}
		if len(events) != 1 || events[0].Type != audit.EventDeviceTrustRevoked {
			t.Fatalf("audit events = %+v, want one EventDeviceTrustRevoked", events)
		}
	})

	t.Run("missing id -> 400", func(t *testing.T) {
		t.Parallel()
		d := newTrustedDeviceTestDeps()
		ctx, rec := newCtx(http.MethodDelete, "", "") // built directly, no router match -> Param("id") == ""
		HandleRevokeMyTrustedDevice(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("unknown id -> 404", func(t *testing.T) {
		t.Parallel()
		d := newTrustedDeviceTestDeps()
		rec := servePath(http.MethodDelete, "/me/trusted-devices/:id", "/me/trusted-devices/ghost", "",
			func(ctx core.HandlerContext) { HandleRevokeMyTrustedDevice(d, ctx) })
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("other user's device -> 404, device survives (oracle-safe)", func(t *testing.T) {
		t.Parallel()
		d := newTrustedDeviceTestDeps() // authSubject defaults to "user-1"
		token, dev, err := d.store.Trust(t.Context(), "mallory", "client-a", "", time.Hour)
		if err != nil {
			t.Fatalf("seed trust: %v", err)
		}

		rec := servePath(http.MethodDelete, "/me/trusted-devices/:id", "/me/trusted-devices/"+dev.ID, "",
			func(ctx core.HandlerContext) { HandleRevokeMyTrustedDevice(d, ctx) })
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
		if ok, _ := d.store.Verify(t.Context(), "mallory", "client-a", token); !ok {
			t.Fatal("cross-user revoke attempt must not remove another user's grant")
		}
	})

	t.Run("no store configured -> 404", func(t *testing.T) {
		t.Parallel()
		d := newTestDeps()
		rec := servePath(http.MethodDelete, "/me/trusted-devices/:id", "/me/trusted-devices/x", "",
			func(ctx core.HandlerContext) { HandleRevokeMyTrustedDevice(d, ctx) })
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}
