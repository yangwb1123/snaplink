package sso_test

// feature_gate_hotreload_test.go covers Server.SetAdminAPIGateEnabled /
// Server.SetWebSPAGateEnabled — interfaces/sso's half of the
// feature_gates.admin_api / feature_gates.web_spa SIGHUP hot-reload
// (config/reload's SetAdminAPIGateHook / SetWebSPAGateHook wire a real
// reload to these two methods on a cmd/sso-server process; here we drive
// them directly, mirroring rate_limit_hotreload_test.go's shape). The whole
// point of this feature is the oracle-safety of the OFF path, so these
// tests assert byte-identical responses (status + header + body), not just
// a status code.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/tenant/memory"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/caep"
	"github.com/yangwb1123/snaplink/shared/security"
)

// fghrResponse snapshots everything a byte-identical comparison needs from
// one request.
type fghrResponse struct {
	status int
	header http.Header
	body   string
}

func fghrGet(h http.Handler, path string) fghrResponse {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return fghrResponse{status: rec.Code, header: rec.Header().Clone(), body: rec.Body.String()}
}

// fghrAssertIdentical fails unless got and want are byte-identical on every
// axis a client can observe — status, body, and every header want set (a
// stray EXTRA header on got would still be a leak, so this checks both
// directions of the header set, not just a same-value subset).
func fghrAssertIdentical(t *testing.T, got, want fghrResponse, label string) {
	t.Helper()
	if got.status != want.status {
		t.Errorf("%s: status = %d, want %d (byte-identical to a never-mounted path)", label, got.status, want.status)
	}
	if got.body != want.body {
		t.Errorf("%s: body = %q, want %q", label, got.body, want.body)
	}
	if len(got.header) != len(want.header) {
		t.Errorf("%s: header set = %v, want %v", label, got.header, want.header)
	}
	for k, wantV := range want.header {
		if gotV := got.header[k]; !equalStringSlices(gotV, wantV) {
			t.Errorf("%s: header %q = %v, want %v", label, k, gotV, wantV)
		}
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// fghrNeverMountedBaseline is a path guaranteed to match nothing this
// package's tests ever register — a plain 1-segment path never matches any
// /api/v1/... or /admin/... etc. route or SPA prefix, so it always falls
// through to the router's native http.NotFound, on every server built here.
const fghrNeverMountedBaseline = "/definitely-not-a-real-route"

// TestSetAdminAPIGateEnabled_LiveToggleIsByteIdenticalTo404 proves scenario
// (a): with admin_api ON at boot the admin surface is reachable; flipping
// the LIVE gate off makes the SAME path answer byte-identically to a path
// that was never mounted, and flipping it back on restores reachability —
// both directions work because mountAdminSurface always registers the
// group now (see that function's doc), it never "wasn't built at all".
func TestSetAdminAPIGateEnabled_LiveToggleIsByteIdenticalTo404(t *testing.T) {
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithFeatureGates(sso.FeatureGates{AdminAPI: sso.Bool(true)}),
	)
	h := srv.Handler()

	if resp := fghrGet(h, "/api/v1/admin/endpoints"); resp.status == http.StatusNotFound {
		t.Fatalf("GET /api/v1/admin/endpoints with admin_api on = 404, want the route reachable")
	}
	baseline := fghrGet(h, fghrNeverMountedBaseline)

	if !srv.SetAdminAPIGateEnabled(false) {
		t.Fatal("SetAdminAPIGateEnabled(false) = false, want true (the admin group is always mounted)")
	}
	fghrAssertIdentical(t, fghrGet(h, "/api/v1/admin/endpoints"), baseline, "admin_api live-disabled")

	if !srv.SetAdminAPIGateEnabled(true) {
		t.Fatal("SetAdminAPIGateEnabled(true) = false, want true")
	}
	if resp := fghrGet(h, "/api/v1/admin/endpoints"); resp.status == http.StatusNotFound {
		t.Fatalf("GET /api/v1/admin/endpoints after live re-enable = 404, want reachable again")
	}
}

// TestSetWebSPAGateEnabled_NoTenantStore_ReturnsFalseGracefully proves the
// one real asymmetry: sso-server serves no static frontend of its own (see
// buildProbeMux) — mountBrandingEndpoint (server_me.go) is the ONLY route
// left gated by web_spa, and it requires a tenant store. With none wired,
// there is nothing mounted for the gate to affect, so SetWebSPAGateEnabled
// must report that (false), not silently no-op while looking like it
// succeeded — that distinction is what lets config/reload surface it as
// Result.Ignored instead of a false Result.Applied.
func TestSetWebSPAGateEnabled_NoTenantStore_ReturnsFalseGracefully(t *testing.T) {
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		// No tenant store at all — mirrors a deployment without multi-tenancy.
	)
	_ = srv.Handler()

	if srv.SetWebSPAGateEnabled(false) {
		t.Fatal("SetWebSPAGateEnabled(false) = true, want false (no tenant store was ever wired)")
	}
	if srv.SetWebSPAGateEnabled(true) {
		t.Fatal("SetWebSPAGateEnabled(true) = true, want false (still nothing wired to affect)")
	}
}

// TestSetAdminAPIGateEnabled_AlwaysReportsApplied_EvenWithoutAdminAPIStores
// proves admin_api has NO analogous "nothing wired" gap: the client-lookup
// + endpoint-inventory routes mountAdminSurface always registers are enough
// on their own, with zero optional admin stores configured.
func TestSetAdminAPIGateEnabled_AlwaysReportsApplied_EvenWithoutAdminAPIStores(t *testing.T) {
	srv := sso.NewServer(sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()))
	_ = srv.Handler()

	if !srv.SetAdminAPIGateEnabled(false) {
		t.Fatal("SetAdminAPIGateEnabled(false) = false, want true — admin_api always has a mounted route to affect")
	}
	if !srv.SetAdminAPIGateEnabled(true) {
		t.Fatal("SetAdminAPIGateEnabled(true) = false, want true")
	}
}

// TestSetAdminAPIGateEnabled_ByteIdenticalWithGlobalTracingMiddleware
// reproduces the exact scenario an adversarial review found broken in an
// earlier version of this feature: WithTracingMiddleware adds a global,
// Use()-registered middleware (stamping X-Request-Id/Traceparent/
// X-Trace-Id) BEFORE mountAdminSurface runs, so it was baked into every
// admin route's own middleware list. A handler-only gate would still run
// that middleware on a gated-off request — leaking headers a genuinely
// never-mounted path never has, exactly the oracle this feature exists to
// prevent. The fix (core.GatedRouter's route-matching-level gate) must
// keep the gated-off response byte-identical to the baseline EVEN with
// Tracing wired.
func TestSetAdminAPIGateEnabled_ByteIdenticalWithGlobalTracingMiddleware(t *testing.T) {
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithTracingMiddleware(),
		sso.WithFeatureGates(sso.FeatureGates{AdminAPI: sso.Bool(true)}),
	)
	h := srv.Handler()

	if resp := fghrGet(h, "/api/v1/admin/endpoints"); resp.status == http.StatusNotFound {
		t.Fatalf("GET /api/v1/admin/endpoints with admin_api on = 404, want reachable")
	}
	baseline := fghrGet(h, fghrNeverMountedBaseline)
	if _, ok := baseline.header["X-Request-Id"]; ok {
		t.Fatalf("sanity check failed: baseline itself carries X-Request-Id — Tracing ran for a path that should never match any route")
	}

	if !srv.SetAdminAPIGateEnabled(false) {
		t.Fatal("SetAdminAPIGateEnabled(false) = false, want true")
	}
	got := fghrGet(h, "/api/v1/admin/endpoints")
	if _, ok := got.header["X-Request-Id"]; ok {
		t.Errorf("gated-off admin response leaked X-Request-Id — Tracing middleware ran even though the gate was off")
	}
	fghrAssertIdentical(t, got, baseline, "admin_api live-disabled with Tracing wired")
}

// TestSetWebSPAGateEnabled_BrandingEndpoint_ByteIdenticalTo404 covers the
// mountBrandingEndpoint code path (server_me.go) — the ONLY route web_spa
// still gates now that sso-server serves no static frontend of its own.
// Registered on s.router (not a raw http.ServeMux entry) and so subject to
// the exact same global-middleware-leak risk admin_api had — this test also
// wires WithTracingMiddleware to reproduce that scenario precisely.
func TestSetWebSPAGateEnabled_BrandingEndpoint_ByteIdenticalTo404(t *testing.T) {
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithTracingMiddleware(),
		sso.WithTenantStore(memory.New()),
	)
	h := srv.Handler()

	if resp := fghrGet(h, "/branding"); resp.status == http.StatusNotFound {
		t.Fatalf("GET /branding with web_spa on = 404, want reachable (tenant store is wired)")
	}
	baseline := fghrGet(h, fghrNeverMountedBaseline)

	if !srv.SetWebSPAGateEnabled(false) {
		t.Fatal("SetWebSPAGateEnabled(false) = false, want true (tenant store is wired)")
	}
	got := fghrGet(h, "/branding")
	if _, ok := got.header["X-Request-Id"]; ok {
		t.Errorf("gated-off branding response leaked X-Request-Id — Tracing middleware ran even though the gate was off")
	}
	fghrAssertIdentical(t, got, baseline, "web_spa live-disabled (branding) with Tracing wired")

	if !srv.SetWebSPAGateEnabled(true) {
		t.Fatal("SetWebSPAGateEnabled(true) = false, want true")
	}
	if resp := fghrGet(h, "/branding"); resp.status == http.StatusNotFound {
		t.Fatalf("GET /branding after live re-enable = 404, want reachable")
	}
}

// fghrNopRevoker is a no-op caep.SubjectRevoker for tests that only need a
// constructible receiver, never a fully-processed SET.
type fghrNopRevoker struct{}

func (fghrNopRevoker) RevokeAllForSubject(context.Context, string) (caep.RevocationResult, error) {
	return caep.RevocationResult{}, nil
}

// TestSetOIDCGateEnabled_LiveToggleByteIdenticalWithTracing proves
// feature_gates.oidc's hot-reload for /userinfo, including the tracing-leak
// scenario TestSetAdminAPIGateEnabled_ByteIdenticalWithGlobalTracingMiddleware
// found for admin_api — mountOIDCUserEndpoints uses the SAME
// core.GatedRouter primitive, so it inherits the same route-matching-level
// fix; this proves that inheritance holds for this call site too.
func TestSetOIDCGateEnabled_LiveToggleByteIdenticalWithTracing(t *testing.T) {
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithTracingMiddleware(),
		sso.WithFeatureGates(sso.FeatureGates{OIDC: sso.Bool(true)}),
	)
	h := srv.Handler()

	if resp := fghrGet(h, "/userinfo"); resp.status == http.StatusNotFound {
		t.Fatalf("GET /userinfo with oidc on = 404, want reachable")
	}
	baseline := fghrGet(h, fghrNeverMountedBaseline)

	if !srv.SetOIDCGateEnabled(false) {
		t.Fatal("SetOIDCGateEnabled(false) = false, want true (/userinfo is always mounted)")
	}
	got := fghrGet(h, "/userinfo")
	if _, ok := got.header["X-Request-Id"]; ok {
		t.Errorf("gated-off /userinfo response leaked X-Request-Id — Tracing middleware ran even though the gate was off")
	}
	fghrAssertIdentical(t, got, baseline, "oidc live-disabled with Tracing wired")

	if !srv.SetOIDCGateEnabled(true) {
		t.Fatal("SetOIDCGateEnabled(true) = false, want true")
	}
	if resp := fghrGet(h, "/userinfo"); resp.status == http.StatusNotFound {
		t.Fatalf("GET /userinfo after live re-enable = 404, want reachable")
	}
}

// TestSetCIBAGateEnabled_LiveToggleByteIdenticalWithTracing is
// feature_gates.ciba's analog, against POST /backchannel-authentication.
func TestSetCIBAGateEnabled_LiveToggleByteIdenticalWithTracing(t *testing.T) {
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithTracingMiddleware(),
		sso.WithFeatureGates(sso.FeatureGates{CIBA: sso.Bool(true)}),
	)
	h := srv.Handler()
	post := func(path string) fghrResponse {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return fghrResponse{status: rec.Code, header: rec.Header().Clone(), body: rec.Body.String()}
	}

	if resp := post("/backchannel-authentication"); resp.status == http.StatusNotFound {
		t.Fatalf("POST /backchannel-authentication with ciba on = 404, want reachable")
	}
	baseline := fghrGet(h, fghrNeverMountedBaseline)

	if !srv.SetCIBAGateEnabled(false) {
		t.Fatal("SetCIBAGateEnabled(false) = false, want true (the route is always mounted)")
	}
	got := post("/backchannel-authentication")
	if _, ok := got.header["X-Request-Id"]; ok {
		t.Errorf("gated-off CIBA response leaked X-Request-Id — Tracing middleware ran even though the gate was off")
	}
	fghrAssertIdentical(t, got, baseline, "ciba live-disabled with Tracing wired")

	if !srv.SetCIBAGateEnabled(true) {
		t.Fatal("SetCIBAGateEnabled(true) = false, want true")
	}
	if resp := post("/backchannel-authentication"); resp.status == http.StatusNotFound {
		t.Fatalf("POST /backchannel-authentication after live re-enable = 404, want reachable")
	}
}

// TestSetCAEPGateEnabled_LiveToggleByteIdenticalWithTracing is
// feature_gates.caep's analog, against POST /ssf/receive, with a receiver
// wired via WithCAEPReceiver.
func TestSetCAEPGateEnabled_LiveToggleByteIdenticalWithTracing(t *testing.T) {
	rcv, err := caep.NewReceiver(
		"https://rp.example.com",
		defaultimpl.NewMemoryJTIReplayStore(),
		fghrNopRevoker{},
		defaultimpl.NewMemoryUserProvider(),
		[]caep.TrustedTransmitter{{
			Issuer: "https://transmitter.example.com",
			JWKS:   security.NewStaticJWKS(nil),
		}},
	)
	if err != nil {
		t.Fatalf("caep.NewReceiver: %v", err)
	}
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithTracingMiddleware(),
		sso.WithCAEPReceiver(rcv),
		sso.WithFeatureGates(sso.FeatureGates{CAEP: sso.Bool(true)}),
	)
	h := srv.Handler()
	post := func(path string) fghrResponse {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return fghrResponse{status: rec.Code, header: rec.Header().Clone(), body: rec.Body.String()}
	}

	if resp := post("/ssf/receive"); resp.status == http.StatusNotFound {
		t.Fatalf("POST /ssf/receive with caep on = 404, want reachable")
	}
	baseline := fghrGet(h, fghrNeverMountedBaseline)

	if !srv.SetCAEPGateEnabled(false) {
		t.Fatal("SetCAEPGateEnabled(false) = false, want true (a receiver is wired)")
	}
	got := post("/ssf/receive")
	if _, ok := got.header["X-Request-Id"]; ok {
		t.Errorf("gated-off CAEP response leaked X-Request-Id — Tracing middleware ran even though the gate was off")
	}
	fghrAssertIdentical(t, got, baseline, "caep live-disabled with Tracing wired")

	if !srv.SetCAEPGateEnabled(true) {
		t.Fatal("SetCAEPGateEnabled(true) = false, want true")
	}
	if resp := post("/ssf/receive"); resp.status == http.StatusNotFound {
		t.Fatalf("POST /ssf/receive after live re-enable = 404, want reachable")
	}
}

// TestSetCAEPGateEnabled_NoReceiverWired_ReturnsFalseGracefully mirrors
// SetWebSPAGateEnabled's "nothing to flip" contract: with no CAEP receiver
// ever wired, there is no already-mounted route for the gate to affect.
func TestSetCAEPGateEnabled_NoReceiverWired_ReturnsFalseGracefully(t *testing.T) {
	srv := sso.NewServer(sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()))
	_ = srv.Handler()

	if srv.SetCAEPGateEnabled(false) {
		t.Fatal("SetCAEPGateEnabled(false) = true, want false (no CAEP receiver was ever wired)")
	}
	if srv.SetCAEPGateEnabled(true) {
		t.Fatal("SetCAEPGateEnabled(true) = true, want false (still nothing wired to affect)")
	}
}

// TestSetFederationGateEnabled_LiveToggleByteIdenticalWithTracing is
// feature_gates.federation's analog, against the RFC 9728 protected-resource
// metadata document.
func TestSetFederationGateEnabled_LiveToggleByteIdenticalWithTracing(t *testing.T) {
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithTracingMiddleware(),
		sso.WithProtectedResourceMetadata(sso.ProtectedResourceMetadata{ResourceName: "Hot-Reload Test Resource"}),
		sso.WithFeatureGates(sso.FeatureGates{Federation: sso.Bool(true)}),
	)
	h := srv.Handler()

	if resp := fghrGet(h, "/.well-known/oauth-protected-resource"); resp.status == http.StatusNotFound {
		t.Fatalf("GET /.well-known/oauth-protected-resource with federation on = 404, want reachable")
	}
	baseline := fghrGet(h, fghrNeverMountedBaseline)

	if !srv.SetFederationGateEnabled(false) {
		t.Fatal("SetFederationGateEnabled(false) = false, want true (protected-resource metadata is wired)")
	}
	got := fghrGet(h, "/.well-known/oauth-protected-resource")
	if _, ok := got.header["X-Request-Id"]; ok {
		t.Errorf("gated-off federation response leaked X-Request-Id — Tracing middleware ran even though the gate was off")
	}
	fghrAssertIdentical(t, got, baseline, "federation live-disabled with Tracing wired")

	if !srv.SetFederationGateEnabled(true) {
		t.Fatal("SetFederationGateEnabled(true) = false, want true")
	}
	if resp := fghrGet(h, "/.well-known/oauth-protected-resource"); resp.status == http.StatusNotFound {
		t.Fatalf("GET /.well-known/oauth-protected-resource after live re-enable = 404, want reachable")
	}
}

// TestSetFederationGateEnabled_NothingWired_ReturnsFalseGracefully mirrors
// SetWebSPAGateEnabled's "nothing to flip" contract: with none of the
// federation sub-features ever wired, there is no already-mounted route for
// the gate to affect.
func TestSetFederationGateEnabled_NothingWired_ReturnsFalseGracefully(t *testing.T) {
	srv := sso.NewServer(sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()))
	_ = srv.Handler()

	if srv.SetFederationGateEnabled(false) {
		t.Fatal("SetFederationGateEnabled(false) = true, want false (no federation sub-feature was ever wired)")
	}
	if srv.SetFederationGateEnabled(true) {
		t.Fatal("SetFederationGateEnabled(true) = true, want false (still nothing wired to affect)")
	}
}

// TestSetFederationGateEnabled_HomeRealmSubFeatureAlsoToggles proves the
// SAME live flag controls a DIFFERENT sub-feature in the group (B2B
// home-realm discovery via WithConnectionStore), not just the
// protected-resource metadata document the previous tests exercised.
func TestSetFederationGateEnabled_HomeRealmSubFeatureAlsoToggles(t *testing.T) {
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithConnectionStore(connections.NewMemoryStore()),
		sso.WithFeatureGates(sso.FeatureGates{Federation: sso.Bool(true)}),
	)
	h := srv.Handler()
	path := sso.PathHomeRealm + "?login_hint=user@example.com"

	if resp := fghrGet(h, path); resp.status == http.StatusNotFound {
		t.Fatalf("GET %s with federation on = 404, want reachable", sso.PathHomeRealm)
	}
	if !srv.SetFederationGateEnabled(false) {
		t.Fatal("SetFederationGateEnabled(false) = false, want true (connection store is wired)")
	}
	if resp := fghrGet(h, path); resp.status != http.StatusNotFound {
		t.Errorf("GET %s with federation live-disabled = %d, want 404", sso.PathHomeRealm, resp.status)
	}
}

// TestSetSelfServiceGateEnabled_LiveToggleByteIdenticalWithTracing is
// feature_gates.self_service's analog, against the always-mounted
// GET /permissions/me — mountSelfServiceProfile registers it unconditionally
// of any backing store, so no store wiring is needed here.
func TestSetSelfServiceGateEnabled_LiveToggleByteIdenticalWithTracing(t *testing.T) {
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithTracingMiddleware(),
		sso.WithFeatureGates(sso.FeatureGates{SelfService: sso.Bool(true)}),
	)
	h := srv.Handler()

	if resp := fghrGet(h, sso.PathMyPermissions); resp.status == http.StatusNotFound {
		t.Fatalf("GET %s with self_service on = 404, want reachable", sso.PathMyPermissions)
	}
	baseline := fghrGet(h, fghrNeverMountedBaseline)

	if !srv.SetSelfServiceGateEnabled(false) {
		t.Fatal("SetSelfServiceGateEnabled(false) = false, want true (/permissions/me is always mounted)")
	}
	got := fghrGet(h, sso.PathMyPermissions)
	if _, ok := got.header["X-Request-Id"]; ok {
		t.Errorf("gated-off self-service response leaked X-Request-Id — Tracing middleware ran even though the gate was off")
	}
	fghrAssertIdentical(t, got, baseline, "self_service live-disabled with Tracing wired")

	if !srv.SetSelfServiceGateEnabled(true) {
		t.Fatal("SetSelfServiceGateEnabled(true) = false, want true")
	}
	if resp := fghrGet(h, sso.PathMyPermissions); resp.status == http.StatusNotFound {
		t.Fatalf("GET %s after live re-enable = 404, want reachable", sso.PathMyPermissions)
	}
}
