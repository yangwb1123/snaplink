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
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/snaplink/sso/domains/tenant/memory"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
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

// TestSetWebSPAGateEnabled_LiveToggleIsByteIdenticalTo404 proves the same
// property for web_spa, exercised against the admin-console SPA filesystem
// mount (server_routes.go's buildProbeMux) — the FS is wired at boot via
// WithAdminConsoleFS, so both directions of the toggle are available.
func TestSetWebSPAGateEnabled_LiveToggleIsByteIdenticalTo404(t *testing.T) {
	fsys := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>admin console</html>")}}
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithAdminConsoleFS(fsys),
	)
	h := srv.Handler()

	if resp := fghrGet(h, "/admin/"); resp.status != http.StatusOK {
		t.Fatalf("GET /admin/ with web_spa on = %d, want 200", resp.status)
	}
	baseline := fghrGet(h, fghrNeverMountedBaseline)

	if !srv.SetWebSPAGateEnabled(false) {
		t.Fatal("SetWebSPAGateEnabled(false) = false, want true (admin console FS is wired)")
	}
	fghrAssertIdentical(t, fghrGet(h, "/admin/"), baseline, "web_spa live-disabled")

	if !srv.SetWebSPAGateEnabled(true) {
		t.Fatal("SetWebSPAGateEnabled(true) = false, want true")
	}
	if resp := fghrGet(h, "/admin/"); resp.status != http.StatusOK {
		t.Fatalf("GET /admin/ after live re-enable = %d, want 200", resp.status)
	}
}

// TestSetWebSPAGateEnabled_NoFilesystemWired_ReturnsFalseGracefully proves
// scenario (c), the one real asymmetry: with NO SPA filesystem ever wired
// via a With*FS option at NewServer time, there is no already-mounted route
// for the gate to affect. SetWebSPAGateEnabled must report that (false),
// not silently no-op while looking like it succeeded — that distinction is
// what lets config/reload surface it as Result.Ignored instead of a false
// Result.Applied.
func TestSetWebSPAGateEnabled_NoFilesystemWired_ReturnsFalseGracefully(t *testing.T) {
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		// No With*FS option at all — mirrors an API-only deployment.
	)
	_ = srv.Handler()

	if srv.SetWebSPAGateEnabled(false) {
		t.Fatal("SetWebSPAGateEnabled(false) = true, want false (no SPA filesystem was ever wired)")
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
// mountBrandingEndpoint code path specifically (server_me.go) — a
// DIFFERENT call site from the admin-console SPA filesystem mount
// TestSetWebSPAGateEnabled_LiveToggleIsByteIdenticalTo404 already covers,
// registered on s.router (not a raw http.ServeMux entry) and so subject
// to the exact same global-middleware-leak risk admin_api had. This one
// also wires WithTracingMiddleware to reproduce that scenario precisely.
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
