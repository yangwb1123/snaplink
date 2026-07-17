package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This file is a regression suite for the admin-gateway routing bug: the
// outer mux composed in buildAdminRESTMux (build_http.go) used to mount the
// admin gRPC-gateway as a catch-all subtree over /api/v1/admin/, which
// silently swallowed every SSO-router-owned admin route into the gateway's
// blanket 404 (routingErrorHandler) unless a bespoke exact-path carve-out
// was added — a pattern that was forgotten at least twice (bulk-revoke,
// commit fdebea60; the admin local-user CRUD collision fixed alongside this
// suite). adminGatewayExactPaths + newAdminOuterMux invert this: the gateway
// is now mounted ONLY at the exact patterns it owns, and everything else
// falls through "/" to the SSO router by default.
//
// This file covers the pure ROUTING TABLE (no admin auth, no *app, no real
// gRPC-gateway) with the real stdlib http.ServeMux — fast and deterministic.
// admin_gateway_routing_e2e_test.go covers the full composed handler
// (buildApp + buildHTTPHandler + a real admin bearer) for behavior that only
// exists once the real gateway/permissions/admin-middleware are wired.

const (
	routeMarkerHeader = "X-Route-Marker"
	routeMarkerGate   = "gateway"
	routeMarkerBase   = "base"
)

// markerHandler answers any request with a distinctive status (StatusTeapot
// — never confusable with a real handler's response) and stamps
// routeMarkerHeader so the test can tell which of the two handlers a given
// request actually reached.
func markerHandler(marker string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(routeMarkerHeader, marker)
		w.WriteHeader(http.StatusTeapot)
	})
}

// concretePath turns a route pattern (as returned by adminGatewayExactPaths,
// which may contain Go http.ServeMux "{name}" wildcards) into a concrete,
// dispatchable request path by substituting every wildcard with a fixed
// placeholder. Route REGISTRATION only cares about a wildcard's position;
// dispatching a real request needs an actual path.
func concretePath(pattern string) string {
	var b strings.Builder
	inWildcard := false
	for _, r := range pattern {
		switch {
		case r == '{':
			inWildcard = true
			b.WriteString("x")
		case r == '}':
			inWildcard = false
		case inWildcard:
			// skip the wildcard's variable name
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TestAdminGatewayExactPaths_ValidServeMuxSyntax is the regression test for a
// boot-crashing bug caught while building this suite: grpc-gateway's
// "custom verb" URL shapes (e.g. "/api/v1/admin/releases/{id}:pin", a colon
// suffix GLUED to the wildcard segment) are NOT valid Go 1.22+
// http.ServeMux pattern syntax — mux.Handle panics at registration with
// "bad wildcard segment (must end with '}')". Reproduced with a standalone
// throwaway script against the real stdlib mux before this fix; asserted
// here permanently so a future edit to adminGatewayExactPaths can't
// reintroduce a pattern the outer mux can't register (which would crash
// buildAdminRESTMux — and therefore the whole server — at startup whenever
// admin.api_rest_enabled is true).
func TestAdminGatewayExactPaths_ValidServeMuxSyntax(t *testing.T) {
	t.Parallel()
	paths := adminGatewayExactPaths()
	if len(paths) == 0 {
		t.Fatal("adminGatewayExactPaths returned no patterns")
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("registering adminGatewayExactPaths() on a real http.ServeMux panicked: %v", r)
			}
		}()
		mux := http.NewServeMux()
		for _, p := range paths {
			mux.Handle(p, markerHandler(routeMarkerGate))
		}
	}()
}

// TestAdminOuterMux_GatewayOwnedPathsReachGateway dispatches a concrete
// request for every pattern adminGatewayExactPaths declares and confirms
// newAdminOuterMux routes it to the gateway handler — the routing table's
// OWN claims, verified against the real stdlib ServeMux rather than assumed.
func TestAdminOuterMux_GatewayOwnedPathsReachGateway(t *testing.T) {
	t.Parallel()
	paths := adminGatewayExactPaths()
	mux := newAdminOuterMux(paths, markerHandler(routeMarkerGate), markerHandler(routeMarkerBase))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, pattern := range paths {
		reqPath := concretePath(pattern)
		resp, err := http.Get(srv.URL + reqPath)
		if err != nil {
			t.Fatalf("GET %s (pattern %q): %v", reqPath, pattern, err)
		}
		got := resp.Header.Get(routeMarkerHeader)
		_ = resp.Body.Close()
		if got != routeMarkerGate {
			t.Errorf("pattern %q, request %s: routed to marker %q, want %q (gateway)", pattern, reqPath, got, routeMarkerGate)
		}
	}
}

// TestAdminOuterMux_CustomVerbShapesReachGateway empirically proves the claim
// documented on adminGatewayExactPaths: since Go's ServeMux cannot register a
// colon-suffixed wildcard segment directly, the plain "{id}" pattern (already
// registered for that resource's Get/Delete) must ALSO catch the
// grpc-gateway "custom verb" request shapes ("{id}:pin", "{id}:rollback",
// "{id}:restore", "{id}:set-status") — Go's ServeMux treats a colon as
// ordinary segment text, so these still structurally match the plain
// wildcard. Verified against the real stdlib mux, not just reasoned about.
func TestAdminOuterMux_CustomVerbShapesReachGateway(t *testing.T) {
	t.Parallel()
	mux := newAdminOuterMux(adminGatewayExactPaths(), markerHandler(routeMarkerGate), markerHandler(routeMarkerBase))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	customVerbPaths := []string{
		"/api/v1/admin/releases/rel-1:pin",
		"/api/v1/admin/releases/rel-1:rollback",
		"/api/v1/admin/snapshots/snap-1:restore",
		"/api/v1/admin/tenants/t1:set-status",
	}
	for _, p := range customVerbPaths {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		got := resp.Header.Get(routeMarkerHeader)
		_ = resp.Body.Close()
		if got != routeMarkerGate {
			t.Errorf("%s: routed to marker %q, want %q (gateway) — the plain {id} wildcard should catch this custom-verb shape", p, got, routeMarkerGate)
		}
	}
}

// TestAdminOuterMux_SSORouterOnlyPathsFallThroughToBase is the direct
// regression test for the bug class this whole change fixes: every path here
// is SSO-router-owned (never registered by the admin gRPC-gateway) and, under
// the OLD subtree-plus-carve-outs scheme, would have been silently swallowed
// into the gateway's blanket 404 unless it happened to have its own
// carve-out. adminBulkRevokePath and adminLocalUsersPath/adminLocalUserByIDPath
// are the two concrete collisions this task fixes (bulk-revoke: commit
// fdebea60; local-users: this change); the rest is a representative sample
// of the broader class (token governance, sessions, tenant usage, the authz
// policy-bundle export whose ad-hoc carve-out this change REMOVES, and the
// wasmauthz debug check whose ad-hoc carve-out this change also removes).
func TestAdminOuterMux_SSORouterOnlyPathsFallThroughToBase(t *testing.T) {
	t.Parallel()
	mux := newAdminOuterMux(adminGatewayExactPaths(), markerHandler(routeMarkerGate), markerHandler(routeMarkerBase))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ssoRouterOnlyPaths := []string{
		"/api/v1/admin/tokens/bulk-revoke", // fdebea60's fix
		"/api/v1/admin/local-users",        // this task's fix
		"/api/v1/admin/local-users/u1",     // this task's fix
		"/api/v1/admin/tokens/portfolio",
		"/api/v1/admin/tokens/subjects/u1",
		"/api/v1/admin/tokens/expiring",
		"/api/v1/admin/tokens/suspicious",
		"/api/v1/admin/tokens/usage",
		"/api/v1/admin/token-policies",
		"/api/v1/admin/sessions",
		"/api/v1/admin/sessions/linked/u1",
		"/api/v1/admin/tenants/t1/usage",
		"/api/v1/admin/tenants/t1/members",
		"/api/v1/admin/usage/top-tenants",
		"/api/v1/admin/authz/policy-bundle", // ad-hoc carve-out REMOVED by this change
		"/api/v1/admin/wasmauthz/check",     // ad-hoc carve-out REMOVED by this change
		"/api/v1/admin/endpoints",
		"/api/v1/audit/events", // sanity: a DIFFERENT prefix, never affected by this bug either way
	}
	for _, p := range ssoRouterOnlyPaths {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		got := resp.Header.Get(routeMarkerHeader)
		_ = resp.Body.Close()
		if got != routeMarkerBase {
			t.Errorf("%s: routed to marker %q, want %q (base) — a gateway-owned pattern is swallowing an SSO-router path", p, got, routeMarkerBase)
		}
	}
}

// TestAdminOuterMux_GatewayPathsDoNotShadowLocalUsers is a narrower,
// documentation-grade regression guard: the gateway's OWN "/api/v1/admin/users"
// + "/api/v1/admin/users/{id}" shapes must NOT structurally overlap with the
// SSO router's "/api/v1/admin/local-users" + "/api/v1/admin/local-users/{id}"
// — different literal segment ("users" vs "local-users"), so Go's ServeMux
// treats them as fully disjoint patterns. If a future rename ever collapsed
// them back onto the same literal, this test would start failing.
func TestAdminOuterMux_GatewayPathsDoNotShadowLocalUsers(t *testing.T) {
	t.Parallel()
	for _, p := range adminGatewayExactPaths() {
		if strings.Contains(p, "local-users") {
			t.Fatalf("adminGatewayExactPaths must never claim a local-users path (found %q) — that surface is SSO-router-owned", p)
		}
	}
}
