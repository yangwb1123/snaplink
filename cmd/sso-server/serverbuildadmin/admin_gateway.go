// Package serverbuildadmin owns the pure admin gRPC-gateway routing table:
// which URL patterns are gateway-owned vs SSO-router-owned, and the outer
// mux composition. Split out of the command root (build_http.go) so the
// frozen cmd/sso-server go-file ceiling and the 500-line file budget both
// hold; the command root keeps thin wrappers (adminGatewayExactPaths /
// newAdminOuterMux) so the gateway regression suite stays in package main.
package serverbuildadmin

import "net/http"

// GatewayPaths lists every URL PATTERN the admin gRPC-gateway (see
// registerAdminGateway in the command root) actually serves — derived from
// the .proto http annotations under proto/admin/v1/*.proto. Reproduce with:
//
//	grep -rhn "WithHTTPPathPattern(" gen/proto/admin/v1/*.pb.gw.go | \
//	  grep -oP '(?<=WithHTTPPathPattern\(")[^"]+' | sort -u
//
// Registering the gateway ONLY at these literal patterns — instead of the
// whole /api/v1/admin/ subtree — lets every other admin route (which grows
// continuously; see interfaces/sso/server_routes_admin.go) fall through the
// outer mux's "/" catch-all to the SSO router by default, instead of
// requiring an ad-hoc carve-out per new SSO-router route. That old scheme
// silently swallowed new routes into the gateway's blanket 404 whenever a
// carve-out was forgotten — it was forgotten at least twice (bulk-revoke,
// commit fdebea60, and the local-user CRUD collision fixed alongside this
// change).
//
// Several proto RPCs share one URL SHAPE under a different path-variable
// name (e.g. Update's "{client.id}" vs Get/Delete's "{id}" both bind the
// same single wildcard segment — grpc-gateway's OWN internal mux resolves
// the per-method dispatch). Go's http.ServeMux (1.22+ pattern matching) only
// cares about the STRUCTURAL shape — segment count + literal-vs-wildcard —
// so each shape is listed ONCE; the variable name is irrelevant to routing.
//
// IMPORTANT, verified empirically (see TestAdminGatewayExactPaths_ValidServeMuxSyntax):
// grpc-gateway's "custom verb" shapes — "{id}:pin", "{id}:rollback",
// "{id}:restore", "{id}:set-status" (a colon-suffix GLUED to the SAME
// wildcard segment) — are NOT valid Go http.ServeMux pattern syntax.
// mux.Handle panics at registration with "bad wildcard segment (must end
// with '}')": Go's wildcard segment must be the ENTIRE segment, nothing may
// follow "}" before the next "/". Registering the PLAIN "{id}" pattern (also
// needed for that resource's Get/Delete) is sufficient WITHOUT a separate
// entry: Go's ServeMux treats a colon as ordinary segment text, so a request
// for ".../releases/abc:pin" structurally matches "/api/v1/admin/releases/{id}"
// just like ".../releases/abc" does. The request then reaches the gateway
// UNMODIFIED, where grpc-gateway's OWN internal pattern compiler (which DOES
// support the colon-verb convention) re-resolves the exact RPC from the full
// path + method — exactly as it already did before this change, when the
// whole /api/v1/admin/ subtree was forwarded to it. This routing fix only
// changes which requests reach the gateway's ServeHTTP, never how the
// gateway resolves a request once it gets there. "releases:current" (a bare
// literal, no wildcard) has no such restriction and is listed as-is.
//
// The "tokens" and "users" families are NOT full subtrees: the SSO router
// owns most of their sub-paths (token portfolio/expiring/suspicious/usage/
// bulk-revoke/policies, and every users/{id}/... surface except the bare
// CRUD + session-list), so only the gateway's own exact shapes are listed.
func GatewayPaths() []string {
	paths := resourcePaths()
	return append(paths, tokenAndUserPaths()...)
}

// resourcePaths covers the clients/domains/keys/permissions/
// releases/snapshots/tenants families — split out of GatewayPaths
// purely to stay under the function-length budget (§0.1); see that
// function's doc for the shared rationale and the custom-verb caveat these
// "{id}"-only releases/snapshots/tenants entries rely on.
func resourcePaths() []string {
	return []string{
		// clients — proto/admin/v1/clients.proto
		"/api/v1/admin/clients",
		"/api/v1/admin/clients/{id}",
		"/api/v1/admin/clients/{id}/approve",
		"/api/v1/admin/clients/{id}/reject",
		"/api/v1/admin/clients/{id}/rotate-secret",
		// ListExpiring — proto/admin/v1/clients.proto (P3-1 audit: generated
		// gateway pattern was missing from this list, so the request fell to
		// the SSO-router catch-all and 404'd).
		"/api/v1/admin/clients/expiring",
		// domains — proto/admin/v1/tenants.proto
		"/api/v1/admin/domains",
		"/api/v1/admin/domains/{hostname}",
		// keys — proto/admin/v1/keys.proto
		"/api/v1/admin/keys",
		"/api/v1/admin/keys/rotate",
		// permissions — proto/admin/v1/permissions.proto
		"/api/v1/admin/permissions/{client_id}/assignments",
		"/api/v1/admin/permissions/{client_id}/assignments/{user_id}",
		"/api/v1/admin/permissions/{client_id}/assignments/{user_id}/unassign",
		"/api/v1/admin/permissions/{client_id}/menus",
		"/api/v1/admin/permissions/{client_id}/resources",
		"/api/v1/admin/permissions/{client_id}/resources/{id}",
		"/api/v1/admin/permissions/{client_id}/roles",
		"/api/v1/admin/permissions/{client_id}/roles/{role_code}",
		"/api/v1/admin/permissions/{client_id}/sod/conflicts",
		"/api/v1/admin/permissions/{client_id}/dsod/conflicts",
		"/api/v1/admin/permissions/{client_id}/sessions/{session_id}/roles",
		// releases — proto/admin/v1/releases.proto. "{id}" also catches the
		// grpc-gateway custom-verb shapes "{id}:pin"/"{id}:rollback" — see
		// GatewayPaths' doc; do NOT add those separately (panics).
		"/api/v1/admin/releases",
		"/api/v1/admin/releases:current",
		"/api/v1/admin/releases/{id}",
		// snapshots — proto/admin/v1/snapshots.proto. "{id}" also catches
		// "{id}:restore".
		"/api/v1/admin/snapshots",
		"/api/v1/admin/snapshots/{id}",
		// durable multi-step operation journal
		"/api/v1/admin/operations",
		"/api/v1/admin/operations/{id}",
		// tenants — proto/admin/v1/tenants.proto. "{id}" also catches
		// "{id}:set-status".
		"/api/v1/admin/tenants",
		"/api/v1/admin/tenants/{id}",
	}
}

// tokenAndUserPaths covers the tokens/users families — NOT full
// subtrees, since the SSO router owns most of their sub-paths. Split out of
// GatewayPaths purely to stay under the function-length budget.
func tokenAndUserPaths() []string {
	return []string{
		// tokens — proto/admin/v1/tokens.proto — ONLY these three shapes.
		// tokens/portfolio, tokens/subjects/*, tokens/expiring,
		// tokens/suspicious, tokens/usage, tokens/bulk-revoke, and
		// token-policies are ALL SSO-router-owned; never add them here.
		"/api/v1/admin/tokens/revoke",
		"/api/v1/admin/tokens/sessions",
		"/api/v1/admin/tokens/temp",
		// users — proto/admin/v1/users.proto — ONLY the bare CRUD + session-
		// list shapes. Every other users/{id}/... sub-path (mfa, consents,
		// password, email, device-secrets, refresh-tokens, password-reset-
		// tokens, email-change-tokens, lifecycle, recovery-codes) is
		// SSO-router-owned; never add them here.
		"/api/v1/admin/users",
		"/api/v1/admin/users/{id}",
		"/api/v1/admin/users/{id}/sessions",
	}
}

// NewOuterMux composes the final outer mux from the gateway's exact
// owned patterns and the two handlers: `gated` (admin-gated gRPC-gateway)
// answers exactly those patterns, `base` (the admin-gated SSO router)
// answers everything else via the "/" catch-all. Split out of the command
// root so the routing table itself — which patterns resolve to which
// handler — is unit-testable without constructing a full *app (see
// admin_gateway_routing_test.go in the command root).
func NewOuterMux(gatewayPaths []string, gated, base http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	for _, p := range gatewayPaths {
		mux.Handle(p, gated)
	}
	mux.Handle("/", base)
	return mux
}
