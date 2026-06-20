package sso

import (
	"net/http"

	"github.com/snaplink/sso/protocols/oidc"
)

// handleUserInfo delegates to oidc.HandleUserInfo (the OIDC §5.3 endpoint
// orchestration). *Server satisfies oidc.UserInfoDeps via accessors_userinfo.go;
// the security primitives (token validation, DPoP/mTLS sender-constraint,
// residency read-gate) are implemented in the root package.
func (s *Server) handleUserInfo(ctx HandlerContext) { oidc.HandleUserInfo(s, ctx) }

// handleMeshExtAuthz is the Envoy/Istio ext_authz HTTP-mode authorization
// endpoint (cluster C1 mesh data-plane). A mesh sidecar calls it per
// request: a 200 ALLOWs (and the sidecar injects the X-Auth-* response
// headers stamped here into the upstream request), any other status
// DENIES. It is essentially a /userinfo variant that returns IDENTITY
// HEADERS instead of a body — so it reuses the EXACT bearer-validation
// path /userinfo uses (validateAnyToken + the DPoP/mTLS sender-constraint
// checks), with no new validation logic. The "validate at the sidecar,
// inject identity to the upstream" mesh pattern.
//
// TRUST MODEL: every X-Auth-* header is DERIVED from the validated token;
// the endpoint NEVER trusts an inbound X-Auth-*. The upstream trusts the
// injected headers ONLY because the sidecar ran this check, so the mesh
// MUST strip client-supplied X-Auth-* at ingress (same edge-strip model
// as X-Forwarded-* / mtls.backend: header — AGENTS.md §2). The endpoint
// is mesh-internal: only the trusted sidecar should be able to reach it.
func (s *Server) handleMeshExtAuthz(ctx HandlerContext) {
	// Credential-validating endpoint: the (header-only) response must
	// never be retained by an intermediary — a cached cross-request
	// ALLOW would let a different bearer's identity be injected upstream.
	tokenNoStoreHeaders(ctx)
	if err := s.requireDeps(DepTokenIssuer); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	// Thin HTTP wrapper over the dep-free MeshAuthorize seam (mesh_authz.go).
	// The decision (bearer validation + DPoP/mTLS sender-constraint +
	// residency + identity derivation) lives in MeshAuthorize so a future
	// Phase-B go-control-plane gRPC Authorization service reuses the EXACT
	// same logic without duplicating it.
	r := ctx.Request()
	res := s.MeshAuthorize(r.Context(), MeshAuthorizeRequest{
		Method: r.Method,
		URL:    requestURLForDPoP(r),
		Header: r.Header,
		TLS:    r.TLS,
	})
	s.writeMeshAuthzResponse(ctx, res)
}
