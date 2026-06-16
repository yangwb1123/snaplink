package sso

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/snaplink/sso/oauth"
)

func (s *Server) handleUserInfo(ctx HandlerContext) {
	// /userinfo carries the subject's profile (sub, name, email,
	// custom claims). Per RFC 6749 §5.1 cache-prevention pattern
	// applied to /token, the response must never be retained by
	// intermediaries — a stale cached body would leak across
	// users if served from a different bearer.
	tokenNoStoreHeaders(ctx)
	if err := s.requireDeps(DepTokenIssuer, DepUserProvider); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	tokenString := bearerToken(ctx.Request())
	if tokenString == "" {
		// RFC 6750 §3: a 401 from a protected resource MUST carry
		// a WWW-Authenticate challenge naming the scheme + realm.
		// The "no credentials" case omits error parameters per §3.1
		// (the request didn't try to authenticate).
		s.setResourceBearerChallenge(ctx, s.resolveIssuer(ctx), "", "")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrMissingToken))
		return
	}

	claims, _, err := s.validateAnyToken(ctx.Request().Context(), tokenString)
	if err != nil {
		// RFC 6750 §3.1: token-validation failures carry
		// error="invalid_token" in the challenge so the RP can
		// distinguish "I need to refresh" from "I forgot to send".
		s.setResourceBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "The access token is invalid or expired")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}

	// RFC 9449 §7 — when the access token carries a `cnf.jkt`
	// binding, the request MUST also carry a fresh DPoP proof
	// whose JWK thumbprint matches. Legacy bearer tokens (no
	// cnf.jkt) skip this gate. A failure here is indistinguishable
	// from "invalid bearer" on the wire (single error code) so
	// attackers can't tell DPoP-bound from unbound tokens via
	// response probing.
	if err := s.verifyDPoPBearer(ctx, claims); err != nil {
		// RFC 9449 §8 — RS-side nonce challenge: 401 + DPoP-Nonce header.
		// Distinct from the AS-side challenge (400 at /token) so a
		// resource server sees the standard 401-with-WWW-Authenticate
		// pattern it already implements for bearer failures.
		if errors.Is(err, ErrDPoPNonceRequired) {
			s.stampDPoPNonce(ctx)
			s.setResourceBearerChallenge(ctx, s.resolveIssuer(ctx), ErrUseDPoPNonce, "Fresh DPoP nonce required")
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrUseDPoPNonce))
			return
		}
		s.logErrorCtx(ctx, "dpop bearer verification failed", "error", err, "subject", claims.Subject)
		s.setResourceBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "DPoP proof missing or thumbprint mismatch")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}
	// RFC 8705 §3 — symmetric mTLS resource verification. When
	// the token carries cnf.x5t#S256, the inbound TLS connection's
	// client cert MUST have the matching thumbprint. Same wire-
	// shape collapse to invalid_token.
	if err := s.verifyMTLSBearer(ctx, claims); err != nil {
		s.logErrorCtx(ctx, "mtls bearer verification failed", "error", err, "subject", claims.Subject)
		s.setResourceBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "Client certificate missing or thumbprint mismatch")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}

	// Data-residency READ-gate (the access-side counterpart to the login
	// write-gate). The bearer is now fully validated AND any DPoP/mTLS
	// sender-constraint enforced, so this runs ONLY for a holder of a valid
	// token (no unauthenticated oracle). When the token's tenant constrains
	// its serving regions and THIS region isn't allowed, deny with a 403
	// carrying the residency wire code — NOT a 401 invalid_token: the token
	// IS valid, this is a policy denial, a distinct condition that must not
	// corrupt the invalid_token bearer path. tokenNoStoreHeaders already
	// stamped at entry, so the 403 carries no-store too. Zero-cost +
	// byte-identical when residency is disabled (residencyDeniedForAccess
	// returns before any tenant lookup).
	if code, denied := s.residencyDeniedForAccess(ctx, claims); denied {
		ctx.JSON(http.StatusForbidden, errorBody(code))
		return
	}

	// OIDC §8 pairwise: the inbound claims.Subject may be the per-
	// sector opaque identifier rather than a local UserProvider key.
	// Resolve to the local sub before the GetByID — but keep
	// claims.Subject untouched for the projected response so the RP
	// sees the same sub it was given at issuance.
	lookupSub, perr := s.resolveLocalSubject(ctx.Request().Context(), claims.Subject)
	if perr != nil {
		s.logger.Error("pairwise resolve failed at /userinfo", "error", perr, "subject", claims.Subject)
		s.setResourceBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "Subject mapping unavailable")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}
	user, err := s.userProvider.GetByID(ctx.Request().Context(), lookupSub)
	if err != nil {
		ctx.JSON(http.StatusNotFound, errorBody(ErrUserNotFound))
		return
	}

	// OIDC profile: when the token carries "openid" scope, project the
	// user into the OIDC-standard claim shape (sub always, then claims
	// gated by scope per OIDC Core §5.4). The full User struct (with
	// non-standard fields like provider, created_at) is returned only
	// for non-OIDC tokens — pre-OIDC integrations keep working unchanged.
	if slices.Contains(claims.Scopes, ScopeOpenID) {
		body := projectUserInfoForOIDC(user, claims.Scopes, claims.RequestedClaims)
		// OIDC §8 pairwise: the projected `sub` is u.ID (local), but
		// the RP knows the user by the pairwise sub from its token.
		// Restore the inbound sub so the response matches the RP's
		// view (RPs MUST verify `sub` here matches the id_token sub
		// per §5.3.2; mismatch would fail that check).
		if claims.Subject != "" && claims.Subject != user.ID {
			body["sub"] = claims.Subject
		}
		// RFC 9068 §2.2 claims passthrough on the OIDC profile: when
		// the access token carries auth_time / acr / amr (because it
		// was minted via /auth/login with a fresh user-auth event),
		// expose them on /userinfo so downstream policy can branch
		// on factor strength without re-validating the access token.
		// Empty values are omitted so legacy tokens still produce
		// the minimal {sub} response.
		if !claims.AuthTime.IsZero() {
			body["auth_time"] = claims.AuthTime.Unix()
		}
		if claims.ACR != "" {
			body["acr"] = claims.ACR
		}
		if len(claims.AMR) > 0 {
			body["amr"] = claims.AMR
		}
		// OIDC Core §5.3.2 — when the requesting client has
		// `userinfo_signed_response_alg` set AND the wired
		// oidc.IDTokenIssuer implements oidc.UserinfoSigner, return a
		// signed JWT (Content-Type: application/jwt) instead
		// of plain JSON. Today only EdDSA is supported.
		if s.maybeSignUserInfo(ctx, claims.ClientID, body) {
			return
		}
		ctx.JSON(http.StatusOK, body)
		return
	}

	ctx.JSON(http.StatusOK, user)
}

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
	// same logic without duplicating it (and without go-control-plane in the
	// core go.mod). Build the request abstraction from the *http.Request —
	// requestURLForDPoP(r) supplies the same X-Forwarded-aware htu the inline
	// path used, the cloned Header carries the bearer + DPoP proof +
	// X-Forwarded-* + header-mode mTLS cert, and r.TLS feeds TLS-backend
	// mTLS — so MeshAuthorize reads exactly what the inline handler did. The
	// HTTP response is then rendered byte-identically by
	// writeMeshAuthzResponse.
	r := ctx.Request()
	res := s.MeshAuthorize(r.Context(), MeshAuthorizeRequest{
		Method: r.Method,
		URL:    requestURLForDPoP(r),
		Header: r.Header,
		TLS:    r.TLS,
	})
	s.writeMeshAuthzResponse(ctx, res)
}

// projectUserInfoForOIDC returns the OIDC-standard claim set for a user
// gated by the token's scopes. OIDC Core §5.4 mapping:
//
//	openid  → sub (always)
//	email   → email, email_verified
//	profile → name, given_name, family_name, picture, preferred_username
//	address → address (object)
//	phone   → phone_number, phone_number_verified
//
// Non-standard fields on the User (provider, external_id, created_at,
// updated_at) are omitted — OIDC RPs don't expect them and including
// them would make the response shape ambiguous with the legacy
// non-OIDC response.
//
// Per-claim values come from User's first-class fields (Email, Name)
// or from Attributes when the field name matches the claim name.
// Operators control which claims are exposed via what they populate
// in the User and Attributes — there's no per-server claim allowlist
// to maintain.
func projectUserInfoForOIDC(u *User, scopes []string, requestedClaims json.RawMessage) map[string]any {
	out := map[string]any{"sub": u.ID}
	hasScope := func(name string) bool {
		return slices.Contains(scopes, name)
	}
	// Attributes win when both an attribute AND a first-class field
	// carry the same claim — the authenticator is the live source of
	// truth (User.Email + User.Name are caches that aren't always
	// repopulated by the login upsert path).
	emailFrom := func() string {
		if v, ok := u.Attributes["email"]; ok && v != "" {
			return v
		}
		return u.Email
	}
	nameFrom := func() string {
		if v, ok := u.Attributes["name"]; ok && v != "" {
			return v
		}
		return u.Name
	}
	if hasScope("email") {
		if v := emailFrom(); v != "" {
			out["email"] = v
		}
		if v, ok := u.Attributes["email_verified"]; ok {
			out["email_verified"] = v == "true"
		}
	}
	if hasScope("profile") {
		if v := nameFrom(); v != "" {
			out["name"] = v
		}
		for _, k := range []string{"given_name", "family_name", "picture", "preferred_username", "nickname", "locale", "zoneinfo"} {
			if v, ok := u.Attributes[k]; ok && v != "" {
				out[k] = v
			}
		}
	}
	if hasScope("address") {
		if v, ok := u.Attributes["address"]; ok && v != "" {
			out["address"] = v
		}
	}
	if hasScope("phone") {
		if v, ok := u.Attributes["phone_number"]; ok && v != "" {
			out["phone_number"] = v
		}
		if v, ok := u.Attributes["phone_number_verified"]; ok {
			out["phone_number_verified"] = v == "true"
		}
	}
	// OIDC Core §5.5: project userinfo-section requested claims that
	// scope alone did not already include. Fail-open on parse errors.
	if len(requestedClaims) > 0 {
		if _, userinfoReq, parseErr := oauth.ParseRequestedClaims(requestedClaims); parseErr == nil {
			for claimName := range userinfoReq {
				if _, alreadySet := out[claimName]; alreadySet {
					continue
				}
				if v, ok := u.Attributes[claimName]; ok && v != "" {
					out[claimName] = v
				}
			}
		}
	}
	return out
}
