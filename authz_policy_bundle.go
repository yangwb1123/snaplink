package sso

import (
	"encoding/json"
	"net/http"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/oidc"
	"github.com/snaplink/sso/permissions"
)

// handleAuthzPolicyBundle serves the read-only role-DEFINITION export a
// service-mesh sidecar pulls to enforce authorization locally (no
// per-request Authorizer RPC). Admin-gated (admin:read) by the path
// prefix /api/v1/admin/ — see admin.IsProtectedPath.
//
// Unlike credential endpoints this is a CACHEABLE read: it stamps the
// public Cache-Control + strong ETag exactly like the discovery doc (via
// oidc.WriteDoc), NOT no-store. The ETag is content-based (sha256 over the
// bundle's canonical role bytes, EXCLUDING generated_at), so the same role
// set yields the same ETag across regenerations and a sidecar's
// If-None-Match short-circuits to 304.
//
// Error shape mirrors the admin client read (handleGetClient): missing
// client_id -> 400 missing_client_id; unknown client -> 404
// client_not_found (revealing existence to an authenticated admin is
// fine). Reuses the existing wire error vocabulary — no new error code.
func (s *Server) handleAuthzPolicyBundle(ctx HandlerContext) {
	if s.permissions == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	clientID := ctx.Request().URL.Query().Get(core.KeyClientID)
	if clientID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrMissingClientID))
		return
	}
	// 404 on an unknown client so an enumeration of role definitions can't
	// target a non-existent app — and so the response matches the admin
	// CRUD 404 pattern. Skipped when no client store is wired (the bundle
	// is still derivable purely from the permissions provider).
	if s.clientStore != nil {
		if _, err := s.clientStore.Get(ctx.Request().Context(), clientID); err != nil {
			ctx.JSON(http.StatusNotFound, errorBody(ErrClientNotFound))
			return
		}
	}

	base := requestBaseURL(ctx.Request())
	if s.authzPolicyBundleCacheTTL > 0 {
		if entry := s.lookupAuthzPolicyBundleCache(clientID, base); entry != nil {
			oidc.WriteDoc(ctx, entry, s.authzPolicyBundleCacheTTL)
			return
		}
	}

	bundle, err := permissions.BuildPolicyBundle(ctx.Request().Context(), s.permissions, clientID)
	if err != nil {
		s.logger.Error("authz policy bundle build failed", "client_id", clientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	// ttl <= 0 disables both the in-process cache AND the ETag /
	// Cache-Control headers — every pull renders fresh.
	if s.authzPolicyBundleCacheTTL <= 0 {
		ctx.JSON(http.StatusOK, bundle)
		return
	}
	body, err := json.Marshal(bundle)
	if err != nil {
		s.logger.Error("authz policy bundle marshal failed", "client_id", clientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	// ETag is hashed over the bundle's CANONICAL bytes (role content,
	// EXCLUDING generated_at), not the marshaled body — so a re-render
	// with unchanged roles keeps the same ETag and 304s. The cache entry
	// carries the JSON body for the 200 path and that stable ETag for the
	// If-None-Match path.
	canon := oidc.BuildDocEntry(bundle.CanonicalBytes(), s.authzPolicyBundleCacheTTL)
	entry := &discoveryDocEntry{Body: body, ETag: canon.ETag, ExpiresAt: canon.ExpiresAt}
	s.storeAuthzPolicyBundleCache(clientID, base, entry)
	oidc.WriteDoc(ctx, entry, s.authzPolicyBundleCacheTTL)
}

// OIDC + RFC 9207 response-shaping helpers. Three concerns clustered
// here for navigability:
