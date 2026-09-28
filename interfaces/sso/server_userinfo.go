package sso

import (
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/internal/auth/login"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/shared/core"
)

// handleUserInfo delegates to oidc.HandleUserInfo (the OIDC §5.3 endpoint
// orchestration). *Server satisfies oidc.UserInfoDeps via accessors_userinfo.go;
// the security primitives (token validation, DPoP/mTLS sender-constraint,
// residency read-gate) are implemented in the root package.
func (s *Server) handleUserInfo(ctx HandlerContext) { oidc.HandleUserInfo(s, ctx) }

// ResourceToken accepts both RFC 6750 Bearer and RFC 9449 DPoP authorization
// schemes. Only resource-server handlers use this accessor; client-auth and
// management endpoints retain the stricter BearerToken behavior.
func (s *Server) ResourceToken(r *http.Request) string { return oauth.ResourceToken(r) }

// handleCheckSessionIframe delegates to oidc.HandleCheckSessionIframe — the
// OpenID Connect Session Management 1.0 §2 endpoint. No Deps: see there.
func (s *Server) handleCheckSessionIframe(ctx HandlerContext) { oidc.HandleCheckSessionIframe(ctx) }

// mountOIDCUserEndpoints registers the OIDC-specific /userinfo,
// /end_session, and (session-management-gated) /check_session_iframe
// routes UNCONDITIONALLY, gating reachability LIVE via core.GatedRouter so
// feature_gates.oidc is hot-reloadable (SetOIDCGateEnabled) with no
// re-Mount. sessionManagementEnabled stays a boot-time nil/bool check — it
// is a separate opt-in feature (WithOIDCSessionManagement), not the OIDC
// gate. Moved out of server_routes.go (which sat at the line budget) so the
// OIDC gate check + the session-management gate live beside the handlers
// they mount.
func (s *Server) mountOIDCUserEndpoints() {
	gr := core.NewGatedRouter(s.router, s.oidcGateOn)
	gr.GET(PathUserInfo, s.handleUserInfo)
	gr.GET(PathEndSession, s.handleEndSession)
	if s.sessionManagementEnabled {
		gr.GET(PathCheckSessionIframe, s.handleCheckSessionIframe)
	}
}

// applySessionManagement computes + stamps the OpenID Connect Session
// Management 1.0 §2 `session_state` (only when WithOIDCSessionManagement is
// wired AND the request carries the openid scope — byte-identical response
// shape otherwise) and sets the matching browser-state cookie the
// check_session_iframe page later reads via document.cookie.
//
// origin is derived from the RP's OWN redirect_uri — the only allowlist-
// validated RP URL available at /auth/login — per the algorithm's "origin"
// input. browserState is this login's freshly-created session id: it is
// fresh on every login and disappears at logout (ClearSessionManagementCookie
// in accessors.go), which is exactly the "changes when login state changes"
// contract the spec requires of browser_state.
//
// Fail-open: a salt-generation error just omits session_state (and skips
// the cookie) rather than blocking the login.
func (s *Server) applySessionManagement(ctx HandlerContext, req *login.Request, client *Client, session *Session, resp map[string]any) {
	if !s.sessionManagementEnabled || !slices.Contains(req.Scope, ScopeOpenID) {
		return
	}
	origin := oidc.OriginFromURL(req.RedirectURI)
	state, err := oidc.BuildSessionState(client.ID, origin, session.ID)
	if err != nil {
		s.logger.Error("session_state computation failed", "error", err)
		return
	}
	resp[core.KeySessionState] = state
	http.SetCookie(ctx.ResponseWriter(), &http.Cookie{
		Name:     oidc.CheckSessionCookieName,
		Value:    session.ID,
		Path:     PathCheckSessionIframe,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
}

// ClearSessionManagementCookie implements oidc.EndSessionDeps: expires the
// OpenID Connect Session Management 1.0 browser-state cookie so a later
// check_session_iframe comparison observes "changed". A no-op when
// WithOIDCSessionManagement was never wired — writing a Set-Cookie header
// in that case would break /end_session's byte-identical-when-off contract.
// Relocated from accessors.go to keep that file within the per-file line
// budget; it belongs beside applySessionManagement, the other half of this
// cookie's lifecycle.
func (s *Server) ClearSessionManagementCookie(ctx core.HandlerContext) {
	if !s.sessionManagementEnabled {
		return
	}
	http.SetCookie(ctx.ResponseWriter(), &http.Cookie{
		Name:     oidc.CheckSessionCookieName,
		Value:    "",
		Path:     PathCheckSessionIframe,
		MaxAge:   -1,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
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
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrServerMisconfigured))
		return
	}

	// Peer-trust gate: with trusted proxies configured, identity derivation
	// is served ONLY to a direct peer inside the trusted CIDRs (the mesh
	// sidecar / edge tier) — an untrusted caller must not be able to use
	// this endpoint as a token-to-identity oracle. The DENY mirrors the
	// EXACT challenge the ungated MeshAuthorize deny would emit (missing
	// token → bare RFC 6750 §3.1 challenge, no error=; present-but-anything
	// → invalid_token), so the gate's existence is not probeable by a header
	// diff. Unset knob ⇒ no verdict in the context ⇒ legacy behavior,
	// byte-identical.
	if !middleware.ForwardedHeadersTrusted(ctx.Request()) {
		if bearerToken(ctx.Request()) == "" {
			setBearerChallenge(ctx, s.resolveIssuer(ctx), "", "")
		} else {
			setBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "The access token is invalid or expired")
		}
		ctx.ResponseWriter().WriteHeader(http.StatusUnauthorized)
		return
	}

	// Thin HTTP wrapper over the dep-free MeshAuthorize seam (mesh_authz.go).
	// The decision (bearer validation + DPoP/mTLS sender-constraint +
	// residency + identity derivation) lives in MeshAuthorize so the
	// Phase-B go-control-plane gRPC Authorization service
	// (infrastructure/extauthz) reuses the EXACT same logic without
	// duplicating it.
	r := ctx.Request()
	res := s.MeshAuthorize(r.Context(), MeshAuthorizeRequest{
		Method: r.Method,
		URL:    requestURLForDPoP(r),
		Header: r.Header,
		TLS:    r.TLS,
	})
	s.writeMeshAuthzResponse(ctx, res)
}

// Login profile synchronization is kept beside the user/profile access seams so
// the login orchestrator remains within its file budget.
//
// applyLoginPresentationPreferences persists only the two presentation hints
// emitted by the hosted login page. The values are intentionally validated
// here, after the user has authenticated and any consent gate has passed: the
// fields are UX state, not OAuth authorization inputs, and must never become a
// way to mutate an arbitrary account.
func (s *Server) applyLoginPresentationPreferences(
	ctx HandlerContext,
	result *AuthResult,
	req login.Request,
	clientID string,
) {
	if s.userProvider == nil {
		return
	}
	preferences := validLoginPresentationPreferences(req)
	if len(preferences) == 0 {
		return
	}
	user, err := s.userProvider.GetByID(ctx.Request().Context(), result.UserID)
	if err != nil || user == nil {
		s.logger.Error("failed to load user presentation preferences", "user", result.UserID, "error", err)
		return
	}
	if user.Attributes == nil {
		user.Attributes = make(map[string]string, len(preferences))
	}
	changed := mergeLoginPresentationPreferences(user.Attributes, preferences)
	if len(changed) == 0 {
		return
	}
	sort.Strings(changed)
	if err := s.userProvider.CreateOrUpdate(ctx.Request().Context(), user); err != nil {
		s.logger.Error("failed to persist user presentation preferences", "user", result.UserID, "error", err)
		return
	}
	// These values are persisted user presentation state only; they do not
	// grant authorization or alter tenant context. Any ordinary profile claim
	// projection remains governed by the existing OIDC scope/claims rules.
	if s.auditor != nil {
		event := &audit.Event{
			Type:     audit.EventUserPrefsUpdated,
			Outcome:  audit.OutcomeSuccess,
			ActorID:  result.UserID,
			ClientID: clientID,
			ActorIP:  audit.ClientIP(ctx.Request()),
		}
		audit.SetMeta(event, "source", "hosted_login")
		audit.SetMeta(event, "changed_fields", strings.Join(changed, ","))
		s.auditor.Record(ctx.Request().Context(), event)
	}
}

func mergeLoginPresentationPreferences(
	attributes, preferences map[string]string,
) []string {
	changed := make([]string, 0, len(preferences)+1)
	for key, value := range preferences {
		if key == core.LegacyThemeModePreferenceKey &&
			attributes[core.PreferenceThemeModeKey] != value {
			attributes[core.PreferenceThemeModeKey] = value
			changed = append(changed, core.PreferenceThemeModeKey)
		}
		if attributes[key] == value {
			continue
		}
		attributes[key] = value
		changed = append(changed, key)
	}
	return changed
}

func mergeStoredPresentationPreferences(
	current, stored map[string]string,
) map[string]string {
	if current == nil {
		return stored
	}
	merged := make(map[string]string, len(current)+2)
	for key, value := range current {
		merged[key] = value
	}
	if locale := strings.TrimSpace(stored["locale"]); validPresentationLocale(locale) {
		merged["locale"] = locale
	}
	if theme := storedThemeMode(stored); theme != "" {
		merged[core.PreferenceThemeModeKey] = theme
		merged[core.LegacyThemeModePreferenceKey] = theme
	}
	return merged
}

func validLoginPresentationPreferences(req login.Request) map[string]string {
	preferences := make(map[string]string, 2)
	if locale := strings.TrimSpace(req.PresentationLocale); validPresentationLocale(locale) {
		preferences["locale"] = locale
	}
	if theme := strings.TrimSpace(req.PresentationThemeMode); theme == "light" || theme == "dark" || theme == "auto" {
		// Keep the legacy key in this map so existing audit and compatibility
		// expectations remain stable; applyLogin mirrors it to the generic key.
		preferences[core.LegacyThemeModePreferenceKey] = theme
	}
	return preferences
}

func storedThemeMode(attributes map[string]string) string {
	generic := strings.TrimSpace(attributes[core.PreferenceThemeModeKey])
	legacy := strings.TrimSpace(attributes[core.LegacyThemeModePreferenceKey])
	genericValid := validStoredThemeMode(generic)
	legacyValid := validStoredThemeMode(legacy)
	if genericValid && legacyValid && generic != legacy {
		return ""
	}
	if genericValid {
		return generic
	}
	if legacyValid {
		return legacy
	}
	return ""
}

func validStoredThemeMode(value string) bool {
	return value == "light" || value == "dark" || value == "auto"
}

var loginPresentationLocalePattern = regexp.MustCompile(
	`^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$`,
)

func validPresentationLocale(value string) bool {
	return len(value) <= 32 && loginPresentationLocalePattern.MatchString(value)
}
