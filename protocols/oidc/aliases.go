package oidc

// The stateless OIDC protocol helpers (form-post rendering, prompt parsing,
// discovery-doc cache, discovery option lists, userinfo claim projection) live
// in the oidcsupport leaf so this directory stays within the per-directory
// file-count budget. These aliases preserve the historical oidc.* import
// surface unchanged for the Server wiring, the signing-backend implementations,
// and any SDK consumer.

import (
	"github.com/yangwb1123/snaplink/protocols/oidc/oidcsupport"
	"github.com/yangwb1123/snaplink/shared/core"
)

type (
	FormPostData         = oidcsupport.FormPostData
	SilentRenewalRequest = oidcsupport.SilentRenewalRequest
	DocEntry             = oidcsupport.DocEntry
)

const (
	DefaultDocCacheTTL   = oidcsupport.DefaultDocCacheTTL
	ResponseModeQuery    = oidcsupport.ResponseModeQuery
	ResponseModeFragment = oidcsupport.ResponseModeFragment
	ResponseModeFormPost = oidcsupport.ResponseModeFormPost
	// CheckSessionCookieName re-exports the OpenID Connect Session
	// Management 1.0 browser-state cookie name (see check_session_iframe.go)
	// so the Server wiring can stamp/clear it without importing oidcsupport
	// directly.
	CheckSessionCookieName = oidcsupport.CheckSessionCookieName
)

var (
	RenderFormPostResponse  = oidcsupport.RenderFormPostResponse
	ParsePromptValues       = oidcsupport.ParsePromptValues
	PromptHasNone           = oidcsupport.PromptHasNone
	ScopeContainsOpenID     = oidcsupport.ScopeContainsOpenID
	BuildDocEntry           = oidcsupport.BuildDocEntry
	WriteDoc                = oidcsupport.WriteDoc
	CodeChallengeMethodsFor = oidcsupport.CodeChallengeMethodsFor
	ResponseTypesFor        = oidcsupport.ResponseTypesFor
	SubjectTypesFor         = oidcsupport.SubjectTypesFor
	IsValidResponseMode     = oidcsupport.IsValidResponseMode
	ProjectUserInfoForOIDC  = oidcsupport.ProjectUserInfoForOIDC
	ProjectIDTokenClaims    = oidcsupport.ProjectIDTokenClaims
	SanitizeUserForUserInfo = oidcsupport.SanitizeUserForUserInfo
	// OpenID Connect Session Management 1.0 §2/§3 — see session_state.go /
	// check_session_iframe.go in oidcsupport for the implementation.
	BuildSessionState        = oidcsupport.BuildSessionState
	OriginFromURL            = oidcsupport.OriginFromURL
	RenderCheckSessionIframe = oidcsupport.RenderCheckSessionIframe
)

// RoutesDeps is the union of the UserInfo and EndSession handler deps plus
// the session-management opt-in flag the mount branches on. *sso.Server
// satisfies it via accessors.
type RoutesDeps interface {
	UserInfoDeps
	EndSessionDeps
	// SessionManagementEnabled reports whether WithOIDCSessionManagement
	// was wired — the boot-time condition for mounting the
	// check_session_iframe route.
	SessionManagementEnabled() bool
}

// MountRoutes registers the OIDC user-facing endpoints (GET /userinfo,
// GET /end_session, and the session-management-gated
// GET /check_session_iframe) on r, wrapped in a core.GatedRouter so the
// routes hot-toggle with the OIDC feature gate exactly as they did when
// registered from interfaces/sso (mountOIDCUserEndpoints). The JWKS route
// stays registered by interfaces/sso beside its handler. gate must be
// non-nil — the Server's live oidcGateOn method value; nil is a programmer
// error.
func MountRoutes(r core.Router, d RoutesDeps, gate func() bool) {
	if gate == nil {
		panic("oidc: MountRoutes requires a non-nil gate")
	}
	gr := core.NewGatedRouter(r, gate)
	gr.GET(core.PathUserInfo, func(ctx core.HandlerContext) { HandleUserInfo(d, ctx) })
	gr.GET(core.PathEndSession, func(ctx core.HandlerContext) { HandleEndSession(d, ctx) })
	if d.SessionManagementEnabled() {
		gr.GET(core.PathCheckSessionIframe, func(ctx core.HandlerContext) { HandleCheckSessionIframe(ctx) })
	}
}
