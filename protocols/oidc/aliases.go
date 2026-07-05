package oidc

// The stateless OIDC protocol helpers (form-post rendering, prompt parsing,
// discovery-doc cache, discovery option lists, userinfo claim projection) live
// in the oidcsupport leaf so this directory stays within the per-directory
// file-count budget. These aliases preserve the historical oidc.* import
// surface unchanged for the Server wiring, the signing-backend implementations,
// and any SDK consumer.

import "github.com/snaplink/sso/protocols/oidc/oidcsupport"

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
