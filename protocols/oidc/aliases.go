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
)
