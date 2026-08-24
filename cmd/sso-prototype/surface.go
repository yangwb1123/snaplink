package main

import (
	"net/http"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// prototypeHiddenMetadata are the OIDC discovery fields the prototype edition
// must not advertise. The minimal edition retains them; here they are the
// only edition-specific narrowing and the list exists ONLY in this root, so
// the OIDC surface is compiled out of the prototype binary.
var prototypeHiddenMetadata = []string{
	"acr_values_supported",
	"backchannel_logout_session_supported",
	"backchannel_logout_supported",
	"check_session_iframe",
	"claim_types_supported",
	"claims_parameter_supported",
	"claims_supported",
	"display_values_supported",
	"end_session_endpoint",
	"frontchannel_logout_session_supported",
	"frontchannel_logout_supported",
	"id_token_encryption_alg_values_supported",
	"id_token_encryption_enc_values_supported",
	"id_token_signing_alg_values_supported",
	"prompt_values_supported",
	"subject_types_supported",
	"userinfo_encryption_alg_values_supported",
	"userinfo_encryption_enc_values_supported",
	"userinfo_endpoint",
	"userinfo_signing_alg_values_supported",
}

// prototypeMetadataPath is the prototype discovery surface: the OAuth
// authorization-server metadata only, never the OIDC discovery document.
func prototypeMetadataPath(path string) bool {
	return path == sso.PathOAuthAuthorizationServerMetadata
}

func prototypeNarrowMetadata(document map[string]any) {
	for _, key := range prototypeHiddenMetadata {
		delete(document, key)
	}
}

// prototypeRouteAllowed gates the prototype route table: health/probes/JWKS
// GET, login/token/logout POST, and nothing OIDC (no UserInfo, no
// end-session).
func prototypeRouteAllowed(method, path string) bool {
	if method == http.MethodOptions {
		return prototypePathExists(path)
	}
	switch path {
	case sso.PathHealth, sso.PathLivez, sso.PathReadyz, sso.PathJWKS:
		return method == http.MethodGet
	case sso.PathLogin, sso.PathToken, sso.PathLogout:
		return method == http.MethodPost
	default:
		return false
	}
}

func prototypePathExists(path string) bool {
	return prototypeRouteAllowed(http.MethodGet, path) ||
		prototypeRouteAllowed(http.MethodPost, path) ||
		prototypeMetadataPath(path)
}
