package main

import (
	"net/http"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// minimalMetadataPath is the minimal discovery surface: OAuth
// authorization-server metadata plus the OIDC discovery document.
func minimalMetadataPath(path string) bool {
	if path == sso.PathOAuthAuthorizationServerMetadata {
		return true
	}
	return path == sso.PathOIDCDiscovery
}

// minimalNarrowMetadata retains the OIDC discovery fields — nothing
// edition-specific to strip beyond the shared narrowing.
func minimalNarrowMetadata(map[string]any) {}

// minimalRouteAllowed gates the minimal route table: health/probes/JWKS GET,
// login/token/logout POST, plus the OIDC surface (UserInfo and end-session
// GET).
func minimalRouteAllowed(method, path string) bool {
	if method == http.MethodOptions {
		return minimalPathExists(path)
	}
	switch path {
	case sso.PathHealth, sso.PathLivez, sso.PathReadyz, sso.PathJWKS:
		return method == http.MethodGet
	case sso.PathLogin, sso.PathToken, sso.PathLogout:
		return method == http.MethodPost
	case sso.PathUserInfo, sso.PathEndSession:
		return method == http.MethodGet
	default:
		return false
	}
}

func minimalPathExists(path string) bool {
	return minimalRouteAllowed(http.MethodGet, path) ||
		minimalRouteAllowed(http.MethodPost, path) ||
		minimalMetadataPath(path)
}
