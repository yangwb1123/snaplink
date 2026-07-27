package main

import (
	"encoding/json"
	"net/http"

	"github.com/snaplink/sso/interfaces/sso"
)

const (
	keyGrantTypes       = "grant_types_supported"
	keyResponseTypes    = "response_types_supported"
	keyChallengeMethods = "code_challenge_methods_supported"
	keyScopes           = "scopes_supported"
	keyTokenAuthMethods = "token_endpoint_auth_methods_supported"
)

var hiddenMetadataEndpoints = []string{
	"backchannel_authentication_endpoint",
	"device_authorization_endpoint",
	"introspection_endpoint",
	"pushed_authorization_request_endpoint",
	"registration_endpoint",
	"revocation_endpoint",
	"introspection_endpoint_auth_methods_supported",
	"introspection_endpoint_auth_signing_alg_values_supported",
	"mtls_endpoint_aliases",
	"pushed_authorization_request_endpoint_auth_methods_supported",
	"pushed_authorization_request_endpoint_auth_signing_alg_values_supported",
	"revocation_endpoint_auth_methods_supported",
	"revocation_endpoint_auth_signing_alg_values_supported",
	"tls_client_certificate_bound_access_tokens",
	"token_endpoint_auth_signing_alg_values_supported",
}

type prototypeSurface struct {
	next   http.Handler
	scopes []string
}

func newPrototypeSurface(next http.Handler, scopes []string) http.Handler {
	return &prototypeSurface{
		next:   next,
		scopes: append([]string(nil), scopes...),
	}
}

func (h *prototypeSurface) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if isMetadataPath(r.URL.Path) {
		h.serveMetadata(w, r)
		return
	}
	if !prototypeRouteAllowed(r.Method, r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == sso.PathToken {
		if !authorizationCodeOnly(w, r) {
			return
		}
	}
	h.next.ServeHTTP(w, r)
}

func (h *prototypeSurface) serveMetadata(w http.ResponseWriter, r *http.Request) {
	response := newBufferedResponse()
	h.next.ServeHTTP(response, r)
	if response.status != http.StatusOK {
		response.flushTo(w)
		return
	}
	document := map[string]any{}
	if json.Unmarshal(response.body.Bytes(), &document) != nil {
		response.flushTo(w)
		return
	}
	narrowMetadata(document, h.scopes)
	response.body.Reset()
	_ = json.NewEncoder(&response.body).Encode(document)
	response.header.Del("Content-Length")
	response.flushTo(w)
}

func narrowMetadata(document map[string]any, scopes []string) {
	document[keyGrantTypes] = []string{"authorization_code"}
	document[keyResponseTypes] = []string{"code"}
	document[keyChallengeMethods] = []string{sso.PKCEMethodS256}
	document[keyScopes] = append([]string(nil), scopes...)
	document[keyTokenAuthMethods] = []string{
		"client_secret_basic",
		"client_secret_post",
	}
	document["request_parameter_supported"] = false
	document["request_uri_parameter_supported"] = false
	for _, key := range hiddenMetadataEndpoints {
		delete(document, key)
	}
}

func configuredScopes(clients []clientSeed) []string {
	seen := make(map[string]struct{})
	scopes := make([]string, 0)
	for _, client := range clients {
		for _, scope := range client.Scopes {
			if _, ok := seen[scope]; ok {
				continue
			}
			seen[scope] = struct{}{}
			scopes = append(scopes, scope)
		}
	}
	return scopes
}

func prototypeRouteAllowed(method, path string) bool {
	if method == http.MethodOptions {
		return prototypePathAllowed(path)
	}
	switch path {
	case sso.PathHealth, sso.PathLivez, sso.PathReadyz, sso.PathJWKS:
		return method == http.MethodGet
	case sso.PathLogin:
		return method == http.MethodPost
	case sso.PathToken, sso.PathLogout:
		return method == http.MethodPost
	case sso.PathUserInfo, sso.PathEndSession:
		return method == http.MethodGet
	default:
		return false
	}
}

func prototypePathAllowed(path string) bool {
	return prototypeRouteAllowed(http.MethodGet, path) ||
		prototypeRouteAllowed(http.MethodPost, path) ||
		isMetadataPath(path)
}

func isMetadataPath(path string) bool {
	return path == sso.PathOIDCDiscovery ||
		path == sso.PathOAuthAuthorizationServerMetadata
}
