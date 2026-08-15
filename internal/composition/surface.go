package composition

import (
	"encoding/json"
	"net/http"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	KeyGrantTypes       = "grant_types_supported"
	KeyResponseTypes    = "response_types_supported"
	KeyChallengeMethods = "code_challenge_methods_supported"
	KeyScopes           = "scopes_supported"
	KeyTokenAuthMethods = "token_endpoint_auth_methods_supported"
)

// HiddenMetadataEndpoints are the discovery fields both small editions hide
// (device/introspection/PAR/registration/revocation and friends): the small
// server is authorization-code-only by construction.
var HiddenMetadataEndpoints = []string{
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

// Surface is the edition surface envelope: it intercepts the discovery
// document and the route table before they reach the SDK server, using the
// edition hooks supplied by the composition root.
type Surface struct {
	next   http.Handler
	scopes []string
	hooks  SurfaceHooks
}

// NewSurface wraps next with the small-edition surface envelope. scopes are
// the configured client scopes advertised in the discovery document; hooks
// carry the edition-specific metadata/route behavior.
func NewSurface(next http.Handler, scopes []string, hooks SurfaceHooks) http.Handler {
	return &Surface{
		next:   next,
		scopes: append([]string(nil), scopes...),
		hooks:  hooks,
	}
}

func (h *Surface) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.hooks.IsMetadata != nil && h.hooks.IsMetadata(r.URL.Path) {
		h.serveMetadata(w, r)
		return
	}
	if h.hooks.Allowed != nil && !h.hooks.Allowed(r.Method, r.URL.Path) {
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

func (h *Surface) serveMetadata(w http.ResponseWriter, r *http.Request) {
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
	if h.hooks.Narrow != nil {
		h.hooks.Narrow(document)
	}
	response.body.Reset()
	_ = json.NewEncoder(&response.body).Encode(document)
	response.header.Del("Content-Length")
	response.flushTo(w)
}

// narrowMetadata applies the edition-generic narrowing both editions share.
func narrowMetadata(document map[string]any, scopes []string) {
	document[KeyGrantTypes] = []string{"authorization_code"}
	document[KeyResponseTypes] = []string{"code"}
	document[KeyChallengeMethods] = []string{sso.PKCEMethodS256}
	document[KeyScopes] = append([]string(nil), scopes...)
	document[KeyTokenAuthMethods] = []string{
		"client_secret_basic",
		"client_secret_post",
	}
	document["request_parameter_supported"] = false
	document["request_uri_parameter_supported"] = false
	for _, key := range HiddenMetadataEndpoints {
		delete(document, key)
	}
}

// ConfiguredScopes returns the deduplicated union of the configured client
// scopes, in first-seen order.
func ConfiguredScopes(clients []ClientSeed) []string {
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
