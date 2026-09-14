package sso_test

import (
	"net/http"
	"testing"
)

func TestRcovDiscoveryPublicRevokeAuthDoesNotEnablePublicIntrospection(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	var doc map[string]any
	resp := rcovGetJSON(t, s.http.URL+"/.well-known/openid-configuration", &doc)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status=%d, want 200", resp.StatusCode)
	}
	if !discoveryHasAuthMethod(doc["revocation_endpoint_auth_methods_supported"], "none") {
		t.Fatal("revocation discovery does not advertise public-client none auth")
	}
	if discoveryHasAuthMethod(doc["introspection_endpoint_auth_methods_supported"], "none") {
		t.Fatal("introspection discovery must not advertise public-client none auth")
	}
	for _, endpoint := range []string{"revocation_endpoint_auth_methods_supported", "introspection_endpoint_auth_methods_supported"} {
		for _, method := range []string{"tls_client_auth", "self_signed_tls"} {
			if discoveryHasAuthMethod(doc[endpoint], method) {
				t.Errorf("%s must not advertise unsupported %s authentication", endpoint, method)
			}
		}
	}
}

func discoveryHasAuthMethod(raw any, want string) bool {
	methods, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, method := range methods {
		if method == want {
			return true
		}
	}
	return false
}
