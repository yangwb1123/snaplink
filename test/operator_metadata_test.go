package ssotest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

func newOpMetadataHarness(t *testing.T, opts ...sso.Option) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	base := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	server := sso.NewServer(append(base, opts...)...)
	srv := httptest.NewServer(server.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func TestOperatorMetadata_AdvertisedWhenSet(t *testing.T) {
	srv := newOpMetadataHarness(t, sso.WithOperatorMetadata(
		"https://acme.example/oidc-policy",
		"https://acme.example/oidc-tos",
		"https://acme.example/sso-docs",
	))
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if doc["op_policy_uri"] != "https://acme.example/oidc-policy" {
		t.Errorf("op_policy_uri = %v", doc["op_policy_uri"])
	}
	if doc["op_tos_uri"] != "https://acme.example/oidc-tos" {
		t.Errorf("op_tos_uri = %v", doc["op_tos_uri"])
	}
	if doc["service_documentation"] != "https://acme.example/sso-docs" {
		t.Errorf("service_documentation = %v", doc["service_documentation"])
	}
}

func TestOperatorMetadata_OmittedWhenUnset(t *testing.T) {
	srv := newOpMetadataHarness(t)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	for _, f := range []string{"op_policy_uri", "op_tos_uri", "service_documentation"} {
		if _, present := doc[f]; present {
			t.Errorf("%s leaked when unset: %v", f, doc[f])
		}
	}
}

func TestOperatorMetadata_PartialFieldsAcceptedIndividually(t *testing.T) {
	// Setting only policy URI omits the others (omitempty).
	srv := newOpMetadataHarness(t, sso.WithOperatorMetadata(
		"https://acme.example/policy", "", "",
	))
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if doc["op_policy_uri"] != "https://acme.example/policy" {
		t.Errorf("policy = %v", doc["op_policy_uri"])
	}
	if _, present := doc["op_tos_uri"]; present {
		t.Errorf("op_tos_uri leaked when empty: %v", doc["op_tos_uri"])
	}
}
