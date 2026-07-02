package ssotest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

func TestDiscovery_IntrospectionRevocationAuthMethods(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "test", Active: true, TokenStrategy: "jwt"})
	server := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPARStore(defaultimpl.NewMemoryPARStore(), 0),
	)
	srv := httptest.NewServer(server.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)

	want := []string{"client_secret_basic", "client_secret_post", "private_key_jwt",
		"tls_client_auth", "self_signed_tls"}
	sort.Strings(want)

	// token_endpoint_auth_methods_supported additionally advertises "none":
	// RFC 6749 §2.1 / OIDC Core §9 public clients (SPAs, native apps)
	// authenticate only by client_id + PKCE (see
	// server_discovery_config.go:193-199). Introspection/revocation/PAR
	// share the same client-auth pipeline and correctly omit it.
	wantToken := append(append([]string{}, want...), "none")
	sort.Strings(wantToken)

	for _, field := range []string{
		"introspection_endpoint_auth_methods_supported",
		"revocation_endpoint_auth_methods_supported",
		"pushed_authorization_request_endpoint_auth_methods_supported",
		"token_endpoint_auth_methods_supported",
	} {
		fieldWant := want
		if field == "token_endpoint_auth_methods_supported" {
			fieldWant = wantToken
		}
		raw, ok := doc[field].([]any)
		if !ok {
			t.Errorf("%s missing from discovery: %v", field, doc[field])
			continue
		}
		got := make([]string, 0, len(raw))
		for _, v := range raw {
			got = append(got, v.(string))
		}
		sort.Strings(got)
		if !reflect.DeepEqual(got, fieldWant) {
			t.Errorf("%s = %v want %v", field, got, fieldWant)
		}
	}
}
