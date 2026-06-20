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

	want := []string{"client_secret_basic", "client_secret_post", "private_key_jwt"}
	sort.Strings(want)

	for _, field := range []string{
		"introspection_endpoint_auth_methods_supported",
		"revocation_endpoint_auth_methods_supported",
		"pushed_authorization_request_endpoint_auth_methods_supported",
	} {
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
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v want %v", field, got, want)
		}
	}
}
