package sso_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

func newACRValuesSupportedHarness(t *testing.T, values []string) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "test", Active: true, TokenStrategy: "jwt"})
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if values != nil {
		opts = append(opts, sso.WithSupportedACRValues(values...))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	_ = context.Background()
	return httpSrv
}

func TestACRValuesSupported_AdvertisedInDiscovery(t *testing.T) {
	values := []string{
		"urn:mace:incommon:iap:bronze",
		"urn:mace:incommon:iap:silver",
		"urn:level:high",
	}
	srv := newACRValuesSupportedHarness(t, values)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	raw, ok := doc["acr_values_supported"].([]any)
	if !ok {
		t.Fatalf("acr_values_supported missing: %v", doc)
	}
	got := make([]string, 0, len(raw))
	for _, v := range raw {
		got = append(got, v.(string))
	}
	sort.Strings(got)
	want := append([]string(nil), values...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("acr_values_supported = %v want %v", got, want)
	}
}

func TestACRValuesSupported_OmittedWhenUnset(t *testing.T) {
	srv := newACRValuesSupportedHarness(t, nil)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if _, present := doc["acr_values_supported"]; present {
		t.Errorf("acr_values_supported leaked when unset")
	}
}

func TestACRValuesSupported_DedupesAndDropsEmpty(t *testing.T) {
	// Empty strings and duplicates MUST be filtered — discovery
	// is supposed to advertise a clean set.
	srv := newACRValuesSupportedHarness(t, []string{"a", "", "b", "a", "c", ""})
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	raw := doc["acr_values_supported"].([]any)
	got := make([]string, 0, len(raw))
	for _, v := range raw {
		got = append(got, v.(string))
	}
	sort.Strings(got)
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got = %v want %v (dedupe + empty drop)", got, want)
	}
}
