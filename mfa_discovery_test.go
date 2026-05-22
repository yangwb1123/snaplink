package sso_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

// stubDiscoveryProvider is a minimal MFAProvider that lets the
// discovery test pin the wire shape without pulling in the
// concrete TOTP / WebAuthn / Push impls — keeps the test focused
// on the discovery code rather than the provider integration.
type stubDiscoveryProvider struct {
	methods []string
}

func (s *stubDiscoveryProvider) SupportedMethods() []string { return s.methods }
func (s *stubDiscoveryProvider) Verify(_ context.Context, _, _ string, _ map[string]string) error {
	return nil
}

func newDiscoveryHarness(t *testing.T, provider sso.MFAProvider) *httptest.Server {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "test", Active: true, TokenStrategy: "jwt"})
	opts := []sso.Option{
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if provider != nil {
		opts = append(opts,
			sso.WithMFAProvider(provider),
			sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), 0),
		)
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func fetchMFADiscovery(t *testing.T, srv *httptest.Server) map[string]any {
	t.Helper()
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	return doc
}

func TestDiscovery_MFAFieldsOmittedWhenUnwired(t *testing.T) {
	// Without WithMFAProvider, the two MFA discovery fields MUST
	// be absent — wire-shape parity with vanilla OIDC discovery so
	// callers that don't speak the extension aren't disturbed.
	srv := newDiscoveryHarness(t, nil)
	doc := fetchMFADiscovery(t, srv)
	if _, present := doc["mfa_endpoint"]; present {
		t.Errorf("mfa_endpoint leaked when no provider wired: %v", doc["mfa_endpoint"])
	}
	if _, present := doc["mfa_methods_supported"]; present {
		t.Errorf("mfa_methods_supported leaked when no provider wired: %v", doc["mfa_methods_supported"])
	}
}

func TestDiscovery_MFAFieldsPresentWhenProviderWired(t *testing.T) {
	srv := newDiscoveryHarness(t, &stubDiscoveryProvider{methods: []string{"totp"}})
	doc := fetchMFADiscovery(t, srv)
	endpoint, ok := doc["mfa_endpoint"].(string)
	if !ok || endpoint == "" {
		t.Fatalf("mfa_endpoint missing or wrong type: %v", doc["mfa_endpoint"])
	}
	if got := endpoint; got[len(got)-9:] != "/auth/mfa" {
		t.Errorf("mfa_endpoint = %q, want suffix /auth/mfa", got)
	}
	raw, ok := doc["mfa_methods_supported"].([]any)
	if !ok {
		t.Fatalf("mfa_methods_supported missing: %v", doc)
	}
	if len(raw) != 1 || raw[0] != "totp" {
		t.Errorf("mfa_methods_supported = %v, want [totp]", raw)
	}
}

func TestDiscovery_MFAMethodsAggregatedForMultiProvider(t *testing.T) {
	// MultiMFAProvider aggregates SupportedMethods across leaves —
	// discovery should reflect every method the composite reports.
	totpLeaf := &stubDiscoveryProvider{methods: []string{"totp"}}
	pushLeaf := &stubDiscoveryProvider{methods: []string{"push"}}
	multi, err := defaultimpl.NewMultiMFAProvider(totpLeaf, pushLeaf)
	if err != nil {
		t.Fatalf("NewMultiMFAProvider: %v", err)
	}
	srv := newDiscoveryHarness(t, multi)
	doc := fetchMFADiscovery(t, srv)
	raw, _ := doc["mfa_methods_supported"].([]any)
	got := make([]string, 0, len(raw))
	for _, v := range raw {
		got = append(got, v.(string))
	}
	sort.Strings(got)
	want := []string{"push", "totp"}
	if len(got) != len(want) {
		t.Fatalf("mfa_methods_supported = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mfa_methods_supported[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestDiscovery_GrantTypesIncludesTokenExchange(t *testing.T) {
	// Wire-shape pin: token-exchange is in SupportedGrants + must
	// appear in grant_types_supported so RPs querying discovery know
	// the URL is accepted at /token.
	srv := newDiscoveryHarness(t, nil)
	doc := fetchMFADiscovery(t, srv)
	raw, _ := doc["grant_types_supported"].([]any)
	found := false
	for _, v := range raw {
		if v == "urn:ietf:params:oauth:grant-type:token-exchange" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("token-exchange not in grant_types_supported: %v", raw)
	}
}

func TestDiscovery_GrantTypesIncludesDeviceCode(t *testing.T) {
	srv := newDiscoveryHarness(t, nil)
	doc := fetchMFADiscovery(t, srv)
	raw, _ := doc["grant_types_supported"].([]any)
	found := false
	for _, v := range raw {
		if v == "urn:ietf:params:oauth:grant-type:device_code" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("device_code not in grant_types_supported: %v", raw)
	}
}
