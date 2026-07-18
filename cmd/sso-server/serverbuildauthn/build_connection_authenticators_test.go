package serverbuildauthn

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/platform/audit"
)

// testOIDCConnection returns a TypeOIDC connection whose Config carries every
// key NewOIDCFederationAuthenticator requires, so a build succeeds unless a
// test deliberately breaks one key to drive the failure path.
func testOIDCConnection(id, tenantID string) *connections.Connection {
	return &connections.Connection{
		ID:       id,
		TenantID: tenantID,
		Type:     connections.TypeOIDC,
		Enabled:  true,
		Config: map[string]string{
			connections.ConfigKeyOIDCAuthorizationEndpoint: "https://idp.example.test/authorize",
			connections.ConfigKeyOIDCTokenEndpoint:         "https://idp.example.test/token",
			connections.ConfigKeyOIDCClientID:              "upstream-client",
			connections.ConfigKeyOIDCClientSecret:          "upstream-secret",
			connections.ConfigKeyOIDCRedirectURI:           "https://sso.example.test/auth/callback",
			connections.ConfigKeyOIDCScopes:                "openid profile email",
		},
	}
}

func TestConnectionAuthenticatorFactory_BuildsOIDCAuthenticator(t *testing.T) {
	t.Parallel()
	f := NewConnectionAuthenticatorFactory(nil, testLogger(), 0)

	auth, err := f.AuthenticatorFor(context.Background(), testOIDCConnection("conn-okta", "t-acme"))
	if err != nil {
		t.Fatalf("AuthenticatorFor: %v", err)
	}
	// Name MUST be the connection ID — it is the provider value /auth/login
	// dispatches on, and lockout keys / audit trails key off it.
	if got := auth.Name(); got != "conn-okta" {
		t.Errorf("Name() = %q, want the connection id", got)
	}
	loginURL := auth.LoginURL("st-1")
	if !strings.HasPrefix(loginURL, "https://idp.example.test/authorize?") {
		t.Errorf("LoginURL = %q, want the connection's authorization endpoint", loginURL)
	}
	for _, want := range []string{"client_id=upstream-client", "state=st-1", "scope=openid+profile+email"} {
		if !strings.Contains(loginURL, want) {
			t.Errorf("LoginURL %q missing %q", loginURL, want)
		}
	}
}

func TestConnectionAuthenticatorFactory_CacheHitReturnsSameInstance(t *testing.T) {
	t.Parallel()
	f := NewConnectionAuthenticatorFactory(nil, testLogger(), 0)

	// Two independently-constructed but value-identical connections: the
	// cache key must be the config CONTENT (fingerprint), never pointer or
	// map identity — the store clones on every Get.
	a1, err := f.AuthenticatorFor(context.Background(), testOIDCConnection("conn-okta", "t-acme"))
	if err != nil {
		t.Fatalf("first build: %v", err)
	}
	a2, err := f.AuthenticatorFor(context.Background(), testOIDCConnection("conn-okta", "t-acme"))
	if err != nil {
		t.Fatalf("second build: %v", err)
	}
	if a1 != a2 {
		t.Error("unchanged config rebuilt the authenticator, want the cached instance")
	}
}

func TestConnectionAuthenticatorFactory_ConfigChangeForcesRebuild(t *testing.T) {
	t.Parallel()
	f := NewConnectionAuthenticatorFactory(nil, testLogger(), 0)

	a1, err := f.AuthenticatorFor(context.Background(), testOIDCConnection("conn-okta", "t-acme"))
	if err != nil {
		t.Fatalf("first build: %v", err)
	}
	changed := testOIDCConnection("conn-okta", "t-acme")
	changed.Config[connections.ConfigKeyOIDCAuthorizationEndpoint] = "https://idp2.example.test/authorize"
	a2, err := f.AuthenticatorFor(context.Background(), changed)
	if err != nil {
		t.Fatalf("rebuild after config change: %v", err)
	}
	if a1 == a2 {
		t.Fatal("admin config change served the stale cached authenticator")
	}
	// The rebuilt instance must reflect the NEW config, not just be new.
	if url := a2.LoginURL("st"); !strings.HasPrefix(url, "https://idp2.example.test/authorize?") {
		t.Errorf("rebuilt LoginURL = %q, want the updated endpoint", url)
	}
}

func TestConnectionAuthenticatorFactory_SAMLUnsupported(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(16)
	f := NewConnectionAuthenticatorFactory(audit.New(sink), testLogger(), 0)

	c := testOIDCConnection("conn-adfs", "t-acme")
	c.Type = connections.TypeSAML
	if _, err := f.AuthenticatorFor(context.Background(), c); !errors.Is(err, connections.ErrConnectionTypeUnsupported) {
		t.Fatalf("err = %v, want ErrConnectionTypeUnsupported", err)
	}
	// SAML routes through the SAML module's own endpoints by design — it is
	// NOT an operator misconfiguration, so no build-failure event fires.
	if got := sink.Len(); got != 0 {
		t.Errorf("audit events = %d, want 0 for an expected-unsupported type", got)
	}
}

func TestConnectionAuthenticatorFactory_NilConnection(t *testing.T) {
	t.Parallel()
	f := NewConnectionAuthenticatorFactory(nil, testLogger(), 0)
	if _, err := f.AuthenticatorFor(context.Background(), nil); !errors.Is(err, connections.ErrNoConnection) {
		t.Fatalf("err = %v, want ErrNoConnection", err)
	}
}

func TestConnectionAuthenticatorFactory_BuildFailureAudited(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(16)
	f := NewConnectionAuthenticatorFactory(audit.New(sink), testLogger(), 0)

	broken := testOIDCConnection("conn-broken", "t-acme")
	delete(broken.Config, connections.ConfigKeyOIDCClientSecret)

	_, err := f.AuthenticatorFor(context.Background(), broken)
	if err == nil {
		t.Fatal("build succeeded despite missing client secret")
	}
	if errors.Is(err, connections.ErrNoConnection) || errors.Is(err, connections.ErrConnectionTypeUnsupported) {
		t.Fatalf("err = %v, want a build error distinct from the sentinel misses", err)
	}
	// A failed build must not poison the cache: the operator fixing nothing
	// and retrying must fail (and be audited) again, not hit a cached nil.
	if _, err := f.AuthenticatorFor(context.Background(), broken); err == nil {
		t.Fatal("second call succeeded, want the build failure to repeat")
	}

	events, qerr := sink.Query(context.Background(), audit.Query{Limit: 10})
	if qerr != nil {
		t.Fatalf("Query: %v", qerr)
	}
	var failures []*audit.Event
	for _, e := range events {
		if e.Type == audit.EventConnectionAuthenticatorBuildFailed {
			failures = append(failures, e)
		}
	}
	if len(failures) != 2 {
		t.Fatalf("connection_authenticator_build_failed events = %d, want 2 (one per attempt)", len(failures))
	}
	for _, e := range failures {
		if e.Outcome != audit.OutcomeFailure {
			t.Errorf("Outcome = %q, want failure", e.Outcome)
		}
		if e.TenantID != "t-acme" {
			t.Errorf("TenantID = %q, want t-acme", e.TenantID)
		}
		if got := e.Metadata["connection_id"]; got != "conn-broken" {
			t.Errorf("connection_id metadata = %q, want conn-broken", got)
		}
		if e.Metadata["reason"] == "" {
			t.Error("reason metadata empty, want the build error text")
		}
	}
}

func TestConnectionAuthenticatorFactory_EvictionStillResolvesBothConnections(t *testing.T) {
	t.Parallel()
	f := NewConnectionAuthenticatorFactory(nil, testLogger(), 1)
	ctx := context.Background()
	connA := testOIDCConnection("conn-a", "t-a")
	connB := testOIDCConnection("conn-b", "t-b")

	a1, err := f.AuthenticatorFor(ctx, connA)
	if err != nil {
		t.Fatalf("build A: %v", err)
	}
	b1, err := f.AuthenticatorFor(ctx, connB) // evicts A (capacity 1)
	if err != nil {
		t.Fatalf("build B: %v", err)
	}
	if a1.Name() != "conn-a" || b1.Name() != "conn-b" {
		t.Fatalf("names = %q/%q, want conn-a/conn-b", a1.Name(), b1.Name())
	}
	// Eviction is a cache concern only — the evicted connection must still
	// resolve (rebuilt), and the rebuild re-enters the cache.
	a2, err := f.AuthenticatorFor(ctx, connA)
	if err != nil {
		t.Fatalf("rebuild A after eviction: %v", err)
	}
	if a2.Name() != "conn-a" {
		t.Errorf("rebuilt Name() = %q, want conn-a", a2.Name())
	}
	if a2 == a1 {
		t.Error("evicted entry returned the old instance, want a rebuild")
	}
	a3, err := f.AuthenticatorFor(ctx, connA)
	if err != nil {
		t.Fatalf("cached A after rebuild: %v", err)
	}
	if a3 != a2 {
		t.Error("rebuilt entry was not cached")
	}
}

// TestConnectionAuthenticatorFactory_ConcurrentEvictionChurn hammers the
// capacity-1 cache from parallel goroutines so -race proves the login-path
// concurrency contract (AuthenticatorFactory is called per request).
func TestConnectionAuthenticatorFactory_ConcurrentEvictionChurn(t *testing.T) {
	t.Parallel()
	f := NewConnectionAuthenticatorFactory(nil, testLogger(), 1)
	conns := []*connections.Connection{
		testOIDCConnection("conn-a", "t-a"),
		testOIDCConnection("conn-b", "t-b"),
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		c := conns[i%2]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				auth, err := f.AuthenticatorFor(context.Background(), c)
				if err != nil {
					t.Errorf("AuthenticatorFor(%s): %v", c.ID, err)
					return
				}
				if auth.Name() != c.ID {
					t.Errorf("Name() = %q, want %q", auth.Name(), c.ID)
					return
				}
			}
		}()
	}
	wg.Wait()
}
