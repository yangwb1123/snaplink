package ssotest

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/cluster"
	clustermemory "github.com/snaplink/sso/cluster/memory"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/tenant"
	tenantmemory "github.com/snaplink/sso/tenant/memory"
)

const (
	ibUserID   = "u-ib"
	ibClientID = "ib-client"
	ibTenantID = "tenant-ib"
)

// newBusReplica builds one "replica" Server sharing the given tenant
// store + invalidation bus, with a deliberately long suspension cache
// TTL so that any cross-node convergence we observe is attributable to
// the bus, not to a TTL expiry.
func newBusReplica(t *testing.T, tstore tenant.Store, bus cluster.Bus, issuer sso.TokenIssuer) *sso.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: ibUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: ibClientID, Active: true, TokenStrategy: "jwt", TenantID: ibTenantID,
	})
	return sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTenantStore(tstore),
		sso.WithTenantSuspensionCheck(time.Hour), // long TTL: only the bus can converge B
		sso.WithInvalidationBus(bus),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
}

// TestInvalidationBus_SuspensionPropagatesAcrossReplicas proves the core
// promise: suspending a tenant + invalidating on replica A makes replica
// B reject that tenant's tokens immediately (via the bus), without
// waiting out B's hour-long suspension cache TTL.
func TestInvalidationBus_SuspensionPropagatesAcrossReplicas(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus := clustermemory.New()
	defer func() { _ = bus.Close() }()

	tstore := tenantmemory.New()
	_ = tstore.PutTenant(ctx, &tenant.Tenant{
		ID: ibTenantID, Slug: "ib", Name: "ib", Status: tenant.StatusActive,
	})
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))

	srvA := newBusReplica(t, tstore, bus, issuer)
	srvB := newBusReplica(t, tstore, bus, issuer)

	doneB, err := srvB.StartInvalidationBus(ctx)
	if err != nil {
		t.Fatalf("start bus on B: %v", err)
	}
	defer func() { cancel(); <-doneB }()

	tok, err := issuer.Issue(ctx, &sso.Subject{ID: ibUserID, ClientID: ibClientID}, []string{"read"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Prime B's cache with the Active status (cache miss → store read → cache put).
	if _, err := srvB.ValidateToken(ctx, tok.AccessToken); err != nil {
		t.Fatalf("B validate while active: %v", err)
	}

	// Suspend in the shared store, then invalidate on A (admin acted on A).
	_ = tstore.PutTenant(ctx, &tenant.Tenant{
		ID: ibTenantID, Slug: "ib", Name: "ib", Status: tenant.StatusSuspended,
	})
	srvA.InvalidateTenantSuspensionCache(ibTenantID)

	// B must converge to "suspended" via the bus despite its hour-long TTL.
	// Poll briefly to absorb the async bus delivery on B's goroutine.
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err = srvB.ValidateToken(ctx, tok.AccessToken)
		if err != nil { // expected: ErrTenantSuspended surfaces here
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("B still served suspended tenant: bus did not propagate invalidation")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestInvalidationBus_DiscoveryReloadAcrossReplicas proves a client
// edit on replica A (which changes the discovery scope union) makes
// replica B re-render its discovery document immediately via the bus,
// instead of waiting out B's hour-long discovery cache TTL.
func TestInvalidationBus_DiscoveryReloadAcrossReplicas(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus := clustermemory.New()
	defer func() { _ = bus.Close() }()

	// Shared client store (cluster-shared backend stand-in).
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "dr-c", Active: true, AllowedScopes: []string{"read"}})

	newReplica := func() *sso.Server {
		return sso.NewServer(
			sso.WithIssuer("https://dr.example"),
			sso.WithClientStore(clients),
			sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
			sso.WithDefaultTokenStrategy("jwt"),
			sso.WithDiscoveryCacheTTL(time.Hour),    // long: only the bus converges B
			sso.WithDiscoveryDocCacheTTL(time.Hour), // long: ditto for the rendered doc
			sso.WithInvalidationBus(bus),
		)
	}
	srvA := newReplica()
	srvB := newReplica()
	doneB, err := srvB.StartInvalidationBus(ctx)
	if err != nil {
		t.Fatalf("start bus on B: %v", err)
	}
	defer func() { cancel(); <-doneB }()

	httpB := httptest.NewServer(srvB.Handler())
	defer httpB.Close()

	// Prime B's discovery cache (does not yet know "write").
	if got := discoveryScopes(t, httpB); scopesContain(got, "write") {
		t.Fatalf("precondition: B already advertises write: %v", got)
	}

	// Admin edits a client on A: add the "write" scope, then invalidate.
	_ = clients.Update(ctx, &sso.Client{ID: "dr-c", Active: true, AllowedScopes: []string{"read", "write"}})
	srvA.InvalidateDiscoveryCache()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if scopesContain(discoveryScopes(t, httpB), "write") {
			return // B converged via the bus
		}
		if time.Now().After(deadline) {
			t.Fatal("B never advertised the new scope: discovery reload did not propagate")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func discoveryScopes(t *testing.T, srv *httptest.Server) []string {
	t.Helper()
	doc := fetchDoc(t, srv)
	raw, _ := doc["scopes_supported"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func scopesContain(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestInvalidationBus_NilBusNoop confirms zero behavior change when no
// bus is wired: StartInvalidationBus returns an already-closed channel
// and InvalidateTenantSuspensionCache still works locally.
func TestInvalidationBus_NilBusNoop(t *testing.T) {
	srv, _, _, _ := newTenantSuspensionHarness(t, time.Minute)
	done, err := srv.StartInvalidationBus(context.Background())
	if err != nil {
		t.Fatalf("start with no bus: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("StartInvalidationBus with no bus should return a closed channel")
	}
	// Must not panic without a bus.
	srv.InvalidateTenantSuspensionCache(tsTenantID)
}
