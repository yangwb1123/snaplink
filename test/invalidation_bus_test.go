package ssotest

import (
	"context"
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
	defer bus.Close()

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
