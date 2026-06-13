package ssotest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/cluster"
	clustermemory "github.com/snaplink/sso/cluster/memory"
	"github.com/snaplink/sso/defaultimpl"
)

// Part 2 — opt-in cross-replica access-token revocation propagation.
//
// Each replica gets its OWN issuer instance (its own in-process deny-set) built
// from the SAME signing key, so a token issued by either validates on both, but
// a revoke on A's deny-set is NOT automatically visible to B's — exactly the
// real multi-process condition the bus must close.

const (
	crrUserID   = "u-crr"
	crrClientID = "crr-client"
)

// newRevocationIssuer builds an Ed25519 issuer pinned to priv (so two replicas
// share the verification key + kid but have independent deny-sets).
func newRevocationIssuer(priv ed25519.PrivateKey) *defaultimpl.Ed25519JWTIssuer {
	return defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Key(priv),
		defaultimpl.WithEd25519TokenTTL(time.Hour), // long TTL: only revocation, not expiry, can reject
	)
}

// newRevocationReplica builds one "replica" Server wired to the shared bus +
// its own issuer. crossReplica toggles WithCrossReplicaRevocation so the
// unarmed/byte-identical path is testable on the same harness.
func newRevocationReplica(t *testing.T, bus cluster.Bus, issuer sso.TokenIssuer, crossReplica bool) *sso.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: crrUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: crrClientID, Active: true, TokenStrategy: "jwt"})

	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithInvalidationBus(bus),
	}
	if crossReplica {
		opts = append(opts, sso.WithCrossReplicaRevocation())
	}
	return sso.NewServer(opts...)
}

// countingBus wraps the real in-process memory bus and counts Publish calls. It
// is NOT a mock — it delegates every method to a genuine clustermemory.Bus and
// merely instruments Publish so a test can assert "exactly one bus message"
// (proving the adopt path never re-publishes).
type countingBus struct {
	*clustermemory.Bus
	mu        sync.Mutex
	published int
}

func newCountingBus() *countingBus { return &countingBus{Bus: clustermemory.New()} }

func (b *countingBus) Publish(ctx context.Context, evt cluster.Event) error {
	b.mu.Lock()
	b.published++
	b.mu.Unlock()
	return b.Bus.Publish(ctx, evt)
}

func (b *countingBus) publishCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.published
}

// TestCrossReplicaRevocation_PropagatesAndRejectsOnPeer is the core promise:
// revoke a token on A → after the bus delivers, B's Validate rejects it, even
// though B's own deny-set started empty. Also locks the ORACLE-SAFE gate (B's
// rejection is the ordinary invalid-token error, no new wire/code path).
func TestCrossReplicaRevocation_PropagatesAndRejectsOnPeer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus := clustermemory.New()
	defer func() { _ = bus.Close() }()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	issuerA := newRevocationIssuer(priv)
	issuerB := newRevocationIssuer(priv)

	srvA := newRevocationReplica(t, bus, issuerA, true)
	srvB := newRevocationReplica(t, bus, issuerB, true)

	doneB, err := srvB.StartInvalidationBus(ctx)
	if err != nil {
		t.Fatalf("start bus on B: %v", err)
	}
	defer func() { cancel(); <-doneB }()

	tok, err := issuerA.Issue(ctx, &sso.Subject{ID: crrUserID, ClientID: crrClientID}, []string{"read"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Precondition: B accepts the token (shared key, empty deny-set).
	if _, err := srvB.ValidateToken(ctx, tok.AccessToken); err != nil {
		t.Fatalf("B should accept the token before revocation: %v", err)
	}

	// Revoke on A through the user-driven seam (the /token/revoke path), which
	// publishes when armed.
	revoked, failed := srvA.RevokeAcrossIssuers(ctx, tok.AccessToken)
	if len(revoked) == 0 || len(failed) != 0 {
		t.Fatalf("A revoke: revoked=%v failed=%v", revoked, failed)
	}
	// A rejects it immediately (local revoke).
	if _, err := srvA.ValidateToken(ctx, tok.AccessToken); err == nil {
		t.Fatal("A must reject its own just-revoked token")
	}

	// B must converge to "revoked" via the bus.
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err = srvB.ValidateToken(ctx, tok.AccessToken)
		if err != nil {
			break // expected: B now rejects the propagated revocation
		}
		if time.Now().After(deadline) {
			t.Fatal("B still accepts the revoked token: bus did not propagate the revocation")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// ORACLE-SAFE: B's error is the ordinary issuer "token revoked"/invalid-token
	// failure, indistinguishable in shape from any other validation failure (the
	// caller only ever sees invalid_token at the wire). We assert it is a plain
	// error here; the wire-level invalid_token mapping is covered by the
	// /userinfo + introspection suites.
	if _, err := srvB.ValidateToken(ctx, tok.AccessToken); err == nil {
		t.Fatal("B must keep rejecting the revoked token")
	}
}

// TestCrossReplicaRevocation_NoBroadcastLoop proves the adopt path does NOT
// re-publish: a single local revoke on A yields EXACTLY ONE bus Publish, even
// though B (and A) both receive + apply it. A re-broadcasting adopt would show
// >1 publish (and storm).
func TestCrossReplicaRevocation_NoBroadcastLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus := newCountingBus()
	defer func() { _ = bus.Close() }()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	issuerA := newRevocationIssuer(priv)
	issuerB := newRevocationIssuer(priv)

	srvA := newRevocationReplica(t, bus, issuerA, true)
	srvB := newRevocationReplica(t, bus, issuerB, true)

	// BOTH replicas subscribe — so if either's adopt re-published, the other
	// would receive it and re-adopt, compounding the publish count.
	doneA, err := srvA.StartInvalidationBus(ctx)
	if err != nil {
		t.Fatalf("start bus on A: %v", err)
	}
	doneB, err := srvB.StartInvalidationBus(ctx)
	if err != nil {
		t.Fatalf("start bus on B: %v", err)
	}
	defer func() { cancel(); <-doneA; <-doneB }()

	tok, err := issuerA.Issue(ctx, &sso.Subject{ID: crrUserID, ClientID: crrClientID}, []string{"read"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	if revoked, _ := srvA.RevokeAcrossIssuers(ctx, tok.AccessToken); len(revoked) == 0 {
		t.Fatal("A revoke hit no issuer")
	}

	// Wait for B to converge (so any re-broadcast would have had time to fire).
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := srvB.ValidateToken(ctx, tok.AccessToken); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("B never converged")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Give any erroneous re-broadcast extra time to surface before counting.
	time.Sleep(100 * time.Millisecond)

	if n := bus.publishCount(); n != 1 {
		t.Fatalf("expected EXACTLY ONE bus publish (no re-broadcast loop), got %d", n)
	}
}

// TestCrossReplicaRevocation_PublishFailOpen proves a publish-side bus error
// does NOT break the local revoke: the token is still revoked on A even when
// the bus rejects the Publish (the local deny-set add already happened).
func TestCrossReplicaRevocation_PublishFailOpen(t *testing.T) {
	ctx := context.Background()

	bus := clustermemory.New()
	_ = bus.Close() // closed bus: every Publish returns ErrClosed (fail-open path)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	issuerA := newRevocationIssuer(priv)
	srvA := newRevocationReplica(t, bus, issuerA, true)

	tok, err := issuerA.Issue(ctx, &sso.Subject{ID: crrUserID, ClientID: crrClientID}, []string{"read"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Revoke must SUCCEED locally despite the publish error.
	revoked, failed := srvA.RevokeAcrossIssuers(ctx, tok.AccessToken)
	if len(revoked) == 0 || len(failed) != 0 {
		t.Fatalf("local revoke must succeed despite publish error: revoked=%v failed=%v", revoked, failed)
	}
	if _, err := srvA.ValidateToken(ctx, tok.AccessToken); err == nil {
		t.Fatal("A must reject the locally-revoked token even when the bus publish failed")
	}
}

// TestCrossReplicaRevocation_UnarmedNoop is the ADDITIVE / byte-identical gate:
// with WithCrossReplicaRevocation NOT armed (default), a revoke on A does NOT
// propagate — B keeps accepting the token (per-replica behavior, identical to a
// build without the feature). Revocation is purely additive: never armed ⇒ B
// simply doesn't add the token, never wrongly rejects a valid one.
func TestCrossReplicaRevocation_UnarmedNoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus := clustermemory.New()
	defer func() { _ = bus.Close() }()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	issuerA := newRevocationIssuer(priv)
	issuerB := newRevocationIssuer(priv)

	// UNARMED on both (crossReplica=false) — bus is still wired (for other kinds).
	srvA := newRevocationReplica(t, bus, issuerA, false)
	srvB := newRevocationReplica(t, bus, issuerB, false)

	doneB, err := srvB.StartInvalidationBus(ctx)
	if err != nil {
		t.Fatalf("start bus on B: %v", err)
	}
	defer func() { cancel(); <-doneB }()

	tok, err := issuerA.Issue(ctx, &sso.Subject{ID: crrUserID, ClientID: crrClientID}, []string{"read"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	if revoked, _ := srvA.RevokeAcrossIssuers(ctx, tok.AccessToken); len(revoked) == 0 {
		t.Fatal("A revoke hit no issuer")
	}
	// A rejects locally (local deny-set always works).
	if _, err := srvA.ValidateToken(ctx, tok.AccessToken); err == nil {
		t.Fatal("A must reject its own revoked token")
	}

	// B must KEEP ACCEPTING — unarmed ⇒ no propagation. Give the bus ample time
	// to (not) deliver an adopt before asserting.
	time.Sleep(250 * time.Millisecond)
	if _, err := srvB.ValidateToken(ctx, tok.AccessToken); err != nil {
		t.Fatalf("unarmed B must still accept the token (byte-identical off): %v", err)
	}
}
