package drtest

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/dr"
)

// Scenario (c): a token minted with the PRE-failover signing key still verifies
// on the DR side after a control-plane restore. Signing-key material is NOT
// carried in the control-plane snapshot (see interfaces/snapshot package doc);
// the DR instance holds the primary's public key independently via the
// leaderless verify-key adoption path. This asserts a restore never disturbs
// that key set — the edge case in docs/dr-framework.md: "the DR region must
// retain the primary region's signing public keys."
func TestDrill_SigningKeysIntactPostRestore(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Primary issuer mints a token pre-failover.
	primaryIssuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://primary.example"),
		defaultimpl.WithEd25519TokenTTL(time.Hour),
	)
	tok, err := primaryIssuer.Issue(ctx, &sso.Subject{ID: "u1", ClientID: "alpha"}, []string{"a:read"})
	if err != nil {
		t.Fatalf("primary Issue: %v", err)
	}

	// DR-side issuer runs its OWN signing key but adopts the primary's public
	// key for verification (the leaderless aggregation model).
	drIssuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://dr.example"),
	)
	if err := drIssuer.AdoptVerifyKey(primaryIssuer.KeyID(), primaryIssuer.PublicKey()); err != nil {
		t.Fatalf("AdoptVerifyKey: %v", err)
	}

	// Fail over: replicate + restore the control plane.
	if err := h.replicator.ReplicateOnce(ctx); err != nil {
		t.Fatalf("ReplicateOnce: %v", err)
	}
	if rep := h.orchestrator(t, &dr.MemoryReplicaPromoter{}).Run(ctx); !rep.Succeeded {
		t.Fatalf("drill failed: %+v", rep)
	}

	// The pre-failover token must still verify on the DR side.
	claims, err := drIssuer.Validate(ctx, tok.AccessToken)
	if err != nil {
		t.Fatalf("pre-failover token failed to verify on DR after restore: %v", err)
	}
	if claims.Subject != "u1" {
		t.Errorf("verified token subject = %q, want u1", claims.Subject)
	}
}

// Scenario (d): the audit hash chain stays continuous across a restore. The
// audit chain is a property of the recording instance, not the control-plane
// snapshot; a DR restore must not break it. Record events, run the drill,
// record more, then walk the whole chain oldest-first and verify it.
func TestDrill_AuditChainContinuousAcrossRestore(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	sink := audit.NewMemorySink(0)
	rec := audit.New(sink, audit.WithHashChain())

	recordN(ctx, rec, 3) // pre-failover
	if err := h.replicator.ReplicateOnce(ctx); err != nil {
		t.Fatalf("ReplicateOnce: %v", err)
	}
	if rep := h.orchestrator(t, &dr.MemoryReplicaPromoter{}).Run(ctx); !rep.Succeeded {
		t.Fatalf("drill failed: %+v", rep)
	}
	recordN(ctx, rec, 3) // post-failover

	// MemorySink returns newest-first; VerifyChain wants oldest-first.
	events, err := sink.Query(ctx, audit.Query{Limit: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 6 {
		t.Fatalf("recorded %d events, want 6", len(events))
	}
	reverse(events)
	if err := audit.VerifyChain(events); err != nil {
		t.Fatalf("audit chain broke across the restore: %v", err)
	}
}

func recordN(ctx context.Context, rec *audit.Recorder, n int) {
	for i := 0; i < n; i++ {
		rec.Record(ctx, &audit.Event{Type: audit.EventPermissionQuery, Outcome: audit.OutcomeSuccess, ActorID: "op"})
	}
}

func reverse(evs []*audit.Event) {
	for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
		evs[i], evs[j] = evs[j], evs[i]
	}
}
