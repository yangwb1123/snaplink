package txntoken_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/protocols/oauth/txntoken"
	"github.com/yangwb1123/snaplink/shared/core"
)

const testTrustDomain = "example.internal"

func newTestIssuer(t *testing.T, opts ...txntoken.IssuerOption) (*defaultimpl.Ed25519JWTIssuer, *txntoken.Issuer) {
	t.Helper()
	signer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("tts.example"))
	iss := txntoken.NewIssuer(signer, testTrustDomain, opts...)
	return signer, iss
}

func TestIssuer_MintFirstHop(t *testing.T) {
	_, iss := newTestIssuer(t)
	signed, claims, err := iss.Mint(context.Background(), txntoken.MintRequest{
		Subject:              "alice",
		RequestingWorkload:   "checkout-svc",
		TrustDomain:          testTrustDomain,
		Purpose:              "order.create",
		RequestContext:       json.RawMessage(`{"trace_id":"abc"}`),
		AuthorizationDetails: json.RawMessage(`[{"type":"payment"}]`),
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if signed == "" {
		t.Fatal("Mint returned empty token")
	}
	if claims.Sub != "alice" {
		t.Errorf("Sub = %q, want alice", claims.Sub)
	}
	if claims.Aud != testTrustDomain {
		t.Errorf("Aud = %q, want %q", claims.Aud, testTrustDomain)
	}
	if claims.Txn == "" {
		t.Error("Txn (transaction id) must be set")
	}
	if claims.Purp != "order.create" {
		t.Errorf("Purp = %q", claims.Purp)
	}
	if claims.Act == nil || claims.Act.Subject != "checkout-svc" {
		t.Errorf("Act = %+v, want outermost subject checkout-svc", claims.Act)
	}
	if claims.Act.Actor != nil {
		t.Errorf("first-hop Act must have no nested actor, got %+v", claims.Act.Actor)
	}
}

// TestIssuer_MintNestedHopPrependsChain mirrors RFC 8693 §4.1.1's act-chain
// prepend (tokengrant.tokExResolveActor): minting a Txn-Token FROM an
// existing Txn-Token's chain must ADD a new outermost link without losing
// the earlier ones, and the subject must NOT change across hops.
func TestIssuer_MintNestedHopPrependsChain(t *testing.T) {
	_, iss := newTestIssuer(t)
	_, first, err := iss.Mint(context.Background(), txntoken.MintRequest{
		Subject:            "alice",
		RequestingWorkload: "checkout-svc",
		TrustDomain:        testTrustDomain,
	})
	if err != nil {
		t.Fatalf("first Mint: %v", err)
	}

	_, second, err := iss.Mint(context.Background(), txntoken.MintRequest{
		Subject:            first.Sub, // principal carries through unchanged
		RequestingWorkload: "inventory-svc",
		PriorChain:         first.Act,
		TrustDomain:        testTrustDomain,
	})
	if err != nil {
		t.Fatalf("second Mint: %v", err)
	}
	if second.Sub != "alice" {
		t.Errorf("nested Sub = %q, want unchanged alice", second.Sub)
	}
	if second.Act == nil || second.Act.Subject != "inventory-svc" {
		t.Fatalf("nested Act = %+v, want outermost subject inventory-svc", second.Act)
	}
	if second.Act.Actor == nil || second.Act.Actor.Subject != "checkout-svc" {
		t.Fatalf("nested Act.Actor = %+v, want nested subject checkout-svc", second.Act.Actor)
	}
}

func TestIssuer_MintChainTooDeepFails(t *testing.T) {
	_, iss := newTestIssuer(t)
	var chain *core.ActorClaim
	for i := 0; i < txntoken.MaxChainDepth; i++ {
		chain = &core.ActorClaim{Subject: "hop", Actor: chain}
	}
	_, _, err := iss.Mint(context.Background(), txntoken.MintRequest{
		Subject:            "alice",
		RequestingWorkload: "one-too-many-svc",
		PriorChain:         chain,
		TrustDomain:        testTrustDomain,
	})
	if err == nil {
		t.Fatal("expected ErrChainTooDeep, got nil")
	}
}

func TestIssuer_MintWrongTrustDomainFails(t *testing.T) {
	_, iss := newTestIssuer(t)
	_, _, err := iss.Mint(context.Background(), txntoken.MintRequest{
		Subject:     "alice",
		TrustDomain: "some-other-domain",
	})
	if err == nil {
		t.Fatal("expected an error for a mismatched trust domain")
	}
}

func TestIssuer_MintRequiresSubject(t *testing.T) {
	_, iss := newTestIssuer(t)
	_, _, err := iss.Mint(context.Background(), txntoken.MintRequest{TrustDomain: testTrustDomain})
	if err == nil {
		t.Fatal("expected an error for an empty subject")
	}
}

func TestIssuer_DefaultTTLIsShort(t *testing.T) {
	_, iss := newTestIssuer(t)
	_, claims, err := iss.Mint(context.Background(), txntoken.MintRequest{
		Subject: "alice", TrustDomain: testTrustDomain,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	ttl := time.Unix(claims.Exp, 0).Sub(time.Unix(claims.Iat, 0))
	if ttl != txntoken.DefaultTTL {
		t.Errorf("ttl = %v, want DefaultTTL %v", ttl, txntoken.DefaultTTL)
	}
	if ttl > time.Minute {
		t.Errorf("ttl = %v is not short-lived", ttl)
	}
}
