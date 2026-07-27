package ssotest

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/yangwb1123/snaplink/domains/tokenexchange"
	"github.com/yangwb1123/snaplink/domains/tokenexchange/memory"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// TestTokenExchange_ChainStoreRecordsHopOnSuccess proves the ONE wired call
// site (tokExRecordChainHop in internal/handler/tokengrant/token_exchange.go)
// actually persists a hop to a REAL ChainStore after a successful exchange,
// and that GetChain can look it back up by the minted token's own jti — the
// exact "what produced token X" incident-response query this feature adds.
func TestTokenExchange_ChainStoreRecordsHopOnSuccess(t *testing.T) {
	store := memory.NewChainStore()
	srv := newTokenExchangeChainPolicyHarness(t, sso.WithTokenExchangeChainStore(store))
	subjectTok := txcpLoginAs(t, srv, txcpSubjectUser)
	actorA := txcpLoginAs(t, srv, txcpActorAUser)

	status, body := txcpExchange(t, srv, subjectTok, actorA)
	if status != http.StatusOK {
		t.Fatalf("exchange status=%d body=%v", status, body)
	}
	accessToken, _ := body["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("no access_token in %v", body)
	}

	jti := tokenexchange.JTIFromJWTUnsafe(accessToken)
	if jti == "" {
		t.Fatalf("could not extract jti from minted access token")
	}
	chain, err := store.GetChain(context.Background(), jti)
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("GetChain(%s) = %d hops, want 1 (the recorded hop)", jti, len(chain))
	}
	hop := chain[0]
	if hop.SubjectID != txcpSubjectUser {
		t.Errorf("hop.SubjectID = %q, want %q", hop.SubjectID, txcpSubjectUser)
	}
	if hop.ActorSubject != txcpActorAUser {
		t.Errorf("hop.ActorSubject = %q, want %q", hop.ActorSubject, txcpActorAUser)
	}
	if hop.ClientID != txcpClient {
		t.Errorf("hop.ClientID = %q, want %q", hop.ClientID, txcpClient)
	}
	if hop.ChainDepth != 1 {
		t.Errorf("hop.ChainDepth = %d, want 1 (one actor_token presented)", hop.ChainDepth)
	}
}

// TestTokenExchange_ChainStoreUnwiredByDefault proves a nil ChainStore (the
// default — sso.WithTokenExchangeChainStore never called) is a complete
// no-op: the exchange grant behaves exactly as it did before this feature
// existed.
func TestTokenExchange_ChainStoreUnwiredByDefault(t *testing.T) {
	srv := newTokenExchangeChainPolicyHarness(t)
	subjectTok := txcpLoginAs(t, srv, txcpSubjectUser)

	status, body := txcpExchange(t, srv, subjectTok, "")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v (want 200 — no ChainStore wired)", status, body)
	}
}

// alwaysFailingChainStore is a hand-written test double (not a mock — no
// call-count/argument assertions) whose RecordHop ALWAYS errors, standing in
// for a down/unreachable durable store (e.g. a sqlite ChainStore whose disk
// is full, or a network partition to a remote backend).
type alwaysFailingChainStore struct{}

func (alwaysFailingChainStore) RecordHop(context.Context, tokenexchange.ChainHop) error {
	return errors.New("simulated chain store outage")
}
func (alwaysFailingChainStore) GetChain(context.Context, string) ([]tokenexchange.ChainHop, error) {
	return nil, nil
}
func (alwaysFailingChainStore) GetDescendants(context.Context, string, int) ([]tokenexchange.ChainHop, error) {
	return nil, nil
}

var _ tokenexchange.ChainStore = alwaysFailingChainStore{}

// TestTokenExchange_ChainStoreFailOpen is the fail-open proof this feature's
// whole design hinges on (AGENTS.md §3 fail-open audit-recording idiom,
// mirrored from platform/audit.Recorder.Record): a ChainStore whose
// RecordHop ALWAYS errors must NEVER fail, delay, or alter the token-exchange
// grant itself. The exchange must still return 200 with a correctly-minted
// access_token, identical to a request with no ChainStore wired at all —
// pure observability can never become a new failure mode for the grant it
// observes.
func TestTokenExchange_ChainStoreFailOpen(t *testing.T) {
	srv := newTokenExchangeChainPolicyHarness(t, sso.WithTokenExchangeChainStore(alwaysFailingChainStore{}))
	subjectTok := txcpLoginAs(t, srv, txcpSubjectUser)
	actorA := txcpLoginAs(t, srv, txcpActorAUser)

	status, body := txcpExchange(t, srv, subjectTok, actorA)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v (want 200 — a failing ChainStore must never fail the grant)", status, body)
	}
	accessToken, _ := body["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("no access_token in %v — the grant must still mint one despite RecordHop erroring", body)
	}
	if tokenexchange.JTIFromJWTUnsafe(accessToken) == "" {
		t.Fatalf("minted access_token has no recoverable jti — issuance itself may have been disturbed")
	}
}
