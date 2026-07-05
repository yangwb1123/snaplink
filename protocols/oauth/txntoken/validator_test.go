package txntoken_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/protocols/oauth/txntoken"
	"github.com/snaplink/sso/shared/core"
)

func TestValidator_RoundTrip(t *testing.T) {
	signer, iss := newTestIssuer(t)
	validator := txntoken.NewValidator(signer, testTrustDomain)

	signed, minted, err := iss.Mint(context.Background(), txntoken.MintRequest{
		Subject: "alice", RequestingWorkload: "checkout-svc", TrustDomain: testTrustDomain,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	claims, err := validator.Validate(context.Background(), signed)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Sub != minted.Sub || claims.Txn != minted.Txn {
		t.Errorf("validated claims = %+v, want to match minted %+v", claims, minted)
	}
}

func TestValidator_RejectsWrongTyp(t *testing.T) {
	signer, _ := newTestIssuer(t)
	validator := txntoken.NewValidator(signer, testTrustDomain)

	// An ordinary RFC 9068 access token (typ=at+jwt) signed by the SAME
	// key must still be refused — the typ gate runs before any claim
	// shape (scopes vs sub/aud/txn) is even considered.
	tok, err := signer.Issue(context.Background(), &core.Subject{ID: "alice"}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := validator.Validate(context.Background(), tok.AccessToken); err == nil {
		t.Fatal("expected an error validating a non-Txn-Token typ")
	}
}

func TestValidator_RejectsExpired(t *testing.T) {
	signer, iss := newTestIssuer(t, txntoken.WithTTL(time.Millisecond))
	validator := txntoken.NewValidator(signer, testTrustDomain)

	signed, _, err := iss.Mint(context.Background(), txntoken.MintRequest{
		Subject: "alice", TrustDomain: testTrustDomain,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := validator.Validate(context.Background(), signed); err == nil {
		t.Fatal("expected an expired-token error")
	}
}

func TestValidator_RejectsAudienceMismatch(t *testing.T) {
	signer, iss := newTestIssuer(t)
	otherDomainValidator := txntoken.NewValidator(signer, "some-other-domain")

	signed, _, err := iss.Mint(context.Background(), txntoken.MintRequest{
		Subject: "alice", TrustDomain: testTrustDomain,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := otherDomainValidator.Validate(context.Background(), signed); err == nil {
		t.Fatal("expected an aud-mismatch error")
	}
}

func TestValidator_RejectsTamperedSignature(t *testing.T) {
	signer, iss := newTestIssuer(t)
	validator := txntoken.NewValidator(signer, testTrustDomain)

	signed, _, err := iss.Mint(context.Background(), txntoken.MintRequest{
		Subject: "alice", TrustDomain: testTrustDomain,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	tampered := signed[:len(signed)-2] + "aa"
	if _, err := validator.Validate(context.Background(), tampered); err == nil {
		t.Fatal("expected a signature-verification error for a tampered token")
	}
}

func TestValidator_RejectsNotYetValid(t *testing.T) {
	signer, _ := newTestIssuer(t)
	validator := txntoken.NewValidator(signer, testTrustDomain)

	future := time.Now().Add(time.Hour)
	claims := txntoken.Claims{
		Sub: "alice", Aud: testTrustDomain,
		Iat: time.Now().Unix(), Exp: future.Add(time.Minute).Unix(), Nbf: future.Unix(),
		Txn: "test-txn",
	}
	signed, err := signer.SignJWT(context.Background(), txntoken.Typ, claims)
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	if _, err := validator.Validate(context.Background(), signed); err == nil {
		t.Fatal("expected a not-yet-valid error")
	}
}

func TestValidator_PanicsOnMisconfiguration(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected NewValidator to panic on a nil key source")
		}
	}()
	txntoken.NewValidator(nil, testTrustDomain)
}
