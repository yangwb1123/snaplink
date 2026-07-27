package defaultimpl_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// fakeExternalSigner stands in for a KMS/HSM signer: it holds the key
// out-of-band (here, just in the struct) and signs on demand. failErr,
// when set, simulates a backend round-trip failure.
type fakeExternalSigner struct {
	priv    ed25519.PrivateKey
	failErr error
	calls   int
}

func (s *fakeExternalSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	s.calls++
	if s.failErr != nil {
		return nil, s.failErr
	}
	return ed25519.Sign(s.priv, msg), nil
}

// TestExternalSigner_IssuesVerifiableTokens proves an injected signer
// produces tokens that Validate accepts against the supplied public key
// — i.e. the issuer never needs the private key in-process.
func TestExternalSigner_IssuesVerifiableTokens(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	signer := &fakeExternalSigner{priv: priv}
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519ExternalSigner(signer, pub, "kms-kid-1"),
	)
	if iss.KeyID() != "kms-kid-1" {
		t.Errorf("kid = %q, want kms-kid-1", iss.KeyID())
	}

	tok, err := iss.Issue(context.Background(), &sso.Subject{ID: "u1", ClientID: "c1"}, []string{"read"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if signer.calls == 0 {
		t.Fatal("external signer was not invoked")
	}
	claims, err := iss.Validate(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.Subject != "u1" {
		t.Errorf("subject = %q, want u1", claims.Subject)
	}
}

// TestExternalSigner_FailurePropagates proves a signer error fails the
// issuance closed (no unsigned token emitted) across every sign path.
func TestExternalSigner_FailurePropagates(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	boom := errors.New("kms unavailable")
	signer := &fakeExternalSigner{priv: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), failErr: boom}
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519ExternalSigner(signer, pub, "kms-kid-2"),
	)

	if _, err := iss.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, nil); !errors.Is(err, boom) {
		t.Errorf("Issue err = %v, want wrapped boom", err)
	}
	if _, err := iss.SignUserInfo(context.Background(), "c", map[string]any{"sub": "u"}); !errors.Is(err, boom) {
		t.Errorf("SignUserInfo err = %v, want wrapped boom", err)
	}
}
