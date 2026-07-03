package tokenpolicy

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// recordingIssuer captures the Subject the decorator forwards so a test can
// assert on the CLAMPED TTL that reached the wrapped issuer. There is no
// Memory* TokenIssuer SPI to reuse (the real issuers are the crypto/opaque
// impls in infrastructure/defaultimpl, which would drag key setup into this
// unit test), so a minimal recording spy is the precise tool for the
// decorator's contract — it is not standing in for an existing Memory* impl.
type recordingIssuer struct {
	gotTTL    time.Duration
	gotScopes []string
	issued    bool
}

func (r *recordingIssuer) Issue(_ context.Context, subject *core.Subject, scopes []string) (*core.Token, error) {
	r.issued = true
	r.gotTTL = subject.TTL
	r.gotScopes = scopes
	return &core.Token{AccessToken: "tok"}, nil
}
func (r *recordingIssuer) Validate(context.Context, string) (*core.TokenClaims, error) {
	return &core.TokenClaims{}, nil
}
func (r *recordingIssuer) Revoke(context.Context, string) error { return nil }

// staticStore is a trivial read-only Store for the decorator tests; the memory
// store is exercised separately under ./memory.
type staticStore struct{ policies []Policy }

func (s staticStore) Policies(context.Context) ([]Policy, error) { return s.policies, nil }

// TestClampingIssuer_NilStoreReturnsInner proves the byte-identical default:
// with no store the decorator is never even constructed.
func TestClampingIssuer_NilStoreReturnsInner(t *testing.T) {
	t.Parallel()
	inner := &recordingIssuer{}
	if got := NewClampingIssuer(inner, nil); got != core.TokenIssuer(inner) {
		t.Fatalf("NewClampingIssuer(inner, nil) wrapped the issuer; want inner unchanged")
	}
}

// TestClampingIssuer_ClampsDownward proves the wrapped issuer receives the
// reduced TTL when a matching max_ttl is below the requested lifetime.
func TestClampingIssuer_ClampsDownward(t *testing.T) {
	t.Parallel()
	inner := &recordingIssuer{}
	store := staticStore{policies: []Policy{{Name: "p", ClientID: "c", MaxTTL: 15 * time.Minute}}}
	iss := NewClampingIssuer(inner, store)

	_, err := iss.Issue(context.Background(),
		&core.Subject{ID: "u", ClientID: "c", TTL: time.Hour}, []string{"openid"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !inner.issued || inner.gotTTL != 15*time.Minute {
		t.Fatalf("inner got TTL %v, want clamped 15m", inner.gotTTL)
	}
}

// TestClampingIssuer_NeverRaises proves a max_ttl ABOVE the requested TTL is a
// no-op — the decorator never lengthens a client-configured lifetime.
func TestClampingIssuer_NeverRaises(t *testing.T) {
	t.Parallel()
	inner := &recordingIssuer{}
	store := staticStore{policies: []Policy{{Name: "p", ClientID: "c", MaxTTL: 2 * time.Hour}}}
	iss := NewClampingIssuer(inner, store)

	_, _ = iss.Issue(context.Background(),
		&core.Subject{ID: "u", ClientID: "c", TTL: time.Hour}, nil)
	if inner.gotTTL != time.Hour {
		t.Fatalf("inner got TTL %v, want unchanged 1h", inner.gotTTL)
	}
}

// TestClampingIssuer_ImposesCeilingOnUnset proves an unset requested TTL (0 =
// issuer default) takes a matching max_ttl as its concrete ceiling.
func TestClampingIssuer_ImposesCeilingOnUnset(t *testing.T) {
	t.Parallel()
	inner := &recordingIssuer{}
	store := staticStore{policies: []Policy{{Name: "p", MaxTTL: 10 * time.Minute}}}
	iss := NewClampingIssuer(inner, store)

	_, _ = iss.Issue(context.Background(),
		&core.Subject{ID: "u", ClientID: "c", TTL: 0}, nil)
	if inner.gotTTL != 10*time.Minute {
		t.Fatalf("inner got TTL %v, want ceiling 10m", inner.gotTTL)
	}
}

// TestClampingIssuer_NoMatchLeavesTTL proves a client-mismatched rule does not
// touch the TTL, and Validate/Revoke delegate unchanged.
func TestClampingIssuer_NoMatchLeavesTTL(t *testing.T) {
	t.Parallel()
	inner := &recordingIssuer{}
	store := staticStore{policies: []Policy{{Name: "p", ClientID: "other", MaxTTL: time.Minute}}}
	iss := NewClampingIssuer(inner, store)

	_, _ = iss.Issue(context.Background(),
		&core.Subject{ID: "u", ClientID: "c", TTL: time.Hour}, nil)
	if inner.gotTTL != time.Hour {
		t.Fatalf("inner got TTL %v, want unchanged 1h", inner.gotTTL)
	}
	if _, err := iss.Validate(context.Background(), "tok"); err != nil {
		t.Fatalf("Validate delegate: %v", err)
	}
	if err := iss.Revoke(context.Background(), "tok"); err != nil {
		t.Fatalf("Revoke delegate: %v", err)
	}
}
