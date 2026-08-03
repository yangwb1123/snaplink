package tokenpolicy

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
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

// TestClampingIssuer_TenantClampsOnlyThatTenant proves the stamp contract: a
// subject whose TenantID matches the rule's tenant gets clamped; a subject
// stamped with a DIFFERENT tenant — and an UNSTAMPED subject (TenantID == "",
// the pre-feature bytes of a missed/old site) — stays unclamped (fail-open).
func TestClampingIssuer_TenantClampsOnlyThatTenant(t *testing.T) {
	t.Parallel()
	store := staticStore{policies: []Policy{{Name: "ta-cap", TenantID: "ta", MaxTTL: 5 * time.Minute}}}

	cases := []struct {
		name    string
		subject *core.Subject
		wantTTL time.Duration
	}{
		{"stamped ta clamps", &core.Subject{ID: "u", ClientID: "c", TenantID: "ta", TTL: time.Hour}, 5 * time.Minute},
		{"stamped tb does not", &core.Subject{ID: "u", ClientID: "c", TenantID: "tb", TTL: time.Hour}, time.Hour},
		{"unstamped stays unclamped", &core.Subject{ID: "u", ClientID: "c", TTL: time.Hour}, time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner := &recordingIssuer{}
			iss := NewClampingIssuer(inner, store)
			_, _ = iss.Issue(context.Background(), tc.subject, nil)
			if inner.gotTTL != tc.wantTTL {
				t.Fatalf("inner got TTL %v, want %v", inner.gotTTL, tc.wantTTL)
			}
		})
	}
}

// TestClampingIssuer_GlobalRuleClampsAnyTenant proves a GLOBAL max_ttl rule
// (empty tenant selector) applies to tenant-stamped and unstamped subjects
// alike — the byte-compat form keeps working under the new dimension.
func TestClampingIssuer_GlobalRuleClampsAnyTenant(t *testing.T) {
	t.Parallel()
	inner := &recordingIssuer{}
	store := staticStore{policies: []Policy{{Name: "global", MaxTTL: 10 * time.Minute}}}
	iss := NewClampingIssuer(inner, store)

	for _, tenant := range []string{"", "ta", "tb"} {
		inner.gotTTL = 0
		_, _ = iss.Issue(context.Background(),
			&core.Subject{ID: "u", ClientID: "c", TenantID: tenant, TTL: time.Hour}, nil)
		if inner.gotTTL != 10*time.Minute {
			t.Fatalf("tenant %q got TTL %v, want clamped 10m", tenant, inner.gotTTL)
		}
	}
}
