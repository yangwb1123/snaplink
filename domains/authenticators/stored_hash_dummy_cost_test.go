package authenticators

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Bug 4: the imported-hash verifier's miss-path dummy used a fast
// bcrypt.DefaultCost (10) hash while a real verify ran the (slower, possibly
// cost-12+) imported KDF — a timing oracle distinguishing known vs unknown
// usernames. A timing assertion would be flaky, so we assert the structural
// fix instead: the dummy carries the matched/configured cost, NOT cost 10.

// TestStoredHashVerifier_DummyDefaultsAboveDefaultCost proves the unpinned
// dummy is minted above bcrypt's cost-10 default so the miss path is not
// trivially faster than a modern imported hash.
func TestStoredHashVerifier_DummyDefaultsAboveDefaultCost(t *testing.T) {
	v := NewStoredHashVerifier(nil)
	cost, err := bcrypt.Cost([]byte(v.dummyHash.Hash))
	if err != nil {
		t.Fatalf("dummy hash not bcrypt: %v", err)
	}
	if cost != DefaultStoredHashDummyCost {
		t.Fatalf("dummy cost = %d; want DefaultStoredHashDummyCost=%d", cost, DefaultStoredHashDummyCost)
	}
	if cost <= bcrypt.DefaultCost {
		t.Fatalf("default dummy cost %d must exceed bcrypt.DefaultCost %d (Bug 4)", cost, bcrypt.DefaultCost)
	}
}

// TestStoredHashVerifier_DummyMatchesPinnedCost proves WithStoredHashDummyCost
// pins the dummy to the imported corpus's cost so the miss path matches the hit
// path.
func TestStoredHashVerifier_DummyMatchesPinnedCost(t *testing.T) {
	const want = 13
	v := NewStoredHashVerifier(nil, WithStoredHashDummyCost(want))
	cost, err := bcrypt.Cost([]byte(v.dummyHash.Hash))
	if err != nil {
		t.Fatalf("dummy hash not bcrypt: %v", err)
	}
	if cost != want {
		t.Fatalf("pinned dummy cost = %d; want %d", cost, want)
	}
}

// TestStoredHashVerifier_DummyRejectsOutOfRangeCost proves an out-of-range
// pinned cost falls back to the safe default rather than panicking or producing
// an empty hash.
func TestStoredHashVerifier_DummyRejectsOutOfRangeCost(t *testing.T) {
	for _, bad := range []int{0, -1, bcrypt.MaxCost + 1} {
		v := NewStoredHashVerifier(nil, WithStoredHashDummyCost(bad))
		cost, err := bcrypt.Cost([]byte(v.dummyHash.Hash))
		if err != nil {
			t.Fatalf("cost %d: dummy hash not bcrypt: %v", bad, err)
		}
		if cost != DefaultStoredHashDummyCost {
			t.Fatalf("out-of-range cost %d: dummy cost = %d; want default %d", bad, cost, DefaultStoredHashDummyCost)
		}
	}
}
