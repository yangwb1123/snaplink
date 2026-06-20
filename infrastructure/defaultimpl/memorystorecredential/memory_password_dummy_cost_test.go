package memorystorecredential

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Bug 4 (native store): the unknown-user dummy was minted once at
// bcrypt.DefaultCost (10) while an imported hash seeded via SetPasswordHash
// could be cost 12+, making the miss path measurably faster than a hit — a
// username enumeration timing oracle. The fix raises the dummy to track the
// slowest seeded cost. We assert the structural fix (dummy cost), not timing.

func TestMemoryPasswordCredentialStore_DummyStartsAtDefaultCost(t *testing.T) {
	s := NewMemoryPasswordCredentialStore()
	cost, err := bcrypt.Cost(s.dummy)
	if err != nil {
		t.Fatalf("dummy not bcrypt: %v", err)
	}
	if cost != bcrypt.DefaultCost {
		t.Fatalf("initial dummy cost = %d; want %d", cost, bcrypt.DefaultCost)
	}
}

func TestMemoryPasswordCredentialStore_DummyRaisesToImportedCost(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryPasswordCredentialStore()

	const importedCost = bcrypt.DefaultCost + 2
	h, err := bcrypt.GenerateFromPassword([]byte("imported"), importedCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := s.SetPasswordHash(ctx, "bob", string(h)); err != nil {
		t.Fatalf("SetPasswordHash: %v", err)
	}
	got, err := bcrypt.Cost(s.dummy)
	if err != nil {
		t.Fatalf("dummy not bcrypt: %v", err)
	}
	if got != importedCost {
		t.Fatalf("dummy cost after import = %d; want %d (Bug 4: miss path must match slowest hit)", got, importedCost)
	}
}

// A lower-cost import must NOT drop the dummy below the default floor.
func TestMemoryPasswordCredentialStore_DummyNeverDropsBelowFloor(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryPasswordCredentialStore()

	h, err := bcrypt.GenerateFromPassword([]byte("imported"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := s.SetPasswordHash(ctx, "bob", string(h)); err != nil {
		t.Fatalf("SetPasswordHash: %v", err)
	}
	got, err := bcrypt.Cost(s.dummy)
	if err != nil {
		t.Fatalf("dummy not bcrypt: %v", err)
	}
	if got < bcrypt.DefaultCost {
		t.Fatalf("dummy cost dropped to %d below floor %d", got, bcrypt.DefaultCost)
	}
}
