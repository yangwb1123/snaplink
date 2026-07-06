package defaultimpl_test

import (
	"context"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"golang.org/x/crypto/bcrypt"
)

// TestSetBcryptCost_ReachesMemoryClientStoreHashing guards against the exact
// bug this pair of functions replaced: a plain `var BcryptCost = pkg.BcryptCost`
// alias copies the int VALUE once at init and never reflects a later
// `defaultimpl.BcryptCost = x` assignment in memorystoreidentity's own
// hashing — silently leaving every seeded client secret hashed at
// bcrypt.DefaultCost regardless of what tests set. SetBcryptCost/BcryptCost
// forward to the live variable instead; this proves the round trip actually
// reaches MemoryClientStore's hashing.
func TestSetBcryptCost_ReachesMemoryClientStoreHashing(t *testing.T) {
	original := defaultimpl.BcryptCost()
	t.Cleanup(func() { defaultimpl.SetBcryptCost(original) })

	defaultimpl.SetBcryptCost(bcrypt.MinCost)
	if got := defaultimpl.BcryptCost(); got != bcrypt.MinCost {
		t.Fatalf("BcryptCost() = %d, want %d", got, bcrypt.MinCost)
	}

	store := defaultimpl.NewMemoryClientStore()
	client := &sso.Client{ID: "cost-check", Secret: "plaintext-secret", Active: true}
	if err := store.Add(context.Background(), client); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := store.Get(context.Background(), "cost-check")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	cost, err := bcrypt.Cost([]byte(got.Secret))
	if err != nil {
		t.Fatalf("bcrypt.Cost: %v", err)
	}
	if cost != bcrypt.MinCost {
		t.Errorf("stored secret hashed at cost %d, want %d (SetBcryptCost did not reach memorystoreidentity's hashing)", cost, bcrypt.MinCost)
	}
}
