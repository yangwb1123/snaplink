package sqlite

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Bug 4 (sqlite store): mirror of the memory peer — the unknown-user dummy was
// minted once at bcrypt.DefaultCost while an imported hash could be cost 12+,
// leaking username existence via timing. The fix raises the in-process dummy to
// track the slowest imported cost. Structural assertion, not timing.

func internalDSN(t *testing.T) string {
	t.Helper()
	return "file:" + t.Name() + ".db?mode=memory&cache=shared&_pragma=busy_timeout(5000)"
}

func TestPasswordCredentialStore_DummyRaisesToImportedCost(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := NewPasswordCredentialStore(internalDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if c, _ := bcrypt.Cost(s.dummy); c != bcrypt.DefaultCost {
		t.Fatalf("initial dummy cost = %d; want %d", c, bcrypt.DefaultCost)
	}

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
		t.Fatalf("dummy cost after import = %d; want %d (Bug 4)", got, importedCost)
	}

	// Verify the imported credential still authenticates after the dummy raise.
	if err := s.VerifyPassword(ctx, "bob", "imported"); err != nil {
		t.Fatalf("imported credential verify failed: %v", err)
	}
}
