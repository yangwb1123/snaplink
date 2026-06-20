package authenticators_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// importUser seeds a user whose credential lives in Attributes the way
// cmd/sso-import writes it.
func importUser(t *testing.T, p *defaultimpl.MemoryUserProvider, id, plaintext, format string) {
	t.Helper()
	var hash string
	var err error
	switch format {
	case authenticators.HashFormatArgon2id:
		hash, err = authenticators.EncodeArgon2id(plaintext, 8192, 1, 1, 32)
	case authenticators.HashFormatPBKDF2SHA256:
		hash, err = authenticators.EncodePBKDF2SHA256(plaintext, 1000)
	case authenticators.HashFormatBcrypt, "":
		var h authenticators.PasswordHash
		h, err = authenticators.HashPassword(plaintext)
		hash = h.Hash
	default:
		t.Fatalf("unknown format %q", format)
	}
	if err != nil {
		t.Fatalf("encode %s: %v", format, err)
	}
	if err := p.CreateOrUpdate(context.Background(), &sso.User{
		ID: id,
		Attributes: map[string]string{
			authenticators.AttrPasswordHash:       hash,
			authenticators.AttrPasswordHashFormat: format,
		},
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func TestStoredHashVerifier_MultiFormat(t *testing.T) {
	ctx := context.Background()
	p := defaultimpl.NewMemoryUserProvider()
	importUser(t, p, "alice", "alice-pw", authenticators.HashFormatArgon2id)
	importUser(t, p, "bob", "bob-pw", authenticators.HashFormatPBKDF2SHA256)
	importUser(t, p, "carol", "carol-pw", authenticators.HashFormatBcrypt)

	v := authenticators.NewStoredHashVerifier(p)

	for _, tc := range []struct{ user, pass string }{
		{"alice", "alice-pw"}, {"bob", "bob-pw"}, {"carol", "carol-pw"},
	} {
		res, err := v.Verify(ctx, tc.user, tc.pass)
		if err != nil {
			t.Errorf("Verify(%s) failed: %v", tc.user, err)
			continue
		}
		if res.UserID != tc.user {
			t.Errorf("Verify(%s) UserID=%q", tc.user, res.UserID)
		}
	}

	// Wrong password and unknown user both fail.
	if _, err := v.Verify(ctx, "alice", "nope"); err == nil {
		t.Error("wrong password must fail")
	}
	if _, err := v.Verify(ctx, "ghost", "whatever"); err == nil {
		t.Error("unknown user must fail")
	}
}

func TestStoredHashRehashHooks_NonBcryptNeedsUpgrade(t *testing.T) {
	ctx := context.Background()
	p := defaultimpl.NewMemoryUserProvider()
	importUser(t, p, "alice", "pw", authenticators.HashFormatArgon2id)
	importUser(t, p, "carol", "pw", authenticators.HashFormatBcrypt)

	needs, update := authenticators.StoredHashRehashHooks(p)

	if got, _ := needs(ctx, "alice"); !got {
		t.Error("argon2id user must need rehash")
	}
	if got, _ := needs(ctx, "carol"); got {
		t.Error("bcrypt user must NOT need rehash")
	}

	// Upgrade alice; her stored format becomes bcrypt and no longer needs rehash.
	newHash, _ := authenticators.HashPassword("pw")
	if err := update(ctx, "alice", newHash.Hash); err != nil {
		t.Fatalf("update: %v", err)
	}
	u, _ := p.GetByID(ctx, "alice")
	if u.Attributes[authenticators.AttrPasswordHashFormat] != authenticators.HashFormatBcrypt {
		t.Errorf("format after upgrade = %q, want bcrypt", u.Attributes[authenticators.AttrPasswordHashFormat])
	}
	if got, _ := needs(ctx, "alice"); got {
		t.Error("upgraded user must no longer need rehash")
	}
}

func TestChainPasswordVerifier_FirstSuccessWins(t *testing.T) {
	ctx := context.Background()
	p := defaultimpl.NewMemoryUserProvider()
	importUser(t, p, "alice", "alice-pw", authenticators.HashFormatArgon2id)

	// A primary verifier that only knows bob (a YAML/store user).
	primary := authenticators.PasswordVerifierFunc(func(_ context.Context, u, pw string) (*sso.AuthResult, error) {
		if u == "bob" && pw == "bob-pw" {
			return &sso.AuthResult{UserID: "bob"}, nil
		}
		return nil, errors.New("no")
	})
	chain := authenticators.NewChainPasswordVerifier(primary, authenticators.NewStoredHashVerifier(p))

	// Store user via primary; imported user via the fallback.
	if res, err := chain.Verify(ctx, "bob", "bob-pw"); err != nil || res.UserID != "bob" {
		t.Errorf("chain bob = %+v, %v", res, err)
	}
	if res, err := chain.Verify(ctx, "alice", "alice-pw"); err != nil || res.UserID != "alice" {
		t.Errorf("chain alice = %+v, %v", res, err)
	}
	if _, err := chain.Verify(ctx, "ghost", "x"); err == nil {
		t.Error("unknown user must fail the whole chain")
	}
}

// TestLazyRehash_UpgradesImportedHashOnLogin is the end-to-end path the import
// tool documents: an argon2id user logs in and the stored hash is transparently
// migrated to bcrypt (async).
func TestLazyRehash_UpgradesImportedHashOnLogin(t *testing.T) {
	ctx := context.Background()
	p := defaultimpl.NewMemoryUserProvider()
	importUser(t, p, "alice", "alice-pw", authenticators.HashFormatArgon2id)

	needs, update := authenticators.StoredHashRehashHooks(p)
	v := &authenticators.LazyRehashVerifier{
		Underlying:  authenticators.NewStoredHashVerifier(p),
		NeedsRehash: needs,
		Updater:     update,
	}

	if _, err := v.Verify(ctx, "alice", "alice-pw"); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	// The rehash is fire-and-forget; poll until the stored format flips.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		u, _ := p.GetByID(ctx, "alice")
		if u.Attributes[authenticators.AttrPasswordHashFormat] == authenticators.HashFormatBcrypt {
			// And the migrated bcrypt hash still verifies the same password.
			if _, err := v.Verify(ctx, "alice", "alice-pw"); err != nil {
				t.Fatalf("login after rehash failed: %v", err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("imported hash was not upgraded to bcrypt after login")
}
