package memorystorecredential

import (
	"context"
	"testing"

	"github.com/snaplink/sso/shared/core"
)

func TestMemoryRecoveryCodeStore_GenerateReturnsDistinctCodes(t *testing.T) {
	s := NewMemoryRecoveryCodeStore()
	codes, err := s.Generate(context.Background(), "alice", core.DefaultRecoveryCodeCount)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(codes) != core.DefaultRecoveryCodeCount {
		t.Fatalf("len(codes) = %d, want %d", len(codes), core.DefaultRecoveryCodeCount)
	}
	seen := map[string]struct{}{}
	for _, c := range codes {
		if c == "" {
			t.Fatal("empty code returned")
		}
		if _, dup := seen[c]; dup {
			t.Fatalf("duplicate code %q", c)
		}
		seen[c] = struct{}{}
	}
}

// TestMemoryRecoveryCodeStore_PlaintextNotStored proves the store never
// keeps a usable copy of the code: every stored key is the SHA-256 hash,
// so a map dump can't be replayed. Internal test so we can read userCodes.
func TestMemoryRecoveryCodeStore_PlaintextNotStored(t *testing.T) {
	s := NewMemoryRecoveryCodeStore()
	codes, _ := s.Generate(context.Background(), "alice", core.DefaultRecoveryCodeCount)
	plaintext := map[string]struct{}{}
	for _, c := range codes {
		plaintext[c] = struct{}{}
	}
	for storedKey := range s.userCodes["alice"] {
		if _, isPlain := plaintext[storedKey]; isPlain {
			t.Fatalf("stored key %q is the plaintext code — hashing not applied", storedKey)
		}
		if len(storedKey) != 64 { // SHA-256 hex digest length
			t.Fatalf("stored key %q is %d chars, want a 64-char SHA-256 hex digest", storedKey, len(storedKey))
		}
	}
}

func TestMemoryRecoveryCodeStore_ConsumeOnce(t *testing.T) {
	s := NewMemoryRecoveryCodeStore()
	codes, _ := s.Generate(context.Background(), "alice", core.DefaultRecoveryCodeCount)

	ok, err := s.Consume(context.Background(), "alice", codes[0])
	if err != nil || !ok {
		t.Fatalf("first consume = (%v, %v), want (true, nil)", ok, err)
	}
	// Single-use: second consume of the same code is false, not an error.
	ok, err = s.Consume(context.Background(), "alice", codes[0])
	if err != nil || ok {
		t.Fatalf("replay consume = (%v, %v), want (false, nil)", ok, err)
	}
	// Unknown code is indistinguishable from a consumed one (anti-enumeration).
	if ok, _ := s.Consume(context.Background(), "alice", "NOTACODE"); ok {
		t.Fatal("unknown code consumed true")
	}
	// A code belonging to an unknown user is also false.
	if ok, _ := s.Consume(context.Background(), "mallory", codes[1]); ok {
		t.Fatal("cross-user consume succeeded")
	}
}

func TestMemoryRecoveryCodeStore_CountRemaining(t *testing.T) {
	s := NewMemoryRecoveryCodeStore()
	if n, _ := s.CountRemaining(context.Background(), "alice"); n != 0 {
		t.Fatalf("count before generate = %d, want 0", n)
	}
	codes, _ := s.Generate(context.Background(), "alice", core.DefaultRecoveryCodeCount)
	if n, _ := s.CountRemaining(context.Background(), "alice"); n != core.DefaultRecoveryCodeCount {
		t.Fatalf("count after generate = %d, want %d", n, core.DefaultRecoveryCodeCount)
	}
	_, _ = s.Consume(context.Background(), "alice", codes[0])
	if n, _ := s.CountRemaining(context.Background(), "alice"); n != core.DefaultRecoveryCodeCount-1 {
		t.Fatalf("count after one consume = %d, want %d", n, core.DefaultRecoveryCodeCount-1)
	}
}

func TestMemoryRecoveryCodeStore_RevokeAll(t *testing.T) {
	s := NewMemoryRecoveryCodeStore()
	codes, _ := s.Generate(context.Background(), "alice", core.DefaultRecoveryCodeCount)
	if err := s.RevokeAll(context.Background(), "alice"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if n, _ := s.CountRemaining(context.Background(), "alice"); n != 0 {
		t.Fatalf("count after revoke = %d, want 0", n)
	}
	// A previously valid code no longer consumes after revoke.
	if ok, _ := s.Consume(context.Background(), "alice", codes[0]); ok {
		t.Fatal("revoked code still consumable")
	}
}

// TestMemoryRecoveryCodeStore_NClamp asserts out-of-range counts fall back
// to the default batch size rather than generating an attacker-chosen
// (or zero) number of codes.
func TestMemoryRecoveryCodeStore_NClamp(t *testing.T) {
	s := NewMemoryRecoveryCodeStore()
	for _, n := range []int{0, -5, 21, 1000} {
		codes, err := s.Generate(context.Background(), "alice", n)
		if err != nil {
			t.Fatalf("generate n=%d: %v", n, err)
		}
		if len(codes) != core.DefaultRecoveryCodeCount {
			t.Fatalf("n=%d produced %d codes, want clamp to %d", n, len(codes), core.DefaultRecoveryCodeCount)
		}
		_ = s.RevokeAll(context.Background(), "alice")
	}
}
