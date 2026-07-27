package defaultmfa_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/defaultmfa"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystorecredential"
	"github.com/yangwb1123/snaplink/shared/core"
)

// newProviderWithCode wires the recovery provider over a real
// MemoryRecoveryCodeStore and mints one batch of codes for "alice".
func newProviderWithCode(t *testing.T) (*defaultmfa.RecoveryMFAProvider, []string) {
	t.Helper()
	store := memorystorecredential.NewMemoryRecoveryCodeStore()
	codes, err := store.Generate(context.Background(), "alice", core.DefaultRecoveryCodeCount)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	p, err := defaultmfa.NewRecoveryMFAProvider(store)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	return p, codes
}

func TestRecoveryMFAProvider_NilStoreRejected(t *testing.T) {
	if _, err := defaultmfa.NewRecoveryMFAProvider(nil); err == nil {
		t.Fatal("expected error for nil store")
	}
}

func TestRecoveryMFAProvider_SupportedMethods(t *testing.T) {
	p, _ := newProviderWithCode(t)
	got := p.SupportedMethods()
	if len(got) != 1 || got[0] != defaultmfa.MethodRecovery {
		t.Fatalf("SupportedMethods = %v, want [%q]", got, defaultmfa.MethodRecovery)
	}
}

func TestRecoveryMFAProvider_VerifySuccessConsumes(t *testing.T) {
	p, codes := newProviderWithCode(t)
	if err := p.Verify(context.Background(), "alice", defaultmfa.MethodRecovery, map[string]string{"code": codes[0]}); err != nil {
		t.Fatalf("Verify valid code = %v, want nil", err)
	}
	// Single-use: a second Verify of the same code must fail.
	if err := p.Verify(context.Background(), "alice", defaultmfa.MethodRecovery, map[string]string{"code": codes[0]}); !errors.Is(err, defaultmfa.ErrRecoveryCodeInvalid) {
		t.Fatalf("replay Verify = %v, want ErrRecoveryCodeInvalid", err)
	}
}

func TestRecoveryMFAProvider_ForgivingNormalization(t *testing.T) {
	p, codes := newProviderWithCode(t)
	// Generate emits upper-case, separator-free codes; a user who types
	// lower-case with stray spaces must still succeed (normalized in the
	// provider, never in the store).
	messy := "  " + toLowerWithSpaces(codes[0]) + "  "
	if err := p.Verify(context.Background(), "alice", defaultmfa.MethodRecovery, map[string]string{"code": messy}); err != nil {
		t.Fatalf("Verify normalized code = %v, want nil", err)
	}
}

func TestRecoveryMFAProvider_WrongMethod(t *testing.T) {
	p, codes := newProviderWithCode(t)
	if err := p.Verify(context.Background(), "alice", "totp", map[string]string{"code": codes[0]}); !errors.Is(err, defaultmfa.ErrRecoveryUnsupportedMethod) {
		t.Fatalf("wrong method = %v, want ErrRecoveryUnsupportedMethod", err)
	}
}

func TestRecoveryMFAProvider_MissingCode(t *testing.T) {
	p, _ := newProviderWithCode(t)
	if err := p.Verify(context.Background(), "alice", defaultmfa.MethodRecovery, map[string]string{"code": "   "}); !errors.Is(err, defaultmfa.ErrRecoveryMissingCode) {
		t.Fatalf("blank code = %v, want ErrRecoveryMissingCode", err)
	}
}

func TestRecoveryMFAProvider_UnknownCode(t *testing.T) {
	p, _ := newProviderWithCode(t)
	if err := p.Verify(context.Background(), "alice", defaultmfa.MethodRecovery, map[string]string{"code": "ZZZZ2345"}); !errors.Is(err, defaultmfa.ErrRecoveryCodeInvalid) {
		t.Fatalf("unknown code = %v, want ErrRecoveryCodeInvalid", err)
	}
}

// toLowerWithSpaces lower-cases every rune and inserts a space after each,
// simulating a user copying a code with sloppy formatting.
func toLowerWithSpaces(s string) string {
	out := make([]rune, 0, len(s)*2)
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			r = r - 'A' + 'a'
		}
		out = append(out, r, ' ')
	}
	return string(out)
}
