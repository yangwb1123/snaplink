package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/config"
)

// TestBuildMFA_DisabledReturnsZeroes proves cmd skips MFA wiring
// entirely when mfa.enabled=false. Risk scorers returning
// DecisionRequireMFA then decay to Allow (back-compat preserved).
func TestBuildMFA_DisabledReturnsZeroes(t *testing.T) {
	provider, store, ttl, mode, err := buildMFA(config.MFAConfig{Enabled: false}, nil, quietLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider != nil || store != nil || ttl != 0 || mode != "" {
		t.Fatalf("disabled config should return zeroes; got provider=%v store=%v ttl=%v mode=%q",
			provider, store, ttl, mode)
	}
}

// TestBuildMFA_TOTPWithMemoryStore covers the most common single-
// replica wiring: TOTP-backed step-up sharing the same authenticator
// (and therefore the same secret store + skew) as primary auth, plus
// the in-process MemoryMFAChallengeStore. Verifies the wired provider
// reports the canonical "totp" method on the wire.
func TestBuildMFA_TOTPWithMemoryStore(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	provider, store, ttl, mode, err := buildMFA(config.MFAConfig{
		Enabled:  true,
		Provider: config.MFAProviderConfig{Kind: "totp"},
		Challenge: config.MFAChallengeConfig{
			Backend: "memory",
			TTL:     3 * time.Minute,
		},
	}, totpAuth, quietLogger())
	if err != nil {
		t.Fatalf("buildMFA: %v", err)
	}
	if provider == nil {
		t.Fatal("provider nil with totp enabled")
	}
	if store == nil {
		t.Fatal("store nil with memory backend enabled")
	}
	if ttl != 3*time.Minute {
		t.Fatalf("ttl: got %v want 3m", ttl)
	}
	if mode == "" || mode[:6] != "memory" {
		t.Fatalf("mode: got %q want memory*", mode)
	}
	methods := provider.SupportedMethods()
	if len(methods) != 1 || methods[0] != "totp" {
		t.Fatalf("SupportedMethods: got %v want [totp]", methods)
	}
}

// TestBuildMFA_TOTPWithSQLiteStore proves the cluster-shared wiring
// path: same provider, but the SQLite peer of MFAChallengeStore. The
// store is exercised through one Put → Consume cycle to prove the
// schema migrated at construction.
func TestBuildMFA_TOTPWithSQLiteStore(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "mfa.db") + "?_journal=WAL"
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	provider, store, _, mode, err := buildMFA(config.MFAConfig{
		Enabled:  true,
		Provider: config.MFAProviderConfig{Kind: "totp"},
		Challenge: config.MFAChallengeConfig{
			Backend: "sqlite",
			SQLite:  config.MFAChallengeSQLiteConfig{DSN: dsn},
		},
	}, totpAuth, quietLogger())
	if err != nil {
		t.Fatalf("buildMFA: %v", err)
	}
	if provider == nil || store == nil {
		t.Fatalf("provider/store nil: provider=%v store=%v", provider, store)
	}
	if mode != "sqlite (cluster-shared)" {
		t.Fatalf("mode: got %q want sqlite (cluster-shared)", mode)
	}

	// Round-trip a challenge through the freshly-built store. Confirms
	// migration ran + the wired backend can satisfy the SDK contract.
	ctx := context.Background()
	c := &sso.MFAChallenge{
		ID:        "ch-roundtrip",
		SubjectID: "user-1",
		ClientID:  "client-1",
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
	}
	if err := store.Put(ctx, c); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := store.Consume(ctx, "ch-roundtrip")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.ID != "ch-roundtrip" {
		t.Fatalf("Consume returned wrong challenge: %#v", got)
	}
}

// TestBuildMFA_KindDefaultsToTOTP proves an empty Provider.Kind falls
// through to "totp" rather than erroring — saves config noise when the
// only wired factor is TOTP anyway.
func TestBuildMFA_KindDefaultsToTOTP(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	provider, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{}, // Kind unset
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, totpAuth, quietLogger())
	if err != nil {
		t.Fatalf("buildMFA: %v", err)
	}
	if provider == nil {
		t.Fatal("provider nil with empty kind (should default to totp)")
	}
}

// TestBuildMFA_TOTPRequiresTOTPAuth proves cmd refuses to wire
// "totp" as MFA provider when authenticators.totp.enabled=false. The
// shared-secret-store contract requires the underlying authenticator
// — without it the provider would silently have no users enrolled.
func TestBuildMFA_TOTPRequiresTOTPAuth(t *testing.T) {
	_, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{Kind: "totp"},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, nil, quietLogger())
	if err == nil {
		t.Fatal("buildMFA: want error when totp provider requested without TOTPAuthenticator")
	}
}

// TestBuildMFA_UnknownKindRejected covers the typo / misconfig path
// where an operator writes mfa.provider.kind=fido2 expecting it to
// "just work". Fail loud — silent fallback to TOTP would surprise.
func TestBuildMFA_UnknownKindRejected(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	_, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{Kind: "fido2"},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, totpAuth, quietLogger())
	if err == nil {
		t.Fatal("buildMFA: want error on unknown provider kind")
	}
}

// TestBuildMFA_SQLiteRequiresDSN proves the SQLite challenge backend
// fails loud when DSN is missing — silently falling back to memory
// would defeat the cluster-shared invariant.
func TestBuildMFA_SQLiteRequiresDSN(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	_, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{Kind: "totp"},
		Challenge: config.MFAChallengeConfig{Backend: "sqlite"}, // SQLite.DSN unset
	}, totpAuth, quietLogger())
	if err == nil {
		t.Fatal("buildMFA: want error on sqlite backend without DSN")
	}
}

// TestBuildMFA_UnknownBackendRejected guards against config typos in
// mfa.challenge.backend (e.g. "redis" before that lands).
func TestBuildMFA_UnknownBackendRejected(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	_, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{Kind: "totp"},
		Challenge: config.MFAChallengeConfig{Backend: "redis"},
	}, totpAuth, quietLogger())
	if err == nil {
		t.Fatal("buildMFA: want error on unknown challenge backend")
	}
}

// TestBuildMFA_DefaultBackendIsMemory proves an empty Backend string
// falls through to memory (matches the rest of cmd's backend
// selectors).
func TestBuildMFA_DefaultBackendIsMemory(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	_, store, _, mode, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{Kind: "totp"},
		Challenge: config.MFAChallengeConfig{}, // Backend unset
	}, totpAuth, quietLogger())
	if err != nil {
		t.Fatalf("buildMFA: %v", err)
	}
	if store == nil {
		t.Fatal("store nil with default backend")
	}
	if mode == "" || mode[:6] != "memory" {
		t.Fatalf("mode: got %q want memory*", mode)
	}
}

// TestBuildMFA_ZeroTTLPassesThrough proves cmd doesn't pre-apply a
// default — it forwards 0, and the SDK's WithMFAChallengeStore
// upgrades 0 to DefaultMFAChallengeTTL on the SDK side. Keeps the
// default-policy decision single-source in the SDK rather than
// scattered across config wrappers.
func TestBuildMFA_ZeroTTLPassesThrough(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	_, _, ttl, _, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{Kind: "totp"},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, totpAuth, quietLogger())
	if err != nil {
		t.Fatalf("buildMFA: %v", err)
	}
	if ttl != 0 {
		t.Fatalf("ttl: got %v want 0 (SDK applies its own default)", ttl)
	}
}

// TestBuildMFA_StoreSurfacesNotFoundSentinel sanity-checks that the
// wired store returns the sso.ErrMFAChallengeNotFound sentinel on
// missing IDs — anti-enumeration depends on this.
func TestBuildMFA_StoreSurfacesNotFoundSentinel(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	_, store, _, _, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{Kind: "totp"},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, totpAuth, quietLogger())
	if err != nil {
		t.Fatalf("buildMFA: %v", err)
	}
	_, err = store.Consume(context.Background(), "missing-id")
	if !errors.Is(err, sso.ErrMFAChallengeNotFound) {
		t.Fatalf("Consume(missing): got %v want sso.ErrMFAChallengeNotFound", err)
	}
}
