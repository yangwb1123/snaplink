package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/authenticators/webauthn"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/spi"
)

// TestBuildMFA_DisabledReturnsZeroes proves cmd skips MFA wiring
// entirely when mfa.enabled=false. Risk scorers returning
// DecisionRequireMFA then decay to Allow (back-compat preserved).
func TestBuildMFA_DisabledReturnsZeroes(t *testing.T) {
	provider, store, ttl, mode, _, _, err := buildMFA(config.MFAConfig{Enabled: false}, nil, nil, quietLogger())
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
	provider, store, ttl, mode, _, _, err := buildMFA(config.MFAConfig{
		Enabled:  true,
		Provider: config.MFAProviderConfig{Kind: "totp"},
		Challenge: config.MFAChallengeConfig{
			Backend: "memory",
			TTL:     3 * time.Minute,
		},
	}, totpAuth, nil, quietLogger())
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
	provider, store, _, mode, _, _, err := buildMFA(config.MFAConfig{
		Enabled:  true,
		Provider: config.MFAProviderConfig{Kind: "totp"},
		Challenge: config.MFAChallengeConfig{
			Backend: "sqlite",
			SQLite:  config.MFAChallengeSQLiteConfig{DSN: dsn},
		},
	}, totpAuth, nil, quietLogger())
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
	c := &spi.MFAChallenge{
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
	provider, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{}, // Kind unset
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, totpAuth, nil, quietLogger())
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
	_, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{Kind: "totp"},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, nil, nil, quietLogger())
	if err == nil {
		t.Fatal("buildMFA: want error when totp provider requested without TOTPAuthenticator")
	}
}

// TestBuildMFA_UnknownKindRejected covers the typo / misconfig path
// where an operator writes mfa.provider.kind=fido2 expecting it to
// "just work". Fail loud — silent fallback to TOTP would surprise.
func TestBuildMFA_UnknownKindRejected(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	_, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{Kind: "fido2"},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, totpAuth, nil, quietLogger())
	if err == nil {
		t.Fatal("buildMFA: want error on unknown provider kind")
	}
}

// TestBuildMFA_SQLiteRequiresDSN proves the SQLite challenge backend
// fails loud when DSN is missing — silently falling back to memory
// would defeat the cluster-shared invariant.
func TestBuildMFA_SQLiteRequiresDSN(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	_, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{Kind: "totp"},
		Challenge: config.MFAChallengeConfig{Backend: "sqlite"}, // SQLite.DSN unset
	}, totpAuth, nil, quietLogger())
	if err == nil {
		t.Fatal("buildMFA: want error on sqlite backend without DSN")
	}
}

// TestBuildMFA_UnknownBackendRejected guards against config typos in
// mfa.challenge.backend (e.g. "redis" before that lands).
func TestBuildMFA_UnknownBackendRejected(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	_, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{Kind: "totp"},
		Challenge: config.MFAChallengeConfig{Backend: "redis"},
	}, totpAuth, nil, quietLogger())
	if err == nil {
		t.Fatal("buildMFA: want error on unknown challenge backend")
	}
}

// TestBuildMFA_DefaultBackendIsMemory proves an empty Backend string
// falls through to memory (matches the rest of cmd's backend
// selectors).
func TestBuildMFA_DefaultBackendIsMemory(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	_, store, _, mode, _, _, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{Kind: "totp"},
		Challenge: config.MFAChallengeConfig{}, // Backend unset
	}, totpAuth, nil, quietLogger())
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
	_, _, ttl, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{Kind: "totp"},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, totpAuth, nil, quietLogger())
	if err != nil {
		t.Fatalf("buildMFA: %v", err)
	}
	if ttl != 0 {
		t.Fatalf("ttl: got %v want 0 (SDK applies its own default)", ttl)
	}
}

// TestBuildMFA_StoreSurfacesNotFoundSentinel sanity-checks that the
// wired store returns the spi.ErrMFAChallengeNotFound sentinel on
// missing IDs — anti-enumeration depends on this.
func TestBuildMFA_StoreSurfacesNotFoundSentinel(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	_, store, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{Kind: "totp"},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, totpAuth, nil, quietLogger())
	if err != nil {
		t.Fatalf("buildMFA: %v", err)
	}
	_, err = store.Consume(context.Background(), "missing-id")
	if !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Fatalf("Consume(missing): got %v want spi.ErrMFAChallengeNotFound", err)
	}
}

// TestBuildMFA_WebAuthnWithMemoryStore proves cmd wires kind=webauthn
// when a webauthnHelper is supplied. The provider is the WebAuthn
// step-up adapter sharing the same Helper instance the primary
// /webauthn/login/{begin,finish} routes use.
func TestBuildMFA_WebAuthnWithMemoryStore(t *testing.T) {
	helper, err := webauthn.NewHelper(webauthn.Config{
		RPID:      "example.com",
		RPOrigins: []string{"https://sso.example.com"},
	}, webauthn.NewMemoryUserStore(), webauthn.NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewHelper: %v", err)
	}
	provider, store, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{Kind: "webauthn"},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, nil, helper, quietLogger())
	if err != nil {
		t.Fatalf("buildMFA: %v", err)
	}
	if provider == nil || store == nil {
		t.Fatalf("provider/store nil: provider=%v store=%v", provider, store)
	}
	methods := provider.SupportedMethods()
	if len(methods) != 1 || methods[0] != webauthn.MethodWebAuthn {
		t.Fatalf("SupportedMethods = %v, want [webauthn]", methods)
	}
	// Webauthn provider implements MFABeginner — the wired interface
	// type assertion is what unblocks step-up factors needing
	// server-side challenge issuance.
	if _, ok := provider.(spi.MFABeginner); !ok {
		t.Errorf("wired provider does not satisfy spi.MFABeginner — Begin dispatch won't fire")
	}
}

// TestBuildMFA_WebAuthnRequiresHelper proves cmd refuses to wire
// kind=webauthn without a webauthn.enabled wiring. Silent fallthrough
// (e.g. degrading to TOTP) would surprise operators.
func TestBuildMFA_WebAuthnRequiresHelper(t *testing.T) {
	_, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled:   true,
		Provider:  config.MFAProviderConfig{Kind: "webauthn"},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, nil, nil, quietLogger())
	if err == nil {
		t.Fatal("buildMFA: want error when webauthn provider requested without Helper")
	}
}

func newTestWebAuthnHelper(t *testing.T) *webauthn.Helper {
	t.Helper()
	h, err := webauthn.NewHelper(webauthn.Config{
		RPID:      "example.com",
		RPOrigins: []string{"https://sso.example.com"},
	}, webauthn.NewMemoryUserStore(), webauthn.NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewHelper: %v", err)
	}
	return h
}

// TestBuildMFA_MultiKindComposesBothFactors proves kind=multi with a
// totp + webauthn Kinds list wires a MultiMFAProvider that lists
// both methods. The composite implements MFABeginner so the two-call
// dispatch path for WebAuthn still works alongside the single-call
// TOTP factor.
func TestBuildMFA_MultiKindComposesBothFactors(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	helper := newTestWebAuthnHelper(t)
	provider, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled: true,
		Provider: config.MFAProviderConfig{
			Kind:  "multi",
			Kinds: []string{"totp", "webauthn"},
		},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, totpAuth, helper, quietLogger())
	if err != nil {
		t.Fatalf("buildMFA: %v", err)
	}
	methods := provider.SupportedMethods()
	wantSet := map[string]bool{authenticators.MethodTOTP: false, webauthn.MethodWebAuthn: false}
	for _, m := range methods {
		if _, ok := wantSet[m]; ok {
			wantSet[m] = true
		}
	}
	for m, seen := range wantSet {
		if !seen {
			t.Errorf("composite missing method %q (got %v)", m, methods)
		}
	}
	if _, ok := provider.(spi.MFABeginner); !ok {
		t.Error("composite should implement MFABeginner so WebAuthn dispatch fires")
	}
}

// TestBuildMFA_MultiRequiresTwoKinds proves an empty or single-entry
// Kinds list when kind=multi errors loudly — a one-element multi is
// a misconfiguration (use the leaf kind directly).
func TestBuildMFA_MultiRequiresTwoKinds(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	for _, tc := range []struct {
		name  string
		kinds []string
	}{
		{"empty", nil},
		{"single", []string{"totp"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, _, _, err := buildMFA(config.MFAConfig{
				Enabled: true,
				Provider: config.MFAProviderConfig{
					Kind:  "multi",
					Kinds: tc.kinds,
				},
				Challenge: config.MFAChallengeConfig{Backend: "memory"},
			}, totpAuth, nil, quietLogger())
			if err == nil {
				t.Fatalf("want error for kinds=%v", tc.kinds)
			}
		})
	}
}

// TestBuildMFA_MultiRejectsNestedMulti proves nesting kind=multi
// inside another multi is forbidden — keeps the operator surface
// flat (one level of composition; richer trees implement
// MFAProvider directly in the SDK).
func TestBuildMFA_MultiRejectsNestedMulti(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	_, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled: true,
		Provider: config.MFAProviderConfig{
			Kind:  "multi",
			Kinds: []string{"totp", "multi"},
		},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, totpAuth, nil, quietLogger())
	if err == nil {
		t.Fatal("want error when kinds list contains 'multi'")
	}
}

// TestBuildMFA_MultiRejectsDuplicateKinds proves duplicate entries
// in the Kinds list error loudly — the underlying MultiMFAProvider
// would also reject via method-conflict, but failing earlier (at
// the YAML layer) gives operators a clearer error.
func TestBuildMFA_MultiRejectsDuplicateKinds(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	_, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled: true,
		Provider: config.MFAProviderConfig{
			Kind:  "multi",
			Kinds: []string{"totp", "totp"},
		},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, totpAuth, nil, quietLogger())
	if err == nil {
		t.Fatal("want error on duplicate kinds entry")
	}
}

// TestBuildMFA_MultiPropagatesInnerKindError proves an inner kind
// failing to build (e.g. webauthn without helper) surfaces as a
// wrapped error naming which inner kind failed — operators see
// the leaf kind in the error string for fast diagnosis.
func TestBuildMFA_MultiPropagatesInnerKindError(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	_, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled: true,
		Provider: config.MFAProviderConfig{
			Kind:  "multi",
			Kinds: []string{"totp", "webauthn"},
		},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, totpAuth, nil, quietLogger()) // webauthnHelper=nil
	if err == nil {
		t.Fatal("want error when inner webauthn kind has no helper")
	}
}

// TestBuildMFA_PushKindWithMemoryStore proves kind=push wires the
// reference PushMFAProvider with the default log transport + in-
// process MemoryPushApprovalStore. Backend="" → memory fallthrough.
func TestBuildMFA_PushKindWithMemoryStore(t *testing.T) {
	provider, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled: true,
		Provider: config.MFAProviderConfig{
			Kind: "push",
			Push: config.MFAPushConfig{}, // all defaults
		},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, nil, nil, quietLogger())
	if err != nil {
		t.Fatalf("buildMFA: %v", err)
	}
	if provider == nil {
		t.Fatal("provider nil with kind=push + defaults")
	}
	methods := provider.SupportedMethods()
	if len(methods) != 1 || methods[0] != defaultimpl.MethodPush {
		t.Fatalf("SupportedMethods = %v, want [push]", methods)
	}
	// Push provider implements MFABeginner so the mfa_required
	// response can carry the approval_id back to the client.
	if _, ok := provider.(spi.MFABeginner); !ok {
		t.Error("push provider should satisfy spi.MFABeginner")
	}
}

// TestBuildMFA_PushKindWithSQLiteStore proves the cluster-shared
// path: PushApprovalStore backed by SQLite so Begin on one replica
// is resolvable by the callback on another.
func TestBuildMFA_PushKindWithSQLiteStore(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "push.db") + "?_journal=WAL"
	provider, _, _, _, sqliteStore, _, err := buildMFA(config.MFAConfig{
		Enabled: true,
		Provider: config.MFAProviderConfig{
			Kind: "push",
			Push: config.MFAPushConfig{
				Backend: "sqlite",
				SQLite:  config.MFAPushSQLiteConfig{DSN: dsn},
			},
		},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, nil, nil, quietLogger())
	if err != nil {
		t.Fatalf("buildMFA: %v", err)
	}
	if provider == nil {
		t.Fatal("provider nil with kind=push + sqlite backend")
	}
	// The SQLite store handle MUST surface so cmd can register a
	// /readyz check + the optional PruneExpired loop. The memory
	// path returns nil; the sqlite path returns the concrete type.
	if sqliteStore == nil {
		t.Fatal("sqlite push store handle nil — readyz wiring is broken")
	}
}

// TestBuildMFA_PushKindMemoryReturnsNilStore proves the memory
// backend does NOT surface a SQLite handle (there is none). cmd
// uses the nil signal to skip /readyz wiring for memory deployments.
func TestBuildMFA_PushKindMemoryReturnsNilStore(t *testing.T) {
	_, _, _, _, sqliteStore, _, err := buildMFA(config.MFAConfig{
		Enabled: true,
		Provider: config.MFAProviderConfig{
			Kind: "push",
			Push: config.MFAPushConfig{Backend: "memory"},
		},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, nil, nil, quietLogger())
	if err != nil {
		t.Fatalf("buildMFA: %v", err)
	}
	if sqliteStore != nil {
		t.Fatalf("memory backend should not surface a SQLite handle: %v", sqliteStore)
	}
}

// TestBuildMFA_MultiWithPushSQLiteCapture proves the SQLite push
// store handle survives kind=multi recursion — operators wiring
// kind=multi + kinds=[totp, push] with push.backend=sqlite still
// get the readyz handle.
func TestBuildMFA_MultiWithPushSQLiteCapture(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "push.db") + "?_journal=WAL"
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	_, _, _, _, sqliteStore, _, err := buildMFA(config.MFAConfig{
		Enabled: true,
		Provider: config.MFAProviderConfig{
			Kind:  "multi",
			Kinds: []string{"totp", "push"},
			Push: config.MFAPushConfig{
				Backend: "sqlite",
				SQLite:  config.MFAPushSQLiteConfig{DSN: dsn},
			},
		},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, totpAuth, nil, quietLogger())
	if err != nil {
		t.Fatalf("buildMFA: %v", err)
	}
	if sqliteStore == nil {
		t.Fatal("multi recursion lost the SQLite push store handle — readyz wiring is broken")
	}
}

// TestBuildMFA_PushKindRequiresSQLiteDSN proves cmd refuses
// kind=push backend=sqlite without a DSN (same fail-loud pattern
// as every other sqlite backend slot).
func TestBuildMFA_PushKindRequiresSQLiteDSN(t *testing.T) {
	_, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled: true,
		Provider: config.MFAProviderConfig{
			Kind: "push",
			Push: config.MFAPushConfig{Backend: "sqlite"}, // DSN unset
		},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, nil, nil, quietLogger())
	if err == nil {
		t.Fatal("want error when push sqlite backend missing DSN")
	}
}

// TestBuildMFA_PushKindRejectsUnknownBackend covers the typo case.
func TestBuildMFA_PushKindRejectsUnknownBackend(t *testing.T) {
	_, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled: true,
		Provider: config.MFAProviderConfig{
			Kind: "push",
			Push: config.MFAPushConfig{Backend: "redis"},
		},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, nil, nil, quietLogger())
	if err == nil {
		t.Fatal("want error on unknown push backend")
	}
}

// TestBuildMFA_PushKindRejectsUnknownTransport covers the typo case
// for the transport selector (log + webhook ship today; others
// would surprise an operator into silent push-delivery failures).
func TestBuildMFA_PushKindRejectsUnknownTransport(t *testing.T) {
	_, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled: true,
		Provider: config.MFAProviderConfig{
			Kind: "push",
			Push: config.MFAPushConfig{Transport: "fcm"},
		},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, nil, nil, quietLogger())
	if err == nil {
		t.Fatal("want error on unknown push transport")
	}
}

// TestBuildMFA_PushWebhookHappyPath proves transport=webhook with
// a URL builds successfully. The transport itself is exercised in
// defaultimpl/push_webhook_test.go.
func TestBuildMFA_PushWebhookHappyPath(t *testing.T) {
	provider, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled: true,
		Provider: config.MFAProviderConfig{
			Kind: "push",
			Push: config.MFAPushConfig{
				Transport: "webhook",
				Webhook: config.MFAPushWebhookConfig{
					URL: "https://gateway.internal/push",
				},
			},
		},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, nil, nil, quietLogger())
	if err != nil {
		t.Fatalf("buildMFA: %v", err)
	}
	if provider == nil {
		t.Fatal("provider nil with transport=webhook")
	}
}

// TestBuildMFA_PushWebhookRequiresURL fails loud — operators who
// flip transport=webhook without setting URL would otherwise get
// silent push-delivery failures.
func TestBuildMFA_PushWebhookRequiresURL(t *testing.T) {
	_, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled: true,
		Provider: config.MFAProviderConfig{
			Kind: "push",
			Push: config.MFAPushConfig{Transport: "webhook"}, // URL missing
		},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, nil, nil, quietLogger())
	if err == nil {
		t.Fatal("want error when webhook URL missing")
	}
}

// TestBuildMFA_PushKindAppliesPollAndMaxWait proves the timing
// overrides flow through to the provider construction. We can't
// inspect the provider state directly, but if the constructor
// silently dropped them the build would still succeed (no test
// signal) — so this is a smoke test that buildMFA at least accepts
// the YAML knobs without erroring.
func TestBuildMFA_PushKindAppliesPollAndMaxWait(t *testing.T) {
	provider, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled: true,
		Provider: config.MFAProviderConfig{
			Kind: "push",
			Push: config.MFAPushConfig{
				PollInterval: 250 * time.Millisecond,
				MaxWait:      30 * time.Second,
			},
		},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, nil, nil, quietLogger())
	if err != nil {
		t.Fatalf("buildMFA: %v", err)
	}
	if provider == nil {
		t.Fatal("provider nil")
	}
}

// TestBuildMFA_MultiWithPushInner proves push works alongside
// totp + webauthn in a kind=multi composition.
func TestBuildMFA_MultiWithPushInner(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	provider, _, _, _, _, _, err := buildMFA(config.MFAConfig{
		Enabled: true,
		Provider: config.MFAProviderConfig{
			Kind:  "multi",
			Kinds: []string{"totp", "push"},
			Push:  config.MFAPushConfig{}, // memory + log defaults
		},
		Challenge: config.MFAChallengeConfig{Backend: "memory"},
	}, totpAuth, nil, quietLogger())
	if err != nil {
		t.Fatalf("buildMFA: %v", err)
	}
	methods := provider.SupportedMethods()
	wantSet := map[string]bool{authenticators.MethodTOTP: false, defaultimpl.MethodPush: false}
	for _, m := range methods {
		if _, ok := wantSet[m]; ok {
			wantSet[m] = true
		}
	}
	for m, seen := range wantSet {
		if !seen {
			t.Errorf("composite missing method %q (got %v)", m, methods)
		}
	}
}
