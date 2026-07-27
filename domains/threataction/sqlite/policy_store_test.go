package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/threataction"
	tsqlite "github.com/yangwb1123/snaplink/domains/threataction/sqlite"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

func newStore(t *testing.T) *tsqlite.ThreatPolicyStore {
	t.Helper()
	s, err := tsqlite.New("file:" + t.TempDir() + "/threat_policies.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestThreatPolicyStore_CRUD(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)

	// List empty store.
	policies, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(policies) != 0 {
		t.Fatalf("expected 0 policies, got %d", len(policies))
	}

	// Get non-existent.
	if _, err := store.Get(ctx, "nonexistent"); !errors.Is(err, threataction.ErrPolicyNotFound) {
		t.Fatalf("expected ErrPolicyNotFound, got %v", err)
	}

	// Put first policy.
	p1 := threataction.ThreatPolicy{
		Name:    "critical-suspend",
		Enabled: true,
		Type:    "impossible_travel",
		Action:  threataction.ActionSuspend,
	}
	if err := store.Put(ctx, p1); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Put second policy.
	p2 := threataction.ThreatPolicy{
		Name:    "warn-notify",
		Enabled: true,
		Type:    "impossible_travel",
		Action:  threataction.ActionNotify,
	}
	if err := store.Put(ctx, p2); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// List returns both, sorted by name (deterministic first-match ordering).
	policies, err = store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}
	if policies[0].Name != "critical-suspend" {
		t.Errorf("expected first policy name critical-suspend, got %s", policies[0].Name)
	}
	if policies[1].Name != "warn-notify" {
		t.Errorf("expected second policy name warn-notify, got %s", policies[1].Name)
	}

	// Get existing policy.
	got, err := store.Get(ctx, "critical-suspend")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Action != threataction.ActionSuspend {
		t.Errorf("expected suspend action, got %s", got.Action)
	}

	// Delete policy.
	if err := store.Delete(ctx, "critical-suspend"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	policies, err = store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy after delete, got %d", len(policies))
	}

	// Delete non-existent.
	if err := store.Delete(ctx, "nonexistent"); !errors.Is(err, threataction.ErrPolicyNotFound) {
		t.Fatalf("expected ErrPolicyNotFound, got %v", err)
	}

	// Upsert replaces existing (true upsert: same name twice, second wins).
	updated := threataction.ThreatPolicy{
		Name:    "warn-notify",
		Enabled: false,
		Type:    "velocity_burst",
		Action:  threataction.ActionNoop,
	}
	if err := store.Put(ctx, updated); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err = store.Get(ctx, "warn-notify")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Enabled {
		t.Error("expected policy to be disabled after update")
	}
	if got.Type != "velocity_burst" {
		t.Errorf("expected type velocity_burst, got %s", got.Type)
	}
	// The upsert must not create a second row under the same name.
	if policies, err := store.List(ctx); err != nil || len(policies) != 1 {
		t.Fatalf("expected upsert to keep exactly 1 policy, got %d (%v)", len(policies), err)
	}
}

// TestThreatPolicyStore_RoundTripNestedFields proves RateLimit and Conditions
// (both optional, nested sub-structs) survive the JSON-blob serialization
// intact — the reason this store isn't fully normalized into columns.
func TestThreatPolicyStore_RoundTripNestedFields(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)

	p := threataction.ThreatPolicy{
		Name:     "rate-limited-suspend",
		Enabled:  true,
		Type:     "impossible_travel",
		Severity: "warn+critical",
		Action:   threataction.ActionSuspend,
		RateLimit: &threataction.RateLimitPolicy{
			PerWindow: threataction.Duration{Duration: time.Hour},
			Max:       3,
		},
		Conditions: threataction.ThreatConditions{
			Key:      "risk_score",
			Operator: "gt",
			Value:    "0.8",
		},
	}
	if err := store.Put(ctx, p); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := store.Get(ctx, "rate-limited-suspend")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.RateLimit == nil {
		t.Fatal("expected RateLimit to survive round-trip, got nil")
	}
	if got.RateLimit.Max != 3 || got.RateLimit.PerWindow.Duration != time.Hour {
		t.Errorf("RateLimit round-trip mismatch: %+v", got.RateLimit)
	}
	if got.Conditions.Key != "risk_score" || got.Conditions.Operator != "gt" || got.Conditions.Value != "0.8" {
		t.Errorf("Conditions round-trip mismatch: %+v", got.Conditions)
	}
	if got.Severity != "warn+critical" {
		t.Errorf("Severity round-trip mismatch: %q", got.Severity)
	}

	// Round-trip through List too.
	policies, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(policies) != 1 || policies[0].RateLimit == nil || policies[0].RateLimit.Max != 3 {
		t.Fatalf("List round-trip mismatch: %+v", policies)
	}

	// A policy with no RateLimit must decode back to nil, not a zero-value struct.
	if err := store.Put(ctx, threataction.ThreatPolicy{Name: "no-rate-limit", Action: threataction.ActionNoop}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got2, err := store.Get(ctx, "no-rate-limit")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got2.RateLimit != nil {
		t.Errorf("expected nil RateLimit for a policy that never set one, got %+v", got2.RateLimit)
	}
}

func TestThreatPolicyStore_FirstMatchOrdering(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)

	_ = store.Put(ctx, threataction.ThreatPolicy{Name: "b-critical", Enabled: true, Action: threataction.ActionSuspend})
	_ = store.Put(ctx, threataction.ThreatPolicy{Name: "a-warn", Enabled: true, Action: threataction.ActionNotify})

	policies, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}
	if policies[0].Name != "a-warn" {
		t.Errorf("expected first policy 'a-warn', got %s", policies[0].Name)
	}
}

// TestThreatPolicyStore_PersistsAcrossReopen proves the whole point of this
// backend over the memory store: policies survive a process restart because
// they live in the sqlite file, not in a process-local map.
func TestThreatPolicyStore_PersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + t.TempDir() + "/reopen.db"

	s1, err := tsqlite.New(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Put(ctx, threataction.ThreatPolicy{Name: "survives-restart", Action: threataction.ActionSuspend}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := tsqlite.New(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	got, err := s2.Get(ctx, "survives-restart")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if got.Action != threataction.ActionSuspend {
		t.Errorf("policy did not survive reopen intact: %+v", got)
	}
}

// TestThreatPolicyStore_Ping proves the readiness-probe wiring point works
// against a real handle and reports closed after Close.
func TestThreatPolicyStore_Ping(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	if err := store.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := store.Ping(ctx); err == nil {
		t.Error("expected Ping to fail after Close")
	}
}

// TestThreatPolicyMaxVersion_MatchesLiveSchema proves the exported
// MaxVersion function used by cmd's boot-time schema guard
// (serverbuildsign.CheckSQLiteSchema) reflects the same version a fresh
// store actually migrates to: CheckSchema must accept the live DB against
// its own advertised max, and reject a binary that only knows an older one.
func TestThreatPolicyMaxVersion_MatchesLiveSchema(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	max := tsqlite.ThreatPolicyMaxVersion()

	if err := migrate.CheckSchema(ctx, store.DB(), "threat_policies", max); err != nil {
		t.Errorf("CheckSchema at binary's own max version: %v", err)
	}
	if err := migrate.CheckSchema(ctx, store.DB(), "threat_policies", max-1); !errors.Is(err, migrate.ErrSchemaTooNew) {
		t.Errorf("expected ErrSchemaTooNew for an older binary, got %v", err)
	}
}
