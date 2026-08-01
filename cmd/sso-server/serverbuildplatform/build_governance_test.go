package serverbuildplatform

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/conditionalaccess"
	"github.com/yangwb1123/snaplink/domains/threataction"
	"github.com/yangwb1123/snaplink/domains/tokenanomaly"
	"github.com/yangwb1123/snaplink/domains/tokenpolicy"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/configaudit"
	"github.com/yangwb1123/snaplink/shared/core/corecredential"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func govLogger() spi.Logger { return spi.NopLogger{} }

func TestBuildCredentialRotation_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	reg, sched, err := BuildCredentialRotation(config.RotationConfig{}, config.ClientSecretRotationConfig{}, nil, nil, govLogger(), nil)
	if err != nil {
		t.Fatalf("BuildCredentialRotation: %v", err)
	}
	if reg != nil || sched != nil {
		t.Fatalf("disabled rotation must return (nil, nil); got reg=%v sched=%v", reg, sched)
	}
}

func TestBuildCredentialRotation_EnabledRegistersWebhookRotator(t *testing.T) {
	t.Parallel()
	cfg := config.RotationConfig{Enabled: true, Interval: time.Hour, Overlap: time.Minute}
	reg, sched, err := BuildCredentialRotation(cfg, config.ClientSecretRotationConfig{}, []byte("seed-secret"), nil, govLogger(), nil)
	if err != nil {
		t.Fatalf("BuildCredentialRotation: %v", err)
	}
	if reg == nil || sched == nil {
		t.Fatal("enabled rotation must return a registry + scheduler")
	}
	inv := reg.Inventory()
	if len(inv) != 1 {
		t.Fatalf("inventory = %d entries; want 1 (the webhook rotator)", len(inv))
	}
	if inv[0].Type != corecredential.CredentialTypeWebhookHMAC {
		t.Errorf("inventory type = %q; want %q", inv[0].Type, corecredential.CredentialTypeWebhookHMAC)
	}
}

func TestBuildCredentialRotation_RequiresIntervalWhenEnabled(t *testing.T) {
	t.Parallel()
	cfg := config.RotationConfig{Enabled: true} // Interval left 0
	if _, _, err := BuildCredentialRotation(cfg, config.ClientSecretRotationConfig{}, nil, nil, govLogger(), nil); err == nil {
		t.Fatal("expected error: rotation.interval required when enabled")
	}
}

// TestBuildCredentialRotation_ClientSecretRotationEnabledRegistersRotator
// proves the client-secret rotator registers onto the SAME registry the
// webhook rotator uses (one shared Scheduler running both, at potentially
// different cadences), independent of whether the webhook feature is on.
func TestBuildCredentialRotation_ClientSecretRotationEnabledRegistersRotator(t *testing.T) {
	t.Parallel()
	clientCfg := config.ClientSecretRotationConfig{Enabled: true, Interval: 24 * time.Hour}
	store := defaultimpl.NewMemoryClientStore()
	reg, sched, err := BuildCredentialRotation(config.RotationConfig{}, clientCfg, nil, store, govLogger(), nil)
	if err != nil {
		t.Fatalf("BuildCredentialRotation: %v", err)
	}
	if reg == nil || sched == nil {
		t.Fatal("enabled client_secret_rotation must return a registry + scheduler")
	}
	inv := reg.Inventory()
	if len(inv) != 1 {
		t.Fatalf("inventory = %d entries; want 1 (the client-secret rotator)", len(inv))
	}
	if inv[0].Type != corecredential.CredentialTypeOAuthClientSecret {
		t.Errorf("inventory type = %q; want %q", inv[0].Type, corecredential.CredentialTypeOAuthClientSecret)
	}
}

// TestBuildCredentialRotation_BothEnabledShareOneRegistry proves BOTH
// rotators land on the same Registry (two inventory entries) when both
// features are enabled together, at independent cadences.
func TestBuildCredentialRotation_BothEnabledShareOneRegistry(t *testing.T) {
	t.Parallel()
	cfg := config.RotationConfig{Enabled: true, Interval: time.Hour}
	clientCfg := config.ClientSecretRotationConfig{Enabled: true, Interval: 24 * time.Hour}
	store := defaultimpl.NewMemoryClientStore()
	reg, sched, err := BuildCredentialRotation(cfg, clientCfg, nil, store, govLogger(), nil)
	if err != nil {
		t.Fatalf("BuildCredentialRotation: %v", err)
	}
	if reg == nil || sched == nil {
		t.Fatal("expected a registry + scheduler")
	}
	inv := reg.Inventory()
	if len(inv) != 2 {
		t.Fatalf("inventory = %d entries; want 2 (webhook + client-secret rotators)", len(inv))
	}
}

func TestBuildCredentialRotation_ClientSecretRotationRequiresInterval(t *testing.T) {
	t.Parallel()
	clientCfg := config.ClientSecretRotationConfig{Enabled: true} // Interval left 0
	store := defaultimpl.NewMemoryClientStore()
	if _, _, err := BuildCredentialRotation(config.RotationConfig{}, clientCfg, nil, store, govLogger(), nil); err == nil {
		t.Fatal("expected error: client_secret_rotation.interval required when enabled")
	}
}

func TestBuildCredentialRotation_ClientSecretRotationRejectsShortOverlap(t *testing.T) {
	t.Parallel()
	clientCfg := config.ClientSecretRotationConfig{
		Enabled: true, Interval: 24 * time.Hour, Overlap: 30 * time.Minute,
	}
	store := defaultimpl.NewMemoryClientStore()
	if _, _, err := BuildCredentialRotation(config.RotationConfig{}, clientCfg, nil, store, govLogger(), nil); err == nil {
		t.Fatal("expected overlap shorter than one hour to fail closed")
	}
}

func TestBuildCredentialRotation_ClientSecretRotationRejectsLifetimeAtInterval(t *testing.T) {
	t.Parallel()
	clientCfg := config.ClientSecretRotationConfig{
		Enabled: true, Interval: 24 * time.Hour, Overlap: time.Hour, Lifetime: 24 * time.Hour,
	}
	store := defaultimpl.NewMemoryClientStore()
	if _, _, err := BuildCredentialRotation(config.RotationConfig{}, clientCfg, nil, store, govLogger(), nil); err == nil {
		t.Fatal("expected lifetime at the rotation interval to fail closed")
	}
}

func TestBuildCredentialRotation_ClientSecretRotationRequiresClientStore(t *testing.T) {
	t.Parallel()
	clientCfg := config.ClientSecretRotationConfig{Enabled: true, Interval: time.Hour}
	if _, _, err := BuildCredentialRotation(config.RotationConfig{}, clientCfg, nil, nil, govLogger(), nil); err == nil {
		t.Fatal("expected error: client_secret_rotation.enabled requires a configured client store")
	}
}

// TestBuildCredentialRotation_ClientSecretRotationRequiresLister proves a
// ClientStore that doesn't implement clientrotation.ClientRotationLister
// (e.g. a hand-rolled or third-party backend) fails loud at boot rather than
// silently never rotating anything.
func TestBuildCredentialRotation_ClientSecretRotationRequiresLister(t *testing.T) {
	t.Parallel()
	clientCfg := config.ClientSecretRotationConfig{Enabled: true, Interval: time.Hour}
	if _, _, err := BuildCredentialRotation(config.RotationConfig{}, clientCfg, nil, listerlessClientStore{}, govLogger(), nil); err == nil {
		t.Fatal("expected error: store without ClientRotationLister must be rejected")
	}
}

// listerlessClientStore is a minimal sso.ClientStore that deliberately does
// NOT implement clientrotation.ClientRotationLister, proving the build-time
// validation rejects it rather than silently registering a rotator that
// would never find anything due.
type listerlessClientStore struct{ sso.ClientStore }

func TestBuildConfigAuditStore_MemoryDefault(t *testing.T) {
	t.Parallel()
	for _, backend := range []string{"", "memory", "MEMORY"} {
		store, err := BuildConfigAuditStore(config.ConfigAuditConfig{Backend: backend})
		if err != nil {
			t.Fatalf("backend=%q: %v", backend, err)
		}
		if store == nil {
			t.Fatalf("backend=%q: nil store", backend)
		}
	}
}

func TestBuildConfigAuditStore_Sqlite(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "cfgaudit.db") + "?_journal=WAL"
	store, err := BuildConfigAuditStore(config.ConfigAuditConfig{
		Backend: "sqlite",
		Sqlite:  config.ConfigAuditSqliteConfig{DSN: dsn},
	})
	if err != nil {
		t.Fatalf("BuildConfigAuditStore(sqlite): %v", err)
	}
	c, ok := store.(io.Closer)
	if !ok {
		t.Fatal("sqlite config-audit store must be an io.Closer")
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestBuildConfigAuditStore_SqliteRequiresDSN(t *testing.T) {
	t.Parallel()
	if _, err := BuildConfigAuditStore(config.ConfigAuditConfig{Backend: "sqlite"}); err == nil {
		t.Fatal("expected error: sqlite backend requires a dsn")
	}
}

func TestBuildConfigAuditStore_UnknownBackend(t *testing.T) {
	t.Parallel()
	if _, err := BuildConfigAuditStore(config.ConfigAuditConfig{Backend: "redis"}); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

// TestEffectiveConfigSnapshot_RedactsAndIsDigestible proves the snapshot
// scrubs credential-bearing leaves (so an operator-visible snapshot never
// leaks a secret) AND that the result is stable-digestible — configaudit.Digest
// json-marshals it, so a non-JSON-serializable map would fail there.
func TestEffectiveConfigSnapshot_RedactsAndIsDigestible(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Audit.Webhook.SigningSecret = "top-secret-value"
	cfg.Server.Issuer = "https://sso.example.com"

	snap, err := EffectiveConfigSnapshot(cfg)
	if err != nil {
		t.Fatalf("EffectiveConfigSnapshot: %v", err)
	}
	audit, _ := snap["audit"].(map[string]any)
	webhook, _ := audit["webhook"].(map[string]any)
	if got := webhook["signing_secret"]; got != "***" {
		t.Errorf("signing_secret = %v; want redacted %q", got, "***")
	}
	// A non-sensitive leaf survives verbatim.
	server, _ := snap["server"].(map[string]any)
	if got := server["issuer"]; got != "https://sso.example.com" {
		t.Errorf("issuer = %v; want the configured value (non-sensitive, unredacted)", got)
	}
	if _, err := configaudit.Digest(snap); err != nil {
		t.Fatalf("snapshot must be JSON-digestible: %v", err)
	}
}

// --- Wave-3 governance wiring: token policy / conditional access / degradation --

func TestBuildTokenPolicyStore_AbsentReturnsNil(t *testing.T) {
	t.Parallel()
	store, err := BuildTokenPolicyStore(config.TokenPolicyConfig{})
	if err != nil {
		t.Fatalf("BuildTokenPolicyStore: %v", err)
	}
	if store != nil {
		t.Fatalf("absent token_policies must return nil store; got %v", store)
	}
}

func TestBuildTokenPolicyStore_InlinePolicies(t *testing.T) {
	t.Parallel()
	store, err := BuildTokenPolicyStore(config.TokenPolicyConfig{
		Policies: []tokenpolicy.Policy{{Name: "cap", MaxTTL: time.Hour}},
	})
	if err != nil {
		t.Fatalf("BuildTokenPolicyStore: %v", err)
	}
	if store == nil {
		t.Fatal("inline policies must return a store")
	}
	ps, err := store.Policies(context.Background())
	if err != nil || len(ps) != 1 || ps[0].Name != "cap" {
		t.Fatalf("Policies = %v, %v; want the one seeded rule", ps, err)
	}
}

func TestBuildTokenPolicyStore_FileBundle(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "tp.yaml")
	if err := os.WriteFile(p, []byte("token_policies:\n  - name: from-file\n    max_ttl: 15m\n"), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	store, err := BuildTokenPolicyStore(config.TokenPolicyConfig{File: p})
	if err != nil {
		t.Fatalf("BuildTokenPolicyStore(file): %v", err)
	}
	ps, _ := store.Policies(context.Background())
	if len(ps) != 1 || ps[0].Name != "from-file" {
		t.Fatalf("file bundle policies = %v; want one 'from-file' rule", ps)
	}
}

func TestBuildTokenPolicyStore_FileAndInlineConflict(t *testing.T) {
	t.Parallel()
	_, err := BuildTokenPolicyStore(config.TokenPolicyConfig{
		File:     "x.yaml",
		Policies: []tokenpolicy.Policy{{Name: "cap"}},
	})
	if err == nil {
		t.Fatal("expected error: file + inline policies are mutually exclusive")
	}
}

func TestBuildConditionalAccess_AbsentReturnsNil(t *testing.T) {
	t.Parallel()
	store, _, err := BuildConditionalAccess(config.AccessPolicyConfig{})
	if err != nil {
		t.Fatalf("BuildConditionalAccess: %v", err)
	}
	if store != nil {
		t.Fatalf("absent access_policies must return nil store; got %v", store)
	}
}

func TestBuildConditionalAccess_InlinePolicies(t *testing.T) {
	t.Parallel()
	store, capCfg, err := BuildConditionalAccess(config.AccessPolicyConfig{
		DefaultDeny: true,
		Policies:    []conditionalaccess.Policy{{Name: "deny", Enabled: true, Actions: conditionalaccess.Actions{Deny: true}}},
	})
	if err != nil {
		t.Fatalf("BuildConditionalAccess: %v", err)
	}
	if store == nil {
		t.Fatal("inline policies must return a store")
	}
	if !capCfg.DefaultDeny {
		t.Error("engine config must carry default_deny through")
	}
	ps, _ := store.List(context.Background())
	if len(ps) != 1 || ps[0].Name != "deny" {
		t.Fatalf("List = %v; want the one seeded policy", ps)
	}
}

func TestBuildConditionalAccess_EnforceDefaultsFalse(t *testing.T) {
	t.Parallel()
	_, capCfg, err := BuildConditionalAccess(config.AccessPolicyConfig{
		Policies: []conditionalaccess.Policy{{Name: "deny", Enabled: true, Actions: conditionalaccess.Actions{Deny: true}}},
	})
	if err != nil {
		t.Fatalf("BuildConditionalAccess: %v", err)
	}
	if capCfg.Enforce {
		t.Error("Enforce must default to false (advisory-only) when the YAML section omits it")
	}
}

func TestBuildConditionalAccess_EnforcePassesThrough(t *testing.T) {
	t.Parallel()
	_, capCfg, err := BuildConditionalAccess(config.AccessPolicyConfig{
		Enforce:  true,
		Policies: []conditionalaccess.Policy{{Name: "deny", Enabled: true, Actions: conditionalaccess.Actions{Deny: true}}},
	})
	if err != nil {
		t.Fatalf("BuildConditionalAccess: %v", err)
	}
	if !capCfg.Enforce {
		t.Error("engine config must carry enforce through")
	}
}

func TestBuildConditionalAccess_FileAndInlineConflict(t *testing.T) {
	t.Parallel()
	_, _, err := BuildConditionalAccess(config.AccessPolicyConfig{
		File:     "x.yaml",
		Policies: []conditionalaccess.Policy{{Name: "p", Enabled: true}},
	})
	if err == nil {
		t.Fatal("expected error: file + inline are mutually exclusive")
	}
}

func TestBuildConditionalAccess_InvalidInlineRejected(t *testing.T) {
	t.Parallel()
	// An empty policy name fails conditionalaccess.Policy.Validate on Put.
	_, _, err := BuildConditionalAccess(config.AccessPolicyConfig{
		Policies: []conditionalaccess.Policy{{Name: ""}},
	})
	if err == nil {
		t.Fatal("expected error: invalid inline policy rejected")
	}
}

func TestBuildDegradationManager_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	m, err := BuildDegradationManager(config.DegradationConfig{})
	if err != nil {
		t.Fatalf("BuildDegradationManager: %v", err)
	}
	if m != nil {
		t.Fatalf("disabled degradation must return nil; got %v", m)
	}
}

func TestBuildDegradationManager_InitialMode(t *testing.T) {
	t.Parallel()
	m, err := BuildDegradationManager(config.DegradationConfig{Enabled: true, InitialMode: "read_only"})
	if err != nil {
		t.Fatalf("BuildDegradationManager: %v", err)
	}
	if m == nil || m.Mode() != sso.DegradationModeReadOnly {
		t.Fatalf("manager mode = %v; want read_only", m)
	}
}

func TestBuildDegradationManager_DefaultModeNormal(t *testing.T) {
	t.Parallel()
	m, err := BuildDegradationManager(config.DegradationConfig{Enabled: true})
	if err != nil {
		t.Fatalf("BuildDegradationManager: %v", err)
	}
	if m == nil || m.Mode() != sso.DegradationModeNormal {
		t.Fatalf("manager mode = %v; want normal (default)", m)
	}
}

func TestBuildDegradationManager_InvalidMode(t *testing.T) {
	t.Parallel()
	if _, err := BuildDegradationManager(config.DegradationConfig{Enabled: true, InitialMode: "bogus"}); err == nil {
		t.Fatal("expected error: invalid initial_mode")
	}
}

// --- Wave-4 governance wiring: token-anomaly detector -------------------------

func TestBuildTokenAnomaly_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	rec, det, err := BuildTokenAnomaly(config.TokenAnomalyConfig{}, govLogger(), nil)
	if err != nil {
		t.Fatalf("BuildTokenAnomaly: %v", err)
	}
	if rec != nil || det != nil {
		t.Fatalf("disabled token_anomaly must return (nil, nil); got rec=%v det=%v", rec, det)
	}
}

func TestBuildTokenAnomaly_RequiresSweepIntervalWhenEnabled(t *testing.T) {
	t.Parallel()
	// Enabled with SweepInterval left 0 — a sweep with no cadence never emits.
	if _, _, err := BuildTokenAnomaly(config.TokenAnomalyConfig{Enabled: true}, govLogger(), nil); err == nil {
		t.Fatal("expected error: sweep_interval required when token_anomaly.enabled")
	}
}

// TestBuildTokenAnomaly_EnabledCoWiresRecorderAndDetector proves the detector is
// the recorder's store (the decorator co-wiring the whole feature depends on):
// only then does the recorder's drain feed the detector's observation table.
func TestBuildTokenAnomaly_EnabledCoWiresRecorderAndDetector(t *testing.T) {
	t.Parallel()
	cfg := config.TokenAnomalyConfig{Enabled: true, SweepInterval: time.Hour, MaxFindings: 8}
	rec, det, err := BuildTokenAnomaly(cfg, govLogger(), nil)
	if err != nil {
		t.Fatalf("BuildTokenAnomaly: %v", err)
	}
	if rec == nil || det == nil {
		t.Fatal("enabled token_anomaly must return a recorder + detector")
	}
	// The recorder must drain into the detector (the metering.Store decorator),
	// not into a bare aggregation store — otherwise the detector never observes.
	if got, ok := rec.UsageStore().(*tokenanomaly.Detector); !ok || got != det {
		t.Fatalf("recorder store = %T; want the returned *tokenanomaly.Detector (co-wired)", rec.UsageStore())
	}
	if det.Findings() == nil {
		t.Error("detector must expose its finding store for the admin read API")
	}
}

// --- Active ITDR wiring: threat-action executor -------------------------------

func TestBuildThreatAction_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	exec, store, err := BuildThreatAction(config.ThreatActionConfig{}, nil, nil, nil, nil, nil, nil, govLogger())
	if err != nil {
		t.Fatalf("BuildThreatAction: %v", err)
	}
	if exec != nil || store != nil {
		t.Fatalf("disabled threat_action must return (nil, nil); got exec=%v store=%v", exec, store)
	}
}

// TestBuildThreatAction_EnabledSeedsPoliciesAndDispatches proves the P0 wiring
// end to end at the cmd composition layer: an enabled threat_action section
// seeds the policy store from cfg.Policies AND the returned executor actually
// dispatches a matching threat to the right handler — not just that it
// constructs without error.
func TestBuildThreatAction_EnabledSeedsPoliciesAndDispatches(t *testing.T) {
	t.Parallel()
	cfg := config.ThreatActionConfig{
		Enabled: true,
		Policies: []threataction.ThreatPolicy{
			{Name: "critical-travel", Enabled: true, Type: "impossible_travel", Severity: "critical", Action: threataction.ActionNotify},
		},
	}
	exec, store, err := BuildThreatAction(cfg, nil, nil, nil, nil, nil, nil, govLogger())
	if err != nil {
		t.Fatalf("BuildThreatAction: %v", err)
	}
	if exec == nil || store == nil {
		t.Fatal("enabled threat_action must return an executor + policy store")
	}
	policies, err := store.List(context.Background())
	if err != nil || len(policies) != 1 || policies[0].Name != "critical-travel" {
		t.Fatalf("policy store not seeded from cfg.Policies: %+v, err=%v", policies, err)
	}
	result, err := exec.Execute(context.Background(), threataction.Threat{
		Type: "impossible_travel", Severity: "critical", SubjectID: "alice",
	}, threataction.ThreatPolicy{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Action != threataction.ActionNotify || !result.OK {
		t.Errorf("Execute result = %+v, want a successful notify (policy matched)", result)
	}
}

// TestBuildThreatAction_ChallengeActionHasHandler proves a policy targeting
// action: challenge dispatches successfully — regression coverage for the
// gap where ActionChallenge had no registered handler and every "challenge"
// policy silently failed with "no handler registered" (audited, never
// crashed, but the action never actually happened).
func TestBuildThreatAction_ChallengeActionHasHandler(t *testing.T) {
	t.Parallel()
	cfg := config.ThreatActionConfig{
		Enabled: true,
		Policies: []threataction.ThreatPolicy{
			{Name: "new-device-challenge", Enabled: true, Type: "new_device", Action: threataction.ActionChallenge},
		},
	}
	exec, _, err := BuildThreatAction(cfg, nil, nil, nil, nil, nil, nil, govLogger())
	if err != nil {
		t.Fatalf("BuildThreatAction: %v", err)
	}
	result, err := exec.Execute(context.Background(), threataction.Threat{
		Type: "new_device", SubjectID: "carol",
	}, threataction.ThreatPolicy{})
	if err != nil {
		t.Fatalf("Execute: %v (action: challenge must have a registered handler)", err)
	}
	if result.Action != threataction.ActionChallenge {
		t.Errorf("Execute result action = %q, want %q", result.Action, threataction.ActionChallenge)
	}
}

// TestBuildThreatAction_NilDependenciesStillBuildAndFailOpen proves the
// executor is safe to construct even when sessionMgr/familyRevoker/bus are
// all nil (a minimal deployment with no session store or refresh-token family
// tracking wired yet) — suspend/revoke handlers must fail-open, not panic.
func TestBuildThreatAction_NilDependenciesStillBuildAndFailOpen(t *testing.T) {
	t.Parallel()
	cfg := config.ThreatActionConfig{
		Enabled: true,
		Policies: []threataction.ThreatPolicy{
			{Name: "p", Enabled: true, Type: "velocity_burst", Action: threataction.ActionSuspend},
		},
	}
	exec, _, err := BuildThreatAction(cfg, nil, nil, nil, nil, nil, nil, govLogger())
	if err != nil {
		t.Fatalf("BuildThreatAction: %v", err)
	}
	result, err := exec.Execute(context.Background(), threataction.Threat{Type: "velocity_burst", SubjectID: "bob"}, threataction.ThreatPolicy{})
	if err != nil {
		t.Fatalf("Execute should fail-open (no error) on a nil session manager: %v", err)
	}
	if result.OK {
		t.Errorf("suspend with no session manager should report !OK, got %+v", result)
	}
}
