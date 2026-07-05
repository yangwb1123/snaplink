package serverbuildplatform

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/conditionalaccess"
	"github.com/snaplink/sso/domains/tokenanomaly"
	"github.com/snaplink/sso/domains/tokenpolicy"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/configaudit"
	"github.com/snaplink/sso/shared/core/corecredential"
	"github.com/snaplink/sso/shared/spi"
)

func govLogger() spi.Logger { return spi.NopLogger{} }

func TestBuildCredentialRotation_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	reg, sched, err := BuildCredentialRotation(config.RotationConfig{}, nil, govLogger(), nil)
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
	reg, sched, err := BuildCredentialRotation(cfg, []byte("seed-secret"), govLogger(), nil)
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
	if _, _, err := BuildCredentialRotation(cfg, nil, govLogger(), nil); err == nil {
		t.Fatal("expected error: rotation.interval required when enabled")
	}
}

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
	rec, det, err := BuildTokenAnomaly(config.TokenAnomalyConfig{}, govLogger())
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
	if _, _, err := BuildTokenAnomaly(config.TokenAnomalyConfig{Enabled: true}, govLogger()); err == nil {
		t.Fatal("expected error: sweep_interval required when token_anomaly.enabled")
	}
}

// TestBuildTokenAnomaly_EnabledCoWiresRecorderAndDetector proves the detector is
// the recorder's store (the decorator co-wiring the whole feature depends on):
// only then does the recorder's drain feed the detector's observation table.
func TestBuildTokenAnomaly_EnabledCoWiresRecorderAndDetector(t *testing.T) {
	t.Parallel()
	cfg := config.TokenAnomalyConfig{Enabled: true, SweepInterval: time.Hour, MaxFindings: 8}
	rec, det, err := BuildTokenAnomaly(cfg, govLogger())
	if err != nil {
		t.Fatalf("BuildTokenAnomaly: %v", err)
	}
	if rec == nil || det == nil {
		t.Fatal("enabled token_anomaly must return a recorder + detector")
	}
	// The recorder must drain into the detector (the tokenusage.Store decorator),
	// not into a bare aggregation store — otherwise the detector never observes.
	if got, ok := rec.UsageStore().(*tokenanomaly.Detector); !ok || got != det {
		t.Fatalf("recorder store = %T; want the returned *tokenanomaly.Detector (co-wired)", rec.UsageStore())
	}
	if det.Findings() == nil {
		t.Error("detector must expose its finding store for the admin read API")
	}
}
