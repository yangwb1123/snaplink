package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/interfaces/sso"
)

// -----------------------------------------------------------------------------
// buildApp — all-SQLite identity + oauth + audit backends
// -----------------------------------------------------------------------------

// TestBuildApp_AllSQLiteBackends drives buildApp's sqlite branches: the
// schema-version boot gate, the appendReadyCheck/appendStorageHealthSource
// Ping+DB() type-assertion paths, audit sqlite primary sink + retention loop,
// and the sqlite store constructors. A memory-only buildApp never exercises
// these (no DB() method), so this is the only place the sqlite assembly path
// is walked end to end from cmd.
func TestBuildApp_AllSQLiteBackends(t *testing.T) {
	dir := t.TempDir()
	idDSN := "file:" + filepath.Join(dir, "identity.db") + "?_journal=WAL"
	oauthDSN := "file:" + filepath.Join(dir, "oauth.db") + "?_journal=WAL"
	auditDSN := "file:" + filepath.Join(dir, "audit.db") + "?_journal=WAL"
	permDSN := "file:" + filepath.Join(dir, "perm.db") + "?_journal=WAL"

	cfg := &config.Config{}
	cfg.Identity = config.IdentityConfig{
		Backend: "sqlite",
		SQLite:  config.IdentitySQLiteConfig{DSN: idDSN},
	}
	cfg.OAuth.Backend = "sqlite"
	cfg.OAuth.SQLite.DSN = oauthDSN

	cfg.Audit.Enabled = true
	cfg.Audit.Backend = "sqlite"
	cfg.Audit.Sqlite.DSN = auditDSN
	cfg.Audit.Retention.Enabled = true
	cfg.Audit.Retention.MaxAge = 24 * time.Hour
	cfg.Audit.Retention.Interval = time.Hour

	cfg.Permissions.Enabled = true
	cfg.Permissions.Backend = "sqlite"
	cfg.Permissions.SQLite.DSN = permDSN

	// Security-layer stores on sqlite so their schema-check + readycheck +
	// storage-health branches (DB() handle path) fire in buildApp.
	cfg.Security.JTIReplay.Enabled = true
	cfg.Security.JTIReplay.Backend = "sqlite"
	cfg.Security.JTIReplay.SQLite.DSN = "file:" + filepath.Join(dir, "jti.db") + "?_journal=WAL"
	cfg.Security.AccountLockout.Enabled = true
	cfg.Security.AccountLockout.Backend = "sqlite"
	cfg.Security.AccountLockout.SQLite.DSN = "file:" + filepath.Join(dir, "lockout.db") + "?_journal=WAL"
	cfg.Security.AccountLockout.MaxFailures = 5

	// Pairwise subjects + BCL index on sqlite.
	cfg.Server.PairwiseSubjects.Enabled = true
	cfg.Server.PairwiseSubjects.Salt = "pw-salt"
	cfg.Server.PairwiseSubjects.Backend = "sqlite"
	cfg.Server.PairwiseSubjects.SQLite.DSN = "file:" + filepath.Join(dir, "pairwise.db") + "?_journal=WAL"
	cfg.BackchannelLogout.Enabled = true
	cfg.BackchannelLogout.Index.Backend = "sqlite"
	cfg.BackchannelLogout.Index.SQLite.DSN = "file:" + filepath.Join(dir, "bcl.db") + "?_journal=WAL"

	// TOTP authenticator (sqlite) so the totp MFA provider can wire — also
	// covers buildAuthenticators' TOTP + enrollment-store branch.
	cfg.Authenticators.TOTP = &config.TOTPConfig{
		Enabled:   true,
		SQLiteDSN: "file:" + filepath.Join(dir, "totp.db") + "?_journal=WAL",
	}

	// MFA challenge store on sqlite, totp provider kind.
	cfg.MFA.Enabled = true
	cfg.MFA.Provider.Kind = "totp"
	cfg.MFA.Challenge.Backend = "sqlite"
	cfg.MFA.Challenge.SQLite.DSN = "file:" + filepath.Join(dir, "mfa.db") + "?_journal=WAL"

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp (all-sqlite): %v", err)
	}
	defer shutdownApp(t, a)

	if a.server == nil {
		t.Fatal("server nil")
	}
	if a.auditRetentionCancel == nil {
		t.Error("audit retention loop not started with sqlite backend + retention.enabled")
	}
	// /readyz must aggregate the sqlite Ping checks and report ready.
	rec := callReadyz(t, a)
	if rec.Code != 200 {
		t.Errorf("/readyz = %d body=%s; want 200", rec.Code, rec.Body.String())
	}
}

// TestBuildApp_AuditRetentionRequiresMaxAge — retention.enabled on a sqlite
// audit backend without a max_age is a misconfiguration that must fail loud.
func TestBuildApp_AuditRetentionRequiresMaxAge(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.Backend = "sqlite"
	cfg.Audit.Sqlite.DSN = "file:" + filepath.Join(dir, "audit.db") + "?_journal=WAL"
	cfg.Audit.Retention.Enabled = true
	// No MaxAge.
	if _, err := buildApp(cfg, quietLogger()); err == nil {
		t.Fatal("expected error: retention.enabled requires max_age")
	}
}

// -----------------------------------------------------------------------------
// buildFederationConfig — full success path
// -----------------------------------------------------------------------------

// TestBuildFederationConfig_FullSuccess exercises the anchor + trust-mark
// issuer + subordinate JWKS-load loops together, which the existing
// boot-guard tests (federation_trust_mark_resolved_test.go) don't reach.
func TestBuildFederationConfig_FullSuccess(t *testing.T) {
	anchorJWKS := writeJWKSFile(t, "https://anchor.fed.test")
	issuerJWKS := writeJWKSFile(t, "https://tm-issuer.fed.test")
	subJWKS := writeJWKSFile(t, "https://sub.fed.test")

	mpl := 1
	cfg := config.FederationConfig{
		AuthorityHints:   []string{"https://anchor.fed.test"},
		OrganizationName: "Fed Test Org",
		Contacts:         []string{"ops@fed.test"},
		TrustAnchors: []config.TrustAnchorConfig{
			{EntityID: "https://anchor.fed.test", JWKSFile: anchorJWKS},
		},
		RequiredTrustMarkTypes: []string{"https://fed.test/tm/certified"},
		TrustMarkIssuers: []config.TrustMarkIssuerConfig{{
			EntityID:     "https://tm-issuer.fed.test",
			JWKSFile:     issuerJWKS,
			AllowedTypes: []string{"https://fed.test/tm/certified"},
		}},
		Subordinates: []config.SubordinateConfig{{
			EntityID: "https://sub.fed.test",
			JWKSFile: subJWKS,
			Constraints: &config.SubordinateConstraintsConfig{
				MaxPathLength:              &mpl,
				NamingConstraintsPermitted: []string{"https://sub.fed.test/"},
			},
		}},
	}
	out, err := buildFederationConfig(cfg)
	if err != nil {
		t.Fatalf("buildFederationConfig: %v", err)
	}
	if len(out.TrustAnchors) != 1 || len(out.TrustMarkIssuers) != 1 || len(out.Subordinates) != 1 {
		t.Errorf("anchors=%d issuers=%d subs=%d; want 1/1/1",
			len(out.TrustAnchors), len(out.TrustMarkIssuers), len(out.Subordinates))
	}
	if out.Subordinates[0].Constraints == nil {
		t.Error("subordinate constraints not propagated")
	}
	if out.OrganizationName != "Fed Test Org" {
		t.Errorf("OrganizationName = %q", out.OrganizationName)
	}
}

// TestBuildFederationConfig_AnchorMissingJWKSFileErrors — a configured anchor
// with no jwks_file is a boot error (the anchor's root-of-trust keys are
// mandatory).
func TestBuildFederationConfig_AnchorMissingJWKSFileErrors(t *testing.T) {
	cfg := config.FederationConfig{
		TrustAnchors: []config.TrustAnchorConfig{{EntityID: "https://anchor.fed.test"}},
	}
	if _, err := buildFederationConfig(cfg); err == nil {
		t.Fatal("expected error for anchor without jwks_file")
	}
}

// TestBuildFederationConfig_SubordinateBadJWKSFileErrors — a configured
// subordinate whose jwks_file can't be read is a boot error.
func TestBuildFederationConfig_SubordinateBadJWKSFileErrors(t *testing.T) {
	cfg := config.FederationConfig{
		Subordinates: []config.SubordinateConfig{{
			EntityID: "https://sub.fed.test",
			JWKSFile: filepath.Join(t.TempDir(), "missing.json"),
		}},
	}
	if _, err := buildFederationConfig(cfg); err == nil {
		t.Fatal("expected error for subordinate with unreadable jwks_file")
	}
}

// -----------------------------------------------------------------------------
// buildReleaseSubsystem — file store + static pinner
// -----------------------------------------------------------------------------

func TestBuildReleaseSubsystem_FileStoreStaticPinner(t *testing.T) {
	cfg := &config.Config{}
	cfg.Releases.Enabled = true
	cfg.Releases.Store.Backend = "file"
	cfg.Releases.Store.File.Dir = filepath.Join(t.TempDir(), "releases")
	cfg.Releases.Pinner.Backend = "static"
	cfg.Releases.Pinner.Static.BundleDir = t.TempDir() // must exist
	reg, store, err := buildReleaseSubsystem(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildReleaseSubsystem: %v", err)
	}
	if reg == nil || reg.Store == nil || reg.Pinner == nil || store == nil {
		t.Fatalf("incomplete registry: %+v", reg)
	}
}

// TestBuildReleaseSubsystem_HTTPProbeRequiresURL — opting into the http probe
// without a URL is a misconfiguration.
func TestBuildReleaseSubsystem_HTTPProbeRequiresURL(t *testing.T) {
	cfg := &config.Config{}
	cfg.Releases.Enabled = true
	cfg.Releases.Store.Backend = "memory"
	cfg.Releases.Pinner.Backend = "noop"
	cfg.Releases.Probe.Backend = "http"
	if _, _, err := buildReleaseSubsystem(cfg, quietLogger()); err == nil {
		t.Fatal("expected error: http probe requires url")
	}
}

// -----------------------------------------------------------------------------
// buildBootstrapLock
// -----------------------------------------------------------------------------

func TestBuildBootstrapLock_NoopReturnsNil(t *testing.T) {
	l, cleanup, err := buildBootstrapLock(&config.Config{}, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if l != nil || cleanup != nil {
		t.Errorf("noop returned non-nil lock=%v or non-nil cleanup; want both nil", l)
	}
}

func TestBuildBootstrapLock_FileBackend(t *testing.T) {
	cfg := &config.Config{}
	cfg.Bootstrap.Lock.Backend = "file"
	cfg.Bootstrap.Lock.File.Dir = t.TempDir()
	l, _, err := buildBootstrapLock(cfg, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if l == nil {
		t.Fatal("file backend returned nil lock")
	}
}

func TestBuildBootstrapLock_EtcdRequiresEndpoints(t *testing.T) {
	cfg := &config.Config{}
	cfg.Bootstrap.Lock.Backend = "etcd"
	if _, _, err := buildBootstrapLock(cfg, quietLogger()); err == nil {
		t.Fatal("expected error: etcd backend requires endpoints")
	}
}

func TestBuildBootstrapLock_UnknownBackendErrors(t *testing.T) {
	cfg := &config.Config{}
	cfg.Bootstrap.Lock.Backend = "zookeeper"
	if _, _, err := buildBootstrapLock(cfg, quietLogger()); err == nil {
		t.Fatal("expected error for unknown bootstrap lock backend")
	}
}

// -----------------------------------------------------------------------------
// logEndpoints — print-only, both branches
// -----------------------------------------------------------------------------

// TestLogEndpoints_MinimalAndFull walks both the bare path list and the
// conditional admin/metrics/audit/network blocks without panicking. The
// output is operator diagnostics only — coverage is the point.
func TestLogEndpoints_MinimalAndFull(t *testing.T) {
	logEndpoints(&config.Config{}, "")

	cfg := &config.Config{}
	cfg.Metrics.Enabled = true
	cfg.Audit.Enabled = true
	cfg.Audit.APIEnabled = true
	cfg.Network.Enabled = true
	cfg.Network.APIEnabled = true
	cfg.Admin.Enabled = true
	cfg.Admin.APIRESTEnabled = true
	cfg.Snapshot.Enabled = true
	cfg.Releases.Enabled = true
	cfg.Tenant.Enabled = true
	logEndpoints(cfg, ":9090")
}

// -----------------------------------------------------------------------------
// buildSnapshotSubsystem — aes-gcm encryption branch
// -----------------------------------------------------------------------------

func TestBuildSnapshotSubsystem_AESGCMInlineKey(t *testing.T) {
	cfg := &config.Config{}
	cfg.Snapshot.Enabled = true
	cfg.Snapshot.Storage.Backend = "inline"
	cfg.Snapshot.Encryption.Backend = "aes-gcm"
	// 32 hex-pairs = 32 bytes.
	cfg.Snapshot.Encryption.Key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	pipe, _, err := buildSnapshotSubsystem(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildSnapshotSubsystem (aes-gcm): %v", err)
	}
	if pipe == nil || pipe.Sealer == nil {
		t.Fatal("aes-gcm sealer not wired")
	}
}

func TestBuildSnapshotSubsystem_AESGCMRequiresKey(t *testing.T) {
	cfg := &config.Config{}
	cfg.Snapshot.Enabled = true
	cfg.Snapshot.Storage.Backend = "inline"
	cfg.Snapshot.Encryption.Backend = "aes-gcm"
	// No key / key_file.
	if _, _, err := buildSnapshotSubsystem(cfg, quietLogger()); err == nil {
		t.Fatal("expected error: aes-gcm requires key or key_file")
	}
}

// -----------------------------------------------------------------------------
// store-builder error branches (sqlite-DSN-required / unknown-backend)
// -----------------------------------------------------------------------------

func TestStoreBuilders_SQLiteDSNRequired(t *testing.T) {
	if _, err := buildUserProvider(config.IdentityConfig{Backend: "sqlite"}); err == nil {
		t.Error("buildUserProvider: expected dsn-required error")
	}
	if _, err := buildSessionManager(config.IdentityConfig{Backend: "sqlite"}, 0); err == nil {
		t.Error("buildSessionManager: expected dsn-required error")
	}
	if _, err := buildClientStore(config.IdentityConfig{Backend: "sqlite"}); err == nil {
		t.Error("buildClientStore: expected dsn-required error")
	}
	if _, err := buildAuthCodeStore(config.OAuthConfig{Backend: "sqlite"}); err == nil {
		t.Error("buildAuthCodeStore: expected dsn-required error")
	}
	if _, err := buildRefreshTokenStore(config.OAuthConfig{Backend: "sqlite"}); err == nil {
		t.Error("buildRefreshTokenStore: expected dsn-required error")
	}
	if _, err := buildDeviceCodeStore(config.OAuthConfig{Backend: "sqlite"}); err == nil {
		t.Error("buildDeviceCodeStore: expected dsn-required error")
	}
}

func TestStoreBuilders_UnknownBackend(t *testing.T) {
	if _, err := buildUserProvider(config.IdentityConfig{Backend: "redis"}); err == nil {
		t.Error("buildUserProvider: expected unknown-backend error")
	}
	if _, err := buildSessionManager(config.IdentityConfig{Backend: "redis"}, 0); err == nil {
		t.Error("buildSessionManager: expected unknown-backend error")
	}
	if _, err := buildAuthCodeStore(config.OAuthConfig{Backend: "redis"}); err == nil {
		t.Error("buildAuthCodeStore: expected unknown-backend error")
	}
	if _, err := buildRefreshTokenStore(config.OAuthConfig{Backend: "redis"}); err == nil {
		t.Error("buildRefreshTokenStore: expected unknown-backend error")
	}
	if _, err := buildDeviceCodeStore(config.OAuthConfig{Backend: "redis"}); err == nil {
		t.Error("buildDeviceCodeStore: expected unknown-backend error")
	}
	if _, err := buildClientStore(config.IdentityConfig{Backend: "redis"}); err == nil {
		t.Error("buildClientStore: expected unknown-backend error")
	}
}

// Self-service store backends: memory happy path + sqlite-DSN-required +
// unknown-backend, for the consent + password-credential selectors.
func TestSelfServiceStoreBuilders(t *testing.T) {
	// Consent store.
	if s, err := buildConsentStore(config.SelfServiceStoreConfig{Backend: "memory"}); err != nil || s == nil {
		t.Errorf("buildConsentStore memory: store=%v err=%v", s, err)
	}
	if _, err := buildConsentStore(config.SelfServiceStoreConfig{Backend: "sqlite"}); err == nil {
		t.Error("buildConsentStore sqlite without dsn: expected error")
	}
	if _, err := buildConsentStore(config.SelfServiceStoreConfig{Backend: "redis"}); err == nil {
		t.Error("buildConsentStore unknown backend: expected error")
	}
	// Password-credential store.
	if s, err := buildPasswordCredentialStore(config.SelfServiceStoreConfig{Backend: "memory"}); err != nil || s == nil {
		t.Errorf("buildPasswordCredentialStore memory: store=%v err=%v", s, err)
	}
	if _, err := buildPasswordCredentialStore(config.SelfServiceStoreConfig{Backend: "sqlite"}); err == nil {
		t.Error("buildPasswordCredentialStore sqlite without dsn: expected error")
	}
	if _, err := buildPasswordCredentialStore(config.SelfServiceStoreConfig{Backend: "redis"}); err == nil {
		t.Error("buildPasswordCredentialStore unknown backend: expected error")
	}
}

// -----------------------------------------------------------------------------
// bootstrapLogger + snapshotRestorerAdapter
// -----------------------------------------------------------------------------

func TestBootstrapLogger_DelegatesToInner(t *testing.T) {
	bl := bootstrapLogger{inner: quietLogger()}
	// NopLogger swallows output; the assertion is no-panic + the adapter
	// satisfies the bootstrap.Logger Info/Error pair.
	bl.Info("boot info", "k", "v")
	bl.Error("boot error", "k", "v")
}

func TestSnapshotRestorerAdapter_UnconfiguredErrors(t *testing.T) {
	a := &snapshotRestorerAdapter{} // all nil
	if err := a.RestoreByID(context.Background(), "snap-1"); err == nil {
		t.Fatal("expected error when snapshot subsystem not configured")
	}
}

// -----------------------------------------------------------------------------
// mountComplianceRoutes — no-op guard
// -----------------------------------------------------------------------------

// TestMountComplianceRoutes_NilDepsNoOp covers the early-return guard: a nil
// deps (or nil Users) mounts nothing and returns no error — nothing to act on.
func TestMountComplianceRoutes_NilDepsNoOp(t *testing.T) {
	srv := sso.NewServer()
	if err := mountComplianceRoutes(srv, nil); err != nil {
		t.Fatalf("nil deps: %v", err)
	}
	if err := mountComplianceRoutes(srv, &complianceDeps{}); err != nil {
		t.Fatalf("nil Users: %v", err)
	}
}
