package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildauthn"
	"github.com/snaplink/sso/cmd/sso-server/serverbuildplatform"
	"github.com/snaplink/sso/cmd/sso-server/serverbuildstore"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/protocols/caep"
)

// writeJWKSFile materializes a minimal valid single-key JWKS document (a real
// Ed25519 public key) at a temp file and returns its path. Reused across the
// JWKS-loading boot paths (SPIFFE, CAEP receiver) so the guard logic — not the
// JWKS parse — is what's under test.
func writeJWKSFile(t *testing.T, issuer string) string {
	t.Helper()
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(issuer))
	keys, err := iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	doc, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatalf("write jwks: %v", err)
	}
	return path
}

// -----------------------------------------------------------------------------
// serverbuildplatform.SubordinateConstraints
// -----------------------------------------------------------------------------

// TestSubordinateConstraints_NilReturnsNil — operators who configure no §6.2
// constraints get no constraints claim in the Subordinate Statement at all.
func TestSubordinateConstraints_NilReturnsNil(t *testing.T) {
	t.Parallel()
	if got := serverbuildplatform.SubordinateConstraints(nil); got != nil {
		t.Errorf("serverbuildplatform.SubordinateConstraints(nil) = %v; want nil", got)
	}
}

// TestSubordinateConstraints_NamingAndEntityTypes — the pointer/empty-slice
// distinctions the SDK relies on must survive translation: a non-nil empty
// allowed_entity_types ("only federation_entity") and a naming_constraints
// object emitted only when at least one side is non-empty.
func TestSubordinateConstraints_NamingAndEntityTypes(t *testing.T) {
	t.Parallel()
	mpl := 0
	emptyTypes := []string{}
	c := &config.SubordinateConstraintsConfig{
		MaxPathLength:              &mpl,
		NamingConstraintsPermitted: []string{"https://sub.fed.test/"},
		AllowedEntityTypes:         &emptyTypes,
	}
	out := serverbuildplatform.SubordinateConstraints(c)
	if out == nil {
		t.Fatal("serverbuildplatform.SubordinateConstraints returned nil for a populated config")
	}
	if out.MaxPathLength == nil || *out.MaxPathLength != 0 {
		t.Errorf("MaxPathLength = %v; want pointer to 0", out.MaxPathLength)
	}
	if out.NamingConstraints == nil || len(out.NamingConstraints.Permitted) != 1 {
		t.Errorf("NamingConstraints not propagated: %+v", out.NamingConstraints)
	}
	if out.AllowedEntityTypes == nil {
		t.Fatal("AllowedEntityTypes nil; a non-nil empty slice must round-trip (only federation_entity)")
	}
	if len(*out.AllowedEntityTypes) != 0 {
		t.Errorf("AllowedEntityTypes = %v; want non-nil empty", *out.AllowedEntityTypes)
	}
}

// TestSubordinateConstraints_NoNamingObjectWhenBothEmpty — both naming sides
// empty must emit NO naming_constraints object (a present-but-empty object
// would over-constrain).
func TestSubordinateConstraints_NoNamingObjectWhenBothEmpty(t *testing.T) {
	t.Parallel()
	out := serverbuildplatform.SubordinateConstraints(&config.SubordinateConstraintsConfig{})
	if out == nil {
		t.Fatal("nil for non-nil empty config")
	}
	if out.NamingConstraints != nil {
		t.Errorf("NamingConstraints = %+v; want nil when both sides empty", out.NamingConstraints)
	}
	if out.AllowedEntityTypes != nil {
		t.Errorf("AllowedEntityTypes = %v; want nil (absent) when config nil", out.AllowedEntityTypes)
	}
}

// -----------------------------------------------------------------------------
// serverbuildplatform.BuildSPIFFEOption
// -----------------------------------------------------------------------------

// TestBuildSPIFFEOption_RequiresTrustDomain / Audience / JWKSFile — each
// required field is independently fatal so a half-wired SPIFFE token-exchange
// never silently admits or rejects every SVID.
func TestBuildSPIFFEOption_RequiresTrustDomain(t *testing.T) {
	t.Parallel()
	_, err := serverbuildplatform.BuildSPIFFEOption(config.SPIFFEConfig{})
	if err == nil || !strings.Contains(err.Error(), "trust_domain") {
		t.Fatalf("err = %v; want trust_domain required", err)
	}
}

func TestBuildSPIFFEOption_RequiresAudience(t *testing.T) {
	t.Parallel()
	_, err := serverbuildplatform.BuildSPIFFEOption(config.SPIFFEConfig{TrustDomain: "example.org"})
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("err = %v; want audience required", err)
	}
}

func TestBuildSPIFFEOption_RequiresJWKSFile(t *testing.T) {
	t.Parallel()
	_, err := serverbuildplatform.BuildSPIFFEOption(config.SPIFFEConfig{TrustDomain: "example.org", Audience: "spiffe-aud"})
	if err == nil || !strings.Contains(err.Error(), "jwks_file") {
		t.Fatalf("err = %v; want jwks_file required", err)
	}
}

// TestBuildSPIFFEOption_MissingJWKSFileErrors — a configured-but-unreadable
// trust bundle is a boot error.
func TestBuildSPIFFEOption_MissingJWKSFileErrors(t *testing.T) {
	t.Parallel()
	_, err := serverbuildplatform.BuildSPIFFEOption(config.SPIFFEConfig{
		TrustDomain: "example.org",
		Audience:    "spiffe-aud",
		JWKSFile:    filepath.Join(t.TempDir(), "does-not-exist.json"),
	})
	if err == nil {
		t.Fatal("expected error reading missing jwks_file")
	}
}

// TestBuildSPIFFEOption_HappyPath — a valid trust bundle yields a non-nil
// sso.Option (the MaxClockSkew>0 branch is also exercised).
func TestBuildSPIFFEOption_HappyPath(t *testing.T) {
	t.Parallel()
	opt, err := serverbuildplatform.BuildSPIFFEOption(config.SPIFFEConfig{
		TrustDomain:  "example.org",
		Audience:     "spiffe-aud",
		JWKSFile:     writeJWKSFile(t, "https://spire.example.org"),
		MaxClockSkew: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if opt == nil {
		t.Fatal("opt is nil despite valid config")
	}
}

// -----------------------------------------------------------------------------
// serverbuildplatform.CaepSubjectMode
// -----------------------------------------------------------------------------

func TestCAEPSubjectMode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    caep.SubjectMapMode
		wantErr bool
	}{
		{"", caep.SubjectMapOpaque, false},
		{"opaque", caep.SubjectMapOpaque, false},
		{" OPAQUE ", caep.SubjectMapOpaque, false},
		{"iss_sub", caep.SubjectMapIssSub, false},
		{"iss-sub", caep.SubjectMapIssSub, false},
		{"bogus", 0, true},
	}
	for _, tc := range cases {
		got, err := serverbuildplatform.CaepSubjectMode(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("serverbuildplatform.CaepSubjectMode(%q) err = %v; wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("serverbuildplatform.CaepSubjectMode(%q) = %v; want %v", tc.in, got, tc.want)
		}
	}
}

// -----------------------------------------------------------------------------
// serverbuildplatform.BuildCAEPReceiverOption
// -----------------------------------------------------------------------------

func TestBuildCAEPReceiverOption_RequiresAudience(t *testing.T) {
	t.Parallel()
	_, err := serverbuildplatform.BuildCAEPReceiverOption(
		config.CAEPReceiverConfig{},
		defaultimpl.NewMemorySessionManager(),
		defaultimpl.NewMemoryRefreshTokenStore(),
		defaultimpl.NewMemoryClientStore(),
		defaultimpl.NewMemoryUserProvider(),
		nil, nil, nil, quietLogger(),
	)
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("err = %v; want audience required", err)
	}
}

func TestBuildCAEPReceiverOption_RequiresTransmitter(t *testing.T) {
	t.Parallel()
	_, err := serverbuildplatform.BuildCAEPReceiverOption(
		config.CAEPReceiverConfig{Audience: "https://recv.test"},
		defaultimpl.NewMemorySessionManager(),
		defaultimpl.NewMemoryRefreshTokenStore(),
		defaultimpl.NewMemoryClientStore(),
		defaultimpl.NewMemoryUserProvider(),
		nil, nil, nil, quietLogger(),
	)
	if err == nil || !strings.Contains(err.Error(), "transmitters") {
		t.Fatalf("err = %v; want transmitters required", err)
	}
}

func TestBuildCAEPReceiverOption_TransmitterRequiresIssuer(t *testing.T) {
	t.Parallel()
	_, err := serverbuildplatform.BuildCAEPReceiverOption(
		config.CAEPReceiverConfig{
			Audience:     "https://recv.test",
			Transmitters: []config.CAEPTransmitterConfig{{JWKSFile: writeJWKSFile(t, "https://tx.test")}},
		},
		defaultimpl.NewMemorySessionManager(),
		defaultimpl.NewMemoryRefreshTokenStore(),
		defaultimpl.NewMemoryClientStore(),
		defaultimpl.NewMemoryUserProvider(),
		nil, nil, nil, quietLogger(),
	)
	if err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("err = %v; want issuer required", err)
	}
}

func TestBuildCAEPReceiverOption_TransmitterRequiresJWKSFile(t *testing.T) {
	t.Parallel()
	_, err := serverbuildplatform.BuildCAEPReceiverOption(
		config.CAEPReceiverConfig{
			Audience:     "https://recv.test",
			Transmitters: []config.CAEPTransmitterConfig{{Issuer: "https://tx.test"}},
		},
		defaultimpl.NewMemorySessionManager(),
		defaultimpl.NewMemoryRefreshTokenStore(),
		defaultimpl.NewMemoryClientStore(),
		defaultimpl.NewMemoryUserProvider(),
		nil, nil, nil, quietLogger(),
	)
	if err == nil || !strings.Contains(err.Error(), "jwks_file") {
		t.Fatalf("err = %v; want jwks_file required", err)
	}
}

// TestBuildCAEPReceiverOption_IssSubRequiresProvider — iss_sub mode with an
// empty provider is insecure (cross-IdP subject hijack); the cmd guard names
// the exact knob before the SDK's own check.
func TestBuildCAEPReceiverOption_IssSubRequiresProvider(t *testing.T) {
	t.Parallel()
	_, err := serverbuildplatform.BuildCAEPReceiverOption(
		config.CAEPReceiverConfig{
			Audience: "https://recv.test",
			Transmitters: []config.CAEPTransmitterConfig{{
				Issuer:      "https://tx.test",
				JWKSFile:    writeJWKSFile(t, "https://tx.test"),
				SubjectMode: "iss_sub",
			}},
		},
		defaultimpl.NewMemorySessionManager(),
		defaultimpl.NewMemoryRefreshTokenStore(),
		defaultimpl.NewMemoryClientStore(),
		defaultimpl.NewMemoryUserProvider(),
		nil, nil, nil, quietLogger(),
	)
	if err == nil || !strings.Contains(err.Error(), "provider") {
		t.Fatalf("err = %v; want provider required for iss_sub", err)
	}
}

func TestBuildCAEPReceiverOption_BadSubjectMode(t *testing.T) {
	t.Parallel()
	_, err := serverbuildplatform.BuildCAEPReceiverOption(
		config.CAEPReceiverConfig{
			Audience: "https://recv.test",
			Transmitters: []config.CAEPTransmitterConfig{{
				Issuer:      "https://tx.test",
				JWKSFile:    writeJWKSFile(t, "https://tx.test"),
				SubjectMode: "garbage",
			}},
		},
		defaultimpl.NewMemorySessionManager(),
		defaultimpl.NewMemoryRefreshTokenStore(),
		defaultimpl.NewMemoryClientStore(),
		defaultimpl.NewMemoryUserProvider(),
		nil, nil, nil, quietLogger(),
	)
	if err == nil || !strings.Contains(err.Error(), "subject_mode") {
		t.Fatalf("err = %v; want subject_mode error", err)
	}
}

// TestBuildCAEPReceiverOption_HappyPath — a fully-formed receiver wires a
// non-nil option (opaque mode, no provider required, MaxClockSkew branch).
func TestBuildCAEPReceiverOption_HappyPath(t *testing.T) {
	t.Parallel()
	opt, err := serverbuildplatform.BuildCAEPReceiverOption(
		config.CAEPReceiverConfig{
			Audience:     "https://recv.test",
			MaxClockSkew: 90 * time.Second,
			Transmitters: []config.CAEPTransmitterConfig{{
				Issuer:      "https://tx.test",
				JWKSFile:    writeJWKSFile(t, "https://tx.test"),
				SubjectMode: "opaque",
			}},
		},
		defaultimpl.NewMemorySessionManager(),
		defaultimpl.NewMemoryRefreshTokenStore(),
		defaultimpl.NewMemoryClientStore(),
		defaultimpl.NewMemoryUserProvider(),
		nil, nil, nil, quietLogger(),
	)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if opt == nil {
		t.Fatal("opt nil despite valid receiver config")
	}
}

// -----------------------------------------------------------------------------
// serverbuildstore.BuildPasswordResetStore
// -----------------------------------------------------------------------------

func TestBuildPasswordResetStore_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	store, err := serverbuildstore.BuildPasswordResetStore(config.PasswordResetConfig{}, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if store != nil {
		t.Errorf("store = %v; want nil for empty backend", store)
	}
}

func TestBuildPasswordResetStore_Memory(t *testing.T) {
	t.Parallel()
	store, err := serverbuildstore.BuildPasswordResetStore(config.PasswordResetConfig{Backend: "memory"}, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if store == nil {
		t.Fatal("store nil for memory backend")
	}
}

func TestBuildPasswordResetStore_SQLiteRequiresDSN(t *testing.T) {
	t.Parallel()
	_, err := serverbuildstore.BuildPasswordResetStore(config.PasswordResetConfig{Backend: "sqlite"}, nil)
	if err == nil || !strings.Contains(err.Error(), "dsn") {
		t.Fatalf("err = %v; want dsn required", err)
	}
}

func TestBuildPasswordResetStore_SQLiteHappyPath(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "reset.db") + "?_journal=WAL"
	store, err := serverbuildstore.BuildPasswordResetStore(config.PasswordResetConfig{
		Backend: "sqlite",
		SQLite:  config.IdentitySQLiteConfig{DSN: dsn},
	}, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if store == nil {
		t.Fatal("store nil for sqlite backend")
	}
}

func TestBuildPasswordResetStore_UnknownBackendErrors(t *testing.T) {
	t.Parallel()
	_, err := serverbuildstore.BuildPasswordResetStore(config.PasswordResetConfig{Backend: "mongodb"}, nil)
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

// -----------------------------------------------------------------------------
// serverbuildstore.ResolvePairwiseSalt
// -----------------------------------------------------------------------------

func TestResolvePairwiseSalt_InlineSalt(t *testing.T) {
	t.Parallel()
	got, err := serverbuildstore.ResolvePairwiseSalt(config.PairwiseSubjectsConfig{Salt: "inline-salt"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != "inline-salt" {
		t.Errorf("got %q; want inline-salt", got)
	}
}

func TestResolvePairwiseSalt_FileTrimsNewline(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "salt")
	if err := os.WriteFile(path, []byte("file-salt\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := serverbuildstore.ResolvePairwiseSalt(config.PairwiseSubjectsConfig{SaltFile: path})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != "file-salt" {
		t.Errorf("got %q; want file-salt (trailing newline trimmed)", got)
	}
}

func TestResolvePairwiseSalt_MissingFileErrors(t *testing.T) {
	t.Parallel()
	_, err := serverbuildstore.ResolvePairwiseSalt(config.PairwiseSubjectsConfig{
		SaltFile: filepath.Join(t.TempDir(), "nope"),
	})
	if err == nil {
		t.Fatal("expected error reading missing salt file")
	}
}

// -----------------------------------------------------------------------------
// serverbuildplatform.BuildSigningKeyRegistry
// -----------------------------------------------------------------------------

func TestBuildSigningKeyRegistry_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	reg, kind, err := serverbuildplatform.BuildSigningKeyRegistry(&config.SigningKeyRegistryConfig{}, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if reg != nil || kind != "" {
		t.Errorf("disabled returned reg=%v kind=%q; want nil/empty", reg, kind)
	}
}

func TestBuildSigningKeyRegistry_Memory(t *testing.T) {
	t.Parallel()
	reg, kind, err := serverbuildplatform.BuildSigningKeyRegistry(&config.SigningKeyRegistryConfig{Backend: "memory"}, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if reg == nil || kind != "memory" {
		t.Errorf("memory backend returned reg=%v kind=%q", reg, kind)
	}
}

func TestBuildSigningKeyRegistry_EtcdRequiresEndpoints(t *testing.T) {
	t.Parallel()
	_, _, err := serverbuildplatform.BuildSigningKeyRegistry(&config.SigningKeyRegistryConfig{Backend: "etcd"}, quietLogger())
	if err == nil || !strings.Contains(err.Error(), "etcd_endpoints") {
		t.Fatalf("err = %v; want etcd_endpoints required", err)
	}
}

func TestBuildSigningKeyRegistry_UnknownBackendErrors(t *testing.T) {
	t.Parallel()
	_, _, err := serverbuildplatform.BuildSigningKeyRegistry(&config.SigningKeyRegistryConfig{Backend: "consul"}, quietLogger())
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

// -----------------------------------------------------------------------------
// serverbuildstore.BuildRegionResolver
// -----------------------------------------------------------------------------

func TestBuildRegionResolver_UnconfiguredReturnsNil(t *testing.T) {
	t.Parallel()
	if r := serverbuildstore.BuildRegionResolver(&config.Config{}, nil); r != nil {
		t.Errorf("unconfigured region returned %v; want nil", r)
	}
}

func TestBuildRegionResolver_ServingRegionPins(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Region.ServingRegion = "eu-west-1"
	cfg.Region.AllowedRegions = []string{"eu-west-1", "us-east-1"}
	cfg.Region.HeaderName = "X-Region"
	r := serverbuildstore.BuildRegionResolver(cfg, nil)
	if r == nil {
		t.Fatal("resolver nil despite serving_region set")
	}
	// No header -> falls back to the pinned serving region.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	got, err := r.Resolve(req)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != "eu-west-1" {
		t.Errorf("resolved region = %q; want eu-west-1 default", got)
	}
}

func TestBuildRegionResolver_HeaderOnlyInstalls(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Region.HeaderName = "X-Region" // serving region empty but header set
	if r := serverbuildstore.BuildRegionResolver(cfg, nil); r == nil {
		t.Error("resolver nil despite header_name set")
	}
}

// -----------------------------------------------------------------------------
// serverbuildauthn.BuildPasswordHealthChecker
// -----------------------------------------------------------------------------

func TestBuildPasswordHealthChecker_DefaultDictionary(t *testing.T) {
	t.Parallel()
	c, err := serverbuildauthn.BuildPasswordHealthChecker(&config.PasswordHealthConfig{}, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if c == nil {
		t.Fatal("dictionary checker nil")
	}
}

func TestBuildPasswordHealthChecker_DictionaryWeakFileMissingErrors(t *testing.T) {
	t.Parallel()
	_, err := serverbuildauthn.BuildPasswordHealthChecker(&config.PasswordHealthConfig{
		Kind:             "dictionary",
		WeakPasswordFile: filepath.Join(t.TempDir(), "no-such-file"),
	}, quietLogger())
	if err == nil {
		t.Fatal("expected error for missing weak-password file")
	}
}

func TestBuildPasswordHealthChecker_HIBP(t *testing.T) {
	t.Parallel()
	c, err := serverbuildauthn.BuildPasswordHealthChecker(&config.PasswordHealthConfig{
		Kind: "hibp",
		HIBP: &config.HIBPHealthConfig{
			BaseURL:   "https://mirror.test/range/",
			Timeout:   3 * time.Second,
			MinCount:  2,
			UserAgent: "snaplink-test",
		},
	}, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if c == nil {
		t.Fatal("hibp checker nil")
	}
}

func TestBuildPasswordHealthChecker_UnknownKindErrors(t *testing.T) {
	t.Parallel()
	_, err := serverbuildauthn.BuildPasswordHealthChecker(&config.PasswordHealthConfig{Kind: "bogus"}, quietLogger())
	if err == nil {
		t.Fatal("expected error for unknown kind")
	}
}

// -----------------------------------------------------------------------------
// serverbuildstore.BuildPushWebhookTransport
// -----------------------------------------------------------------------------

func TestBuildPushWebhookTransport_RequiresURL(t *testing.T) {
	t.Parallel()
	_, err := serverbuildstore.BuildPushWebhookTransport(config.MFAPushWebhookConfig{})
	if err == nil || !strings.Contains(err.Error(), "url") {
		t.Fatalf("err = %v; want url required", err)
	}
}

func TestBuildPushWebhookTransport_HappyPathWithAllOptions(t *testing.T) {
	t.Parallel()
	tr, err := serverbuildstore.BuildPushWebhookTransport(config.MFAPushWebhookConfig{
		URL:                 "https://push.test/notify",
		BearerToken:         "secret",
		Headers:             map[string]string{"X-Tenant": "acme"},
		Timeout:             2 * time.Second,
		RetryMaxAttempts:    3,
		RetryInitialBackoff: 50 * time.Millisecond,
		RetryMaxBackoff:     time.Second,
		SigningSecret:       "whsec-x",
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if tr == nil {
		t.Fatal("transport nil despite valid config")
	}
	wh, ok := tr.(*defaultimpl.HTTPWebhookPushTransport)
	if !ok {
		t.Fatalf("transport type = %T; want *defaultimpl.HTTPWebhookPushTransport", tr)
	}
	if len(wh.SigningSecret) == 0 {
		t.Error("SigningSecret not wired onto transport")
	}
}

// -----------------------------------------------------------------------------
// serverbuildstore.BuildCIBA
// -----------------------------------------------------------------------------

func TestBuildCIBA_MemoryLogTransport(t *testing.T) {
	t.Parallel()
	store, transport, sqliteStore, err := serverbuildstore.BuildCIBA(config.CIBAConfig{}, quietLogger(), nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if store == nil || transport == nil {
		t.Fatalf("store=%v transport=%v; want both non-nil", store, transport)
	}
	if sqliteStore != nil {
		t.Errorf("memory backend returned non-nil sqlite handle %v", sqliteStore)
	}
}

func TestBuildCIBA_SQLiteRequiresDSN(t *testing.T) {
	t.Parallel()
	_, _, _, err := serverbuildstore.BuildCIBA(config.CIBAConfig{Backend: "sqlite"}, quietLogger(), nil)
	if err == nil || !strings.Contains(err.Error(), "sqlite_dsn") {
		t.Fatalf("err = %v; want sqlite_dsn required", err)
	}
}

func TestBuildCIBA_SQLiteHappyPath(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "ciba.db") + "?_journal=WAL"
	store, _, sqliteStore, err := serverbuildstore.BuildCIBA(config.CIBAConfig{Backend: "sqlite", SQLiteDSN: dsn}, quietLogger(), nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if store == nil || sqliteStore == nil {
		t.Fatalf("store=%v sqlite=%v; want both non-nil", store, sqliteStore)
	}
}

func TestBuildCIBA_UnknownBackendErrors(t *testing.T) {
	t.Parallel()
	_, _, _, err := serverbuildstore.BuildCIBA(config.CIBAConfig{Backend: "redis"}, quietLogger(), nil)
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestBuildCIBA_WebhookTransportRequiresURL(t *testing.T) {
	t.Parallel()
	_, _, _, err := serverbuildstore.BuildCIBA(config.CIBAConfig{Transport: "webhook"}, quietLogger(), nil)
	if err == nil || !strings.Contains(err.Error(), "url") {
		t.Fatalf("err = %v; want webhook url required", err)
	}
}

func TestBuildCIBA_WebhookTransportHappyPath(t *testing.T) {
	t.Parallel()
	store, transport, _, err := serverbuildstore.BuildCIBA(config.CIBAConfig{
		Transport: "webhook",
		Webhook:   config.MFAPushWebhookConfig{URL: "https://ciba.test/push"},
	}, quietLogger(), nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if store == nil || transport == nil {
		t.Fatalf("store=%v transport=%v; want both non-nil", store, transport)
	}
}

func TestBuildCIBA_UnknownTransportErrors(t *testing.T) {
	t.Parallel()
	_, _, _, err := serverbuildstore.BuildCIBA(config.CIBAConfig{Transport: "carrier-pigeon"}, quietLogger(), nil)
	if err == nil {
		t.Fatal("expected error for unknown transport")
	}
}

// -----------------------------------------------------------------------------
// serverbuildstore.RunCIBAPrune / serverbuildstore.RunSnapshotRetention (background loops)
// -----------------------------------------------------------------------------

func TestRunCIBAPrune_ExitsOnCancel(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "ciba.db") + "?_journal=WAL"
	store, err := sqlitestores.NewCIBAStore(dsn)
	if err != nil {
		t.Fatalf("NewCIBAStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go serverbuildstore.RunCIBAPrune(ctx, done, store, 20*time.Millisecond, quietLogger(), nil)

	time.Sleep(60 * time.Millisecond) // let at least one tick fire
	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("serverbuildstore.RunCIBAPrune did not exit after cancel")
	}
}

func TestRunSnapshotRetention_ExitsOnCancel(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Snapshot.Enabled = true
	cfg.Snapshot.Storage.Backend = "inline"
	_, storage, err := serverbuildstore.BuildSnapshotSubsystem(cfg, quietLogger())
	if err != nil {
		t.Fatalf("serverbuildstore.BuildSnapshotSubsystem: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go serverbuildstore.RunSnapshotRetention(ctx, done, storage, 20*time.Millisecond, 5, quietLogger(), nil)

	time.Sleep(60 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("serverbuildstore.RunSnapshotRetention did not exit after cancel")
	}
}

// -----------------------------------------------------------------------------
// serverbuildauthn.LoadCertPool — empty-entry skip branch
// -----------------------------------------------------------------------------

// TestLoadCertPool_SkipsEmptyEntries covers the `if p == "" { continue }`
// branch the existing certificate_test.go cases don't reach: a list with a
// blank path yields a valid (empty) pool, not an error. Operators who leave a
// stray empty entry in trusted_ca_files don't trip the missing-file guard.
func TestLoadCertPool_SkipsEmptyEntries(t *testing.T) {
	t.Parallel()
	pool, err := serverbuildauthn.LoadCertPool([]string{""})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if pool == nil {
		t.Fatal("pool nil")
	}
}
