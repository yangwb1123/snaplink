package main

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
)

func TestBuildApp_AllOAuthStoresEnabled_BuildsCleanly(t *testing.T) {
	cfg := &config.Config{}
	cfg.OAuth.AuthCode = config.OAuthStoreConfig{Enabled: true, TTL: 10 * time.Minute}
	cfg.OAuth.RefreshToken = config.OAuthRefreshTokenConfig{OAuthStoreConfig: config.OAuthStoreConfig{Enabled: true, TTL: 30 * 24 * time.Hour}}
	cfg.OAuth.DeviceCode = config.OAuthDeviceCodeConfig{
		Enabled:             true,
		TTL:                 10 * time.Minute,
		PollInterval:        5 * time.Second,
		VerificationBaseURL: "https://example.com/device",
	}
	cfg.OAuth.PAR = config.OAuthStoreConfig{Enabled: true, TTL: 90 * time.Second}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	if a.server == nil {
		t.Fatal("server is nil after buildApp")
	}
}

func TestBuildApp_PARStoreEnabledAdvertisesEndpoint(t *testing.T) {
	cfg := &config.Config{}
	cfg.OAuth.PAR = config.OAuthStoreConfig{Enabled: true}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	endpoint, _ := doc["pushed_authorization_request_endpoint"].(string)
	if endpoint == "" {
		t.Errorf("pushed_authorization_request_endpoint missing — oauth.PARStore wiring broken")
	}
}

func TestBuildApp_PairwiseSubjectsFlipsDiscovery(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.PairwiseSubjects.Enabled = true
	cfg.Server.PairwiseSubjects.Salt = "test-salt"

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	types, _ := doc["subject_types_supported"].([]any)
	saw := map[string]bool{}
	for _, t := range types {
		saw[t.(string)] = true
	}
	if !saw["public"] || !saw["pairwise"] {
		t.Errorf("subject_types_supported = %v want both public and pairwise", types)
	}
}

func TestBuildPairwiseSubjectStore_MemoryDefault(t *testing.T) {
	s, mode, err := buildPairwiseSubjectStore(config.PairwiseSubjectsConfig{})
	if err != nil {
		t.Fatalf("memory build: %v", err)
	}
	if s == nil {
		t.Fatal("store nil")
	}
	if !strings.Contains(mode, "memory") {
		t.Fatalf("mode label %q missing memory marker", mode)
	}
}

func TestBuildPairwiseSubjectStore_SQLiteNeedsDSN(t *testing.T) {
	_, _, err := buildPairwiseSubjectStore(config.PairwiseSubjectsConfig{Backend: "sqlite"})
	if err == nil {
		t.Fatal("expected error when sqlite backend has empty DSN")
	}
}

func TestBuildPairwiseSubjectStore_SQLiteOpensFile(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "pairwise.db") + "?_journal=WAL"
	s, mode, err := buildPairwiseSubjectStore(config.PairwiseSubjectsConfig{
		Backend: "sqlite",
		SQLite:  config.PairwiseSubjectsSQLiteCfg{DSN: dsn},
	})
	if err != nil {
		t.Fatalf("sqlite build: %v", err)
	}
	if s == nil {
		t.Fatal("store nil")
	}
	if !strings.Contains(mode, "sqlite") {
		t.Fatalf("mode label %q missing sqlite marker", mode)
	}
}

func TestBuildPairwiseSubjectStore_UnknownBackendErrors(t *testing.T) {
	_, _, err := buildPairwiseSubjectStore(config.PairwiseSubjectsConfig{Backend: "etcd"})
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestBuildApp_PairwiseSubjectsSQLiteEndToEnd(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "pairwise.db") + "?_journal=WAL"
	cfg := &config.Config{}
	cfg.Server.PairwiseSubjects.Enabled = true
	cfg.Server.PairwiseSubjects.Salt = "test-salt"
	cfg.Server.PairwiseSubjects.Backend = "sqlite"
	cfg.Server.PairwiseSubjects.SQLite.DSN = dsn

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	types, _ := doc["subject_types_supported"].([]any)
	saw := map[string]bool{}
	for _, ty := range types {
		saw[ty.(string)] = true
	}
	if !saw["pairwise"] {
		t.Errorf("sqlite-backed pairwise must still advertise pairwise in subject_types_supported, got %v", types)
	}
}

func TestBuildApp_OAuth21StrictModeFlipsDiscovery(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.OAuth21StrictMode = true

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	methods, _ := doc["code_challenge_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v want [S256] (plain disallowed in 2.1 strict)", methods)
	}
}

func TestBuildApp_JARFetcherFlipsRequestURIParameterSupported(t *testing.T) {
	cfg := &config.Config{}
	cfg.OAuth.JAR = config.OAuthJARConfig{Enabled: true}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	if v, _ := doc["request_uri_parameter_supported"].(bool); !v {
		t.Errorf("request_uri_parameter_supported = %v want true when JAR fetcher wired", doc["request_uri_parameter_supported"])
	}
}

func TestBuildApp_PARStoreDisabledOmitsEndpoint(t *testing.T) {
	cfg := &config.Config{}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	if _, present := doc["pushed_authorization_request_endpoint"]; present {
		t.Error("PAR endpoint advertised when not enabled — omitempty broken")
	}
}
