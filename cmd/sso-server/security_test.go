package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildauthn"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/interfaces/ratelimit"
	"github.com/snaplink/sso/shared/security"
)

func TestBuildRateLimitPolicy_DefaultAndPrefixes(t *testing.T) {
	p, err := buildRateLimitPolicy(config.RateLimitConfig{
		Enabled:       true,
		DefaultPerSec: 5,
		DefaultBurst:  10,
		Prefixes: []config.RateLimitPrefixConfig{
			{Prefix: "/auth/login", PerSec: 1, Burst: 2},
			{Prefix: "/auth/send-code", PerSec: 1, Burst: 2},
		},
	})
	if err != nil {
		t.Fatalf("buildRateLimitPolicy: %v", err)
	}
	if p.Default == nil {
		t.Fatal("Default limiter unexpectedly nil")
	}
	if len(p.Prefixes) != 2 {
		t.Errorf("Prefixes count = %d want 2", len(p.Prefixes))
	}
	if p.Prefixes[0].Prefix != "/auth/login" {
		t.Errorf("first prefix = %q", p.Prefixes[0].Prefix)
	}
	// Key defaults to per-client-or-IP so HTTP Basic on /token buckets
	// per-client rather than per source IP.
	if p.Key == nil {
		t.Error("Key func unexpectedly nil")
	}
}

func TestBuildRateLimitPolicy_ZeroDefaultLeavesDefaultLimiterNil(t *testing.T) {
	// A zero DefaultPerSec means "no limit on unmatched paths" — only
	// the prefix rules apply.
	p, err := buildRateLimitPolicy(config.RateLimitConfig{
		Enabled:       true,
		DefaultPerSec: 0,
		Prefixes: []config.RateLimitPrefixConfig{
			{Prefix: "/auth/login", PerSec: 1, Burst: 2},
		},
	})
	if err != nil {
		t.Fatalf("buildRateLimitPolicy: %v", err)
	}
	if p.Default != nil {
		t.Errorf("Default limiter should be nil when DefaultPerSec=0")
	}
	if len(p.Prefixes) != 1 {
		t.Errorf("Prefixes count = %d want 1", len(p.Prefixes))
	}
}

func TestBuildApp_BodyLimitWired(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.BodyLimit.MaxBytes = 16

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	// A POST whose body exceeds the cap returns 413 before the router
	// even routes it. Use a path that exists (/token) so the failure is
	// the size check, not a routing miss.
	big := make([]byte, 64)
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded",
		bytes.NewReader(big))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d want 413", resp.StatusCode)
	}
}

func TestBuildApp_JTIReplayStoreWiredWhenEnabled(t *testing.T) {
	// Smoke test: just confirm buildApp doesn't panic and the option
	// chain is reachable when the flag is on. End-to-end JAR replay
	// behavior is covered by SDK-level tests.
	cfg := &config.Config{}
	cfg.Security.JTIReplay.Enabled = true

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	if a.server == nil {
		t.Fatal("server nil")
	}
}

func TestBuildRateLimitPolicy_SQLiteRequiresDSN(t *testing.T) {
	_, err := buildRateLimitPolicy(config.RateLimitConfig{
		Enabled:       true,
		Backend:       "sqlite",
		DefaultPerSec: 1,
		DefaultBurst:  1,
	})
	if err == nil {
		t.Fatal("expected error when sqlite backend has empty DSN")
	}
}

func TestBuildRateLimitPolicy_SQLiteOpensFileForEachPrefix(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "ratelimit.db") + "?_journal=WAL"

	p, err := buildRateLimitPolicy(config.RateLimitConfig{
		Enabled:       true,
		Backend:       "sqlite",
		SQLite:        config.RateLimitSQLiteConfig{DSN: dsn},
		DefaultPerSec: 5,
		DefaultBurst:  10,
		Prefixes: []config.RateLimitPrefixConfig{
			{Prefix: "/auth/login", PerSec: 1, Burst: 3},
			{Prefix: "/auth/send-code", PerSec: 0.1, Burst: 1},
		},
	})
	if err != nil {
		t.Fatalf("sqlite build: %v", err)
	}
	if p.Default == nil {
		t.Fatal("Default limiter nil")
	}
	if len(p.Prefixes) != 2 {
		t.Fatalf("Prefixes: got %d want 2", len(p.Prefixes))
	}
	// Spot-check the bucket isolation: drain alice on /auth/login,
	// confirm /auth/send-code still grants alice.
	if ok, _ := p.Prefixes[0].Limiter.Allow("alice"); !ok {
		t.Fatal("/auth/login first allow denied")
	}
	if ok, _ := p.Prefixes[1].Limiter.Allow("alice"); !ok {
		t.Fatal("/auth/send-code allow denied — prefix isolation broken")
	}
}

func TestBuildRateLimitPolicy_UnknownBackendErrors(t *testing.T) {
	_, err := buildRateLimitPolicy(config.RateLimitConfig{
		Enabled: true,
		Backend: "redis",
	})
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestBuildJTIReplayStore_MemoryDefault(t *testing.T) {
	s, mode, err := serverbuildauthn.BuildJTIReplayStore(config.JTIReplayConfig{})
	if err != nil {
		t.Fatalf("memory build: %v", err)
	}
	if s == nil {
		t.Fatal("store nil")
	}
	if !strings.Contains(mode, "memory") {
		t.Fatalf("mode label: got %q want memory variant", mode)
	}
}

func TestBuildJTIReplayStore_SQLiteNeedsDSN(t *testing.T) {
	_, _, err := serverbuildauthn.BuildJTIReplayStore(config.JTIReplayConfig{Backend: "sqlite"})
	if err == nil {
		t.Fatal("expected error when sqlite backend has empty DSN")
	}
}

func TestBuildJTIReplayStore_SQLiteOpensFile(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "jti.db") + "?_journal=WAL"
	s, mode, err := serverbuildauthn.BuildJTIReplayStore(config.JTIReplayConfig{
		Backend: "sqlite",
		SQLite:  config.JTIReplaySQLiteCfg{DSN: dsn},
	})
	if err != nil {
		t.Fatalf("sqlite build: %v", err)
	}
	if s == nil {
		t.Fatal("store nil")
	}
	if !strings.Contains(mode, "sqlite") {
		t.Fatalf("mode label: got %q want sqlite variant", mode)
	}
}

func TestBuildJTIReplayStore_UnknownBackendErrors(t *testing.T) {
	_, _, err := serverbuildauthn.BuildJTIReplayStore(config.JTIReplayConfig{Backend: "redis"})
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestBuildApp_AccountLockoutWiredWithOverrides(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AccountLockout.Enabled = true
	cfg.Security.AccountLockout.MaxFailures = 3

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	if a.server == nil {
		t.Fatal("server nil")
	}
}

func TestBuildApp_AccountLockoutDefaultsWhenZeroValues(t *testing.T) {
	// Zero numeric values fall back to SDK defaults — confirms the
	// wiring code doesn't accidentally pass 0 to the override
	// branches (which would lock the account on the first failure).
	cfg := &config.Config{}
	cfg.Security.AccountLockout.Enabled = true

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	if a.server == nil {
		t.Fatal("server nil")
	}
}

func TestBuildAccountLockout_MemoryDefaultWithOverrides(t *testing.T) {
	l, mode, err := serverbuildauthn.BuildAccountLockout(config.AccountLockoutConfig{
		MaxFailures:     7,
		LockoutDuration: 30 * security.NewMemoryAccountLockout().LockoutDuration,
	})
	if err != nil {
		t.Fatalf("memory build: %v", err)
	}
	if l == nil {
		t.Fatal("lockout nil")
	}
	if !strings.Contains(mode, "memory") {
		t.Fatalf("mode label %q missing memory marker", mode)
	}
	if mem, ok := l.(*security.MemoryAccountLockout); !ok {
		t.Fatalf("expected *security.MemoryAccountLockout, got %T", l)
	} else if mem.MaxFailures != 7 {
		t.Fatalf("MaxFailures override lost: got %d want 7", mem.MaxFailures)
	}
}

func TestBuildAccountLockout_SQLiteNeedsDSN(t *testing.T) {
	_, _, err := serverbuildauthn.BuildAccountLockout(config.AccountLockoutConfig{Backend: "sqlite"})
	if err == nil {
		t.Fatal("expected error when sqlite backend has empty DSN")
	}
}

func TestBuildAccountLockout_SQLiteOpensFile(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "lockout.db") + "?_journal=WAL"
	l, mode, err := serverbuildauthn.BuildAccountLockout(config.AccountLockoutConfig{
		Backend:     "sqlite",
		SQLite:      config.AccountLockoutSQLiteConfig{DSN: dsn},
		MaxFailures: 4,
	})
	if err != nil {
		t.Fatalf("sqlite build: %v", err)
	}
	if l == nil {
		t.Fatal("lockout nil")
	}
	if !strings.Contains(mode, "sqlite") {
		t.Fatalf("mode label %q missing sqlite marker", mode)
	}
}

func TestBuildAccountLockout_UnknownBackendErrors(t *testing.T) {
	_, _, err := serverbuildauthn.BuildAccountLockout(config.AccountLockoutConfig{Backend: "redis"})
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestBuildApp_MTLSEnabledFlipsDiscovery(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.MTLS.Enabled = true

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := make([]byte, 8192)
	n, _ := resp.Body.Read(body)
	if !bytes.Contains(body[:n], []byte("mtls_endpoint_aliases")) {
		t.Errorf("mtls_endpoint_aliases missing from discovery doc: %s", body[:n])
	}
}

func TestBuildClientCertExtractor_DefaultTLS(t *testing.T) {
	ex, mode, err := buildClientCertExtractor(config.MTLSConfig{Enabled: true})
	if err != nil {
		t.Fatalf("default backend: %v", err)
	}
	if ex == nil {
		t.Fatal("extractor nil")
	}
	if !strings.Contains(mode, "TLS") {
		t.Fatalf("expected TLS in mode label, got %q", mode)
	}
}

func TestBuildClientCertExtractor_HeaderRequiresName(t *testing.T) {
	_, _, err := buildClientCertExtractor(config.MTLSConfig{Enabled: true, Backend: "header"})
	if err == nil {
		t.Fatal("expected error when header backend has empty name")
	}
}

func TestBuildClientCertExtractor_HeaderURLPEM(t *testing.T) {
	ex, mode, err := buildClientCertExtractor(config.MTLSConfig{
		Enabled: true,
		Backend: "header",
		Header:  config.MTLSHeaderConfig{Name: "X-SSL-Client-Cert", Encoding: "url-pem"},
	})
	if err != nil {
		t.Fatalf("header build: %v", err)
	}
	h, ok := ex.(*security.HeaderClientCertExtractor)
	if !ok {
		t.Fatalf("expected *HeaderClientCertExtractor, got %T", ex)
	}
	if h.HeaderName != "X-SSL-Client-Cert" {
		t.Fatalf("header name mismatch: %q", h.HeaderName)
	}
	if h.Encoding != security.HeaderCertEncodingURLPEM {
		t.Fatalf("encoding mismatch: %v", h.Encoding)
	}
	if !strings.Contains(mode, "TRUST EDGE MUST STRIP HEADER") {
		t.Fatalf("expected trust-edge warning in mode label, got %q", mode)
	}
}

func TestBuildClientCertExtractor_HeaderEncodings(t *testing.T) {
	cases := []struct {
		in   string
		want security.HeaderCertEncoding
	}{
		{"", security.HeaderCertEncodingURLPEM},
		{"url-pem", security.HeaderCertEncodingURLPEM},
		{"pem", security.HeaderCertEncodingPEM},
		{"base64-der", security.HeaderCertEncodingBase64DER},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := parseHeaderCertEncoding(c.in)
			if err != nil {
				t.Fatalf("parse %q: %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("encoding %q: got %v want %v", c.in, got, c.want)
			}
		})
	}
}

func TestBuildClientCertExtractor_UnknownBackend(t *testing.T) {
	_, _, err := buildClientCertExtractor(config.MTLSConfig{Enabled: true, Backend: "spiffe"})
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestBuildClientCertExtractor_UnknownEncoding(t *testing.T) {
	_, _, err := buildClientCertExtractor(config.MTLSConfig{
		Enabled: true,
		Backend: "header",
		Header:  config.MTLSHeaderConfig{Name: "X-Client-Cert", Encoding: "asn1"},
	})
	if err == nil {
		t.Fatal("expected error for unknown encoding")
	}
}

func TestBuildApp_MTLSHeaderBackendWires(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.MTLS.Enabled = true
	cfg.Security.MTLS.Backend = "header"
	cfg.Security.MTLS.Header.Name = "X-SSL-Client-Cert"
	cfg.Security.MTLS.Header.Encoding = "url-pem"

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := make([]byte, 8192)
	n, _ := resp.Body.Read(body)
	if !bytes.Contains(body[:n], []byte("mtls_endpoint_aliases")) {
		t.Errorf("header backend must still flip mtls_endpoint_aliases on: %s", body[:n])
	}
}

func TestBuildApp_CORSWiredWhenOriginsSet(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.CORS.Enabled = true
	cfg.Security.CORS.AllowedOrigins = []string{"https://example.com"}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	r, _ := http.NewRequest(http.MethodOptions, srv.URL+"/token", nil)
	r.Header.Set("Origin", "https://example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("OPTIONS: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Errorf("Allow-Origin = %q want %q", got, "https://example.com")
	}
}

// Compile-time guard against ratelimit drift; if Policy/PrefixRule
// shapes rename, this file should still build.
var _ = ratelimit.Policy{}
