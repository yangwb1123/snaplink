package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
)

func fetchDoc(t *testing.T, url string) (map[string]any, http.Header) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)
	return doc, resp.Header
}

func TestBuildApp_DiscoveryDocCacheTTLDisabledOmitsCacheControl(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.DiscoveryDocCacheTTL = -1 // SDK treats <=0 as disabled

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	_, hdr := fetchDoc(t, srv.URL+"/.well-known/openid-configuration")
	if cc := hdr.Get("Cache-Control"); cc != "" {
		t.Fatalf("Cache-Control header present when cache disabled: %q", cc)
	}
}

func TestBuildApp_JWKSCacheTTLAppliedToResponse(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.JWKSCacheTTL = 17 * time.Second

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	cc := resp.Header.Get("Cache-Control")
	// SDK emits "public, max-age=<seconds>" — confirm our TTL flowed through.
	if !strings.Contains(cc, "max-age=17") {
		t.Fatalf("Cache-Control %q missing max-age=17", cc)
	}
}

func TestBuildApp_DiscoveryCacheTTLBuildsCleanly(t *testing.T) {
	// The clientDiscoverySnapshot cache is in-process only; behavior
	// is observable as fewer client-store iterations. Smoke test just
	// confirms wiring doesn't panic and the discovery endpoint still
	// answers when the override is set.
	cfg := &config.Config{}
	cfg.Server.DiscoveryCacheTTL = 2 * time.Second

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc, _ := fetchDoc(t, srv.URL+"/.well-known/openid-configuration")
	if _, ok := doc["issuer"]; !ok {
		t.Fatal("discovery doc missing issuer when DiscoveryCacheTTL set")
	}
}
