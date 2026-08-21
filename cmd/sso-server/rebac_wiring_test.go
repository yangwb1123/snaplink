package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestBuildAppWiresConfiguredReBAC(t *testing.T) {
	cfg := &config.Config{ReBAC: config.ReBACConfig{Enabled: true, Backend: "memory"}}
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)
	if a.server.RebacStore() == nil || a.server.RebacEngine() == nil || a.server.RebacEngine().HotRuntime() == nil {
		t.Fatal("configured stock server did not wire the ReBAC runtime")
	}
	req := httptest.NewRequest(http.MethodGet, core.PathAuthzCheck+"?object=document%3A1&relation=viewer&subject=user%3Aalice", nil)
	rec := httptest.NewRecorder()
	a.server.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Fatalf("configured ReBAC check route returned native 404: %s", rec.Body.String())
	}
}
