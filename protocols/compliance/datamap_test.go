package compliance_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/protocols/compliance"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

func TestBuildDataMap_CoreCategoriesPresent(t *testing.T) {
	t.Parallel()
	dm := compliance.BuildDataMap(compliance.DataMapOptions{})
	if dm.GeneratedAt.IsZero() {
		t.Fatal("GeneratedAt not set")
	}
	want := []string{"user_profile", "sessions", "consent_grants", "mfa_enrollments", "refresh_tokens", "audit_log"}
	got := make(map[string]bool, len(dm.Categories))
	for _, c := range dm.Categories {
		got[c.Name] = true
		if c.Store == "" || c.RetentionPolicy == "" || len(c.Fields) == 0 {
			t.Errorf("category %s missing required field(s): %+v", c.Name, c)
		}
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("missing expected category %q", name)
		}
	}
}

func TestBuildDataMap_FoldsConfiguredRetention(t *testing.T) {
	t.Parallel()
	dm := compliance.BuildDataMap(compliance.DataMapOptions{
		ConsentMaxTTL:        30 * 24 * time.Hour,
		AuditRetentionMaxAge: 90 * 24 * time.Hour,
	})
	var consent, auditLog compliance.DataCategory
	for _, c := range dm.Categories {
		switch c.Name {
		case "consent_grants":
			consent = c
		case "audit_log":
			auditLog = c
		}
	}
	if !strings.Contains(consent.RetentionPolicy, "720h0m0s") {
		t.Errorf("consent retention policy = %q, want it to mention the configured TTL", consent.RetentionPolicy)
	}
	if !strings.Contains(auditLog.RetentionPolicy, "2160h0m0s") {
		t.Errorf("audit retention policy = %q, want it to mention the configured max age", auditLog.RetentionPolicy)
	}
}

func TestHandleAdminDataMap(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/admin/compliance/data-map", nil))
	compliance.HandleAdminDataMap(compliance.DataMapOptions{}, spi.NopLogger{}, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
