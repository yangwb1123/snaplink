package main

import (
	"testing"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/protocols/compliance"
)

// TestBuildApp_SelfServiceDataExport_IncludesConsentAndMFA pins the build-
// ordering fix for the self-service exporter: wireSelfServicePassword (which
// constructs b.dataExporter) runs BEFORE wireConsentStore / wireMFAEnrollment
// wire b.consentStore / b.mfaEnrollStore (see wireDomains / wireFinalOptions
// in build_stores.go / build_app_cluster.go), so a naive one-shot Extra
// assignment at construction time would silently capture nil stores. finalize
// late-binds Extra AFTER those stores exist (mirrors the accountEraser fix) —
// this test proves the retained pointer ends up with both exporters wired.
func TestBuildApp_SelfServiceDataExport_IncludesConsentAndMFA(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.SelfService.DataExport = true
	cfg.SelfService.Consent = config.SelfServiceStoreConfig{Backend: "memory"}
	cfg.Authenticators.TOTP = &config.TOTPConfig{Enabled: true}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)

	exp := a.server.DataExporter()
	if exp == nil {
		t.Fatal("DataExporter() nil despite SelfService.DataExport=true")
	}
	if len(exp.Extra) != 2 {
		t.Fatalf("DataExporter().Extra has %d entries, want 2 (consent + mfa_enrollments); got %#v", len(exp.Extra), exp.Extra)
	}
	gotKeys := map[string]bool{}
	for _, x := range exp.Extra {
		gotKeys[x.ExportKey()] = true
	}
	if !gotKeys[compliance.ExportKeyConsent] || !gotKeys[compliance.ExportKeyMFAEnrollments] {
		t.Fatalf("DataExporter().Extra keys = %v, want both %q and %q", gotKeys, compliance.ExportKeyConsent, compliance.ExportKeyMFAEnrollments)
	}
}

// TestBuildApp_SelfServiceDataExport_NoConsentOrMFAWired proves the exporter
// mounts with an empty Extra (not nil-panicking, not phantom keys) when
// SelfService.DataExport is on but neither consent nor MFA is configured —
// the nil-skip path in compliance.SubjectExporters.
func TestBuildApp_SelfServiceDataExport_NoConsentOrMFAWired(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.SelfService.DataExport = true

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)

	exp := a.server.DataExporter()
	if exp == nil {
		t.Fatal("DataExporter() nil despite SelfService.DataExport=true")
	}
	if len(exp.Extra) != 0 {
		t.Fatalf("DataExporter().Extra = %#v, want empty (neither consent nor MFA wired)", exp.Extra)
	}
}
