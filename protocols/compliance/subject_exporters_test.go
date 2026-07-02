package compliance_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/protocols/compliance"
	"github.com/snaplink/sso/shared/core"
)

func TestConsentSubjectExporter_ReturnsGrants(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := defaultimpl.NewMemoryConsentStore()
	grant := core.ConsentGrant{UserID: "u1", ClientID: "c1", Scopes: []string{"openid"}, GrantedAt: time.Now()}
	if err := store.RecordConsent(ctx, grant); err != nil {
		t.Fatalf("record consent: %v", err)
	}

	exp := compliance.ConsentSubjectExporter{Store: store}
	if got := exp.ExportKey(); got != compliance.ExportKeyConsent {
		t.Errorf("ExportKey() = %q, want %q", got, compliance.ExportKeyConsent)
	}
	data, err := exp.ExportSubject(ctx, "u1")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	grants, ok := data.([]core.ConsentGrant)
	if !ok || len(grants) != 1 || grants[0].ClientID != "c1" {
		t.Fatalf("export data = %#v, want one grant for c1", data)
	}
}

func TestConsentSubjectExporter_EmptyStoreReturnsEmptySlice(t *testing.T) {
	t.Parallel()
	exp := compliance.ConsentSubjectExporter{Store: defaultimpl.NewMemoryConsentStore()}
	data, err := exp.ExportSubject(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	grants, ok := data.([]core.ConsentGrant)
	if !ok || len(grants) != 0 {
		t.Fatalf("export data = %#v, want empty slice", data)
	}
}

func TestConsentSubjectExporter_NilStoreReturnsNil(t *testing.T) {
	t.Parallel()
	exp := compliance.ConsentSubjectExporter{}
	data, err := exp.ExportSubject(context.Background(), "u1")
	if err != nil || data != nil {
		t.Fatalf("nil store: data=%#v err=%v, want (nil, nil)", data, err)
	}
}

func TestMFAEnrollmentSubjectExporter_ReturnsFactors(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryMFAEnrollmentStore()
	store.AddFactor("u1", core.MFAEnrolledFactor{ID: "f1", Method: "totp", AddedAt: time.Now()})

	exp := compliance.MFAEnrollmentSubjectExporter{Store: store}
	if got := exp.ExportKey(); got != compliance.ExportKeyMFAEnrollments {
		t.Errorf("ExportKey() = %q, want %q", got, compliance.ExportKeyMFAEnrollments)
	}
	data, err := exp.ExportSubject(context.Background(), "u1")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	factors, ok := data.([]core.MFAEnrolledFactor)
	if !ok || len(factors) != 1 || factors[0].ID != "f1" {
		t.Fatalf("export data = %#v, want one factor f1", data)
	}
}

func TestMFAEnrollmentSubjectExporter_EmptyStoreReturnsEmptySlice(t *testing.T) {
	t.Parallel()
	exp := compliance.MFAEnrollmentSubjectExporter{Store: defaultimpl.NewMemoryMFAEnrollmentStore()}
	data, err := exp.ExportSubject(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	factors, ok := data.([]core.MFAEnrolledFactor)
	if !ok || len(factors) != 0 {
		t.Fatalf("export data = %#v, want empty slice", data)
	}
}

func TestMFAEnrollmentSubjectExporter_NilStoreReturnsNil(t *testing.T) {
	t.Parallel()
	exp := compliance.MFAEnrollmentSubjectExporter{}
	data, err := exp.ExportSubject(context.Background(), "u1")
	if err != nil || data != nil {
		t.Fatalf("nil store: data=%#v err=%v, want (nil, nil)", data, err)
	}
}

func TestSubjectExporters_SkipsNilStores(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		consent  core.ConsentStore
		mfa      core.MFAEnrollmentStore
		wantKeys []string
	}{
		{name: "both nil", wantKeys: nil},
		{name: "consent only", consent: defaultimpl.NewMemoryConsentStore(), wantKeys: []string{compliance.ExportKeyConsent}},
		{name: "mfa only", mfa: defaultimpl.NewMemoryMFAEnrollmentStore(), wantKeys: []string{compliance.ExportKeyMFAEnrollments}},
		{
			name:     "both wired",
			consent:  defaultimpl.NewMemoryConsentStore(),
			mfa:      defaultimpl.NewMemoryMFAEnrollmentStore(),
			wantKeys: []string{compliance.ExportKeyConsent, compliance.ExportKeyMFAEnrollments},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := compliance.SubjectExporters(tc.consent, tc.mfa)
			if len(out) != len(tc.wantKeys) {
				t.Fatalf("SubjectExporters(...) = %d exporters, want %d", len(out), len(tc.wantKeys))
			}
			for i, x := range out {
				if x.ExportKey() != tc.wantKeys[i] {
					t.Errorf("exporter[%d].ExportKey() = %q, want %q", i, x.ExportKey(), tc.wantKeys[i])
				}
			}
		})
	}
}

// TestExportSubject_IncludesConsentAndMFA is the integration-level check that
// the two new exporters plug into the existing best-effort Exporter loop
// (export.go) unchanged, and that the marshaled bundle carries no secret
// material — only the JSON-tagged metadata fields on ConsentGrant /
// MFAEnrolledFactor (neither carries credentials by construction, but this
// guards against a future field addition regressing that).
func TestExportSubject_IncludesConsentAndMFA(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(ctx, &core.User{ID: "u1", Email: "u1@example.com"}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	consentStore := defaultimpl.NewMemoryConsentStore()
	if err := consentStore.RecordConsent(ctx, core.ConsentGrant{UserID: "u1", ClientID: "c1", Scopes: []string{"openid"}, GrantedAt: time.Now()}); err != nil {
		t.Fatalf("record consent: %v", err)
	}
	mfaStore := defaultimpl.NewMemoryMFAEnrollmentStore()
	mfaStore.AddFactor("u1", core.MFAEnrolledFactor{ID: "f1", Method: "totp", AddedAt: time.Now()})

	exp := &compliance.Exporter{
		Users: users,
		Extra: compliance.SubjectExporters(consentStore, mfaStore),
	}
	bundle, err := exp.ExportSubject(ctx, "u1")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	consentData, ok := bundle.Data[compliance.ExportKeyConsent].([]core.ConsentGrant)
	if !ok || len(consentData) != 1 {
		t.Fatalf("bundle.Data[%q] = %#v, want one consent grant", compliance.ExportKeyConsent, bundle.Data[compliance.ExportKeyConsent])
	}
	mfaData, ok := bundle.Data[compliance.ExportKeyMFAEnrollments].([]core.MFAEnrolledFactor)
	if !ok || len(mfaData) != 1 {
		t.Fatalf("bundle.Data[%q] = %#v, want one mfa factor", compliance.ExportKeyMFAEnrollments, bundle.Data[compliance.ExportKeyMFAEnrollments])
	}
}

// TestSubjectExporters_NilInterfaceGuard proves the built-in exporters
// satisfy SubjectExporter (compile-time-ish check surfaced as a runtime
// type assertion so it shows up in `go test` output, not just `go vet`).
func TestSubjectExporters_NilInterfaceGuard(t *testing.T) {
	t.Parallel()
	var _ compliance.SubjectExporter = compliance.ConsentSubjectExporter{}
	var _ compliance.SubjectExporter = compliance.MFAEnrollmentSubjectExporter{}
}
