package compliance_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/protocols/compliance"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func newActiveConsentsFixture(t *testing.T) *compliance.ActiveConsentsReporter {
	t.Helper()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	consents := defaultimpl.NewMemoryConsentStore()

	for _, id := range []string{"u1", "u2"} {
		if err := users.CreateOrUpdate(ctx, &core.User{ID: id}); err != nil {
			t.Fatalf("create user %s: %v", id, err)
		}
	}
	// u1: one active grant.
	if err := consents.RecordConsent(ctx, core.ConsentGrant{UserID: "u1", ClientID: "app1", Scopes: []string{"openid"}, GrantedAt: time.Now()}); err != nil {
		t.Fatalf("record consent: %v", err)
	}
	// u2: one EXPIRED grant, must be excluded from the report.
	if err := consents.RecordConsent(ctx, core.ConsentGrant{
		UserID: "u2", ClientID: "app1", Scopes: []string{"openid"},
		GrantedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("record expired consent: %v", err)
	}

	return &compliance.ActiveConsentsReporter{Users: users, Consent: consents}
}

func TestActiveConsentsReporter_Generate(t *testing.T) {
	t.Parallel()
	r := newActiveConsentsFixture(t)

	rep, err := r.Generate(context.Background())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if rep.Total != 1 || len(rep.Consents) != 1 {
		t.Fatalf("consents = %+v, want exactly 1 active grant", rep.Consents)
	}
	if rep.Consents[0].UserID != "u1" || rep.Consents[0].ClientID != "app1" {
		t.Fatalf("unexpected active grant: %+v", rep.Consents[0])
	}
}

func TestActiveConsentsReporter_UnwiredIsEmptyNotError(t *testing.T) {
	t.Parallel()
	r := &compliance.ActiveConsentsReporter{}
	rep, err := r.Generate(context.Background())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if rep.Total != 0 || len(rep.Consents) != 0 {
		t.Fatalf("expected empty report, got %+v", rep)
	}
}

func TestHandleAdminActiveConsents(t *testing.T) {
	t.Parallel()
	r := newActiveConsentsFixture(t)
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/admin/compliance/consents", nil))
	compliance.HandleAdminActiveConsents(r, spi.NopLogger{}, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
