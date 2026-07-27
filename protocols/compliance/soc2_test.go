package compliance_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/compliance"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func newSOC2Fixture(t *testing.T) (*compliance.SOC2Reporter, *audit.MemorySink) {
	t.Helper()
	ctx := context.Background()

	clients := defaultimpl.NewMemoryClientStore()
	if err := clients.Add(ctx, &core.Client{ID: "app1"}); err != nil {
		t.Fatalf("add client: %v", err)
	}

	prov := permissions.NewMemoryProvider()
	if err := prov.AddRole(ctx, "app1", permissions.Role{Code: "admin", Name: "Admin"}); err != nil {
		t.Fatalf("add role: %v", err)
	}
	if err := prov.AssignRoles(ctx, "u1", "app1", []string{"admin"}); err != nil {
		t.Fatalf("assign role: %v", err)
	}

	sink := audit.NewMemorySink(0)
	rec := audit.New(sink)
	rec.Record(ctx, &audit.Event{Type: audit.EventAdminRoleAssigned, Outcome: audit.OutcomeSuccess, ActorID: "admin1"})
	rec.Record(ctx, &audit.Event{Type: audit.EventAdminTokenRevoked, Outcome: audit.OutcomeSuccess, ActorID: "admin1"})
	// An event type NOT in either curated list must never appear in the pack.
	rec.Record(ctx, &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "u1"})

	return &compliance.SOC2Reporter{Permissions: prov, Clients: clients, Audit: sink}, sink
}

func TestSOC2Reporter_Generate(t *testing.T) {
	t.Parallel()
	r, _ := newSOC2Fixture(t)

	ev, err := r.Generate(context.Background(), compliance.SOC2Options{})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(ev.AccessReview) != 1 || ev.AccessReview[0].ClientID != "app1" {
		t.Fatalf("access review = %+v, want one entry for app1", ev.AccessReview)
	}
	if len(ev.AccessReview[0].Assignments) != 1 || ev.AccessReview[0].Assignments[0].UserID != "u1" {
		t.Fatalf("assignments = %+v", ev.AccessReview[0].Assignments)
	}
	if len(ev.ChangeManagement) != 1 || ev.ChangeManagement[0].Type != audit.EventAdminRoleAssigned {
		t.Fatalf("change management = %+v", ev.ChangeManagement)
	}
	if len(ev.AccessRevocation) != 1 || ev.AccessRevocation[0].Type != audit.EventAdminTokenRevoked {
		t.Fatalf("access revocation = %+v", ev.AccessRevocation)
	}
	if len(ev.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", ev.Errors)
	}
}

func TestSOC2Reporter_UnwiredSectionsAreSkipped(t *testing.T) {
	t.Parallel()
	r := &compliance.SOC2Reporter{}
	ev, err := r.Generate(context.Background(), compliance.SOC2Options{})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(ev.AccessReview) != 0 || len(ev.ChangeManagement) != 0 || len(ev.AccessRevocation) != 0 {
		t.Fatalf("expected empty sections, got %+v", ev)
	}
	want := map[string]bool{"access_review(not wired)": true, "change_management(not wired)": true, "access_revocation(not wired)": true}
	if len(ev.Skipped) != 3 {
		t.Fatalf("skipped = %v, want 3 entries", ev.Skipped)
	}
	for _, s := range ev.Skipped {
		if !want[s] {
			t.Errorf("unexpected skip reason %q", s)
		}
	}
}

func TestSOC2Reporter_SinceFiltersOldEvents(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(0)
	rec := audit.New(sink, audit.WithClock(func() time.Time { return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC) }))
	rec.Record(context.Background(), &audit.Event{Type: audit.EventAdminRoleAssigned, Outcome: audit.OutcomeSuccess})

	r := &compliance.SOC2Reporter{Audit: sink}
	ev, err := r.Generate(context.Background(), compliance.SOC2Options{Since: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(ev.ChangeManagement) != 0 {
		t.Fatalf("expected the 2020 event to be filtered out by Since, got %+v", ev.ChangeManagement)
	}
}

func TestHandleAdminSOC2Report(t *testing.T) {
	t.Parallel()
	r, _ := newSOC2Fixture(t)

	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/admin/compliance/soc2-evidence", nil))
	compliance.HandleAdminSOC2Report(r, spi.NopLogger{}, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got compliance.SOC2Evidence
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.AccessReview) != 1 {
		t.Fatalf("access review = %+v", got.AccessReview)
	}
}

func TestHandleAdminSOC2Report_InvalidSince(t *testing.T) {
	t.Parallel()
	r := &compliance.SOC2Reporter{}
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/admin/compliance/soc2-evidence?since=not-a-time", nil))
	compliance.HandleAdminSOC2Report(r, spi.NopLogger{}, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
