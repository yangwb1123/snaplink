package compliance_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/protocols/compliance"
	"github.com/snaplink/sso/shared/core"
)

// staticExporter is a SubjectExporter test double contributing a fixed
// payload under a fixed key.
type staticExporter struct {
	key  string
	data any
	err  error
}

func (s staticExporter) ExportSubject(context.Context, string) (any, error) { return s.data, s.err }
func (s staticExporter) ExportKey() string                                  { return s.key }

func TestExportSubject_BundlesUserSessionsAndExtras(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	sessions := defaultimpl.NewMemorySessionManager()
	if err := users.CreateOrUpdate(ctx, &core.User{ID: "u1", Email: "u1@example.com"}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := sessions.Create(ctx, "u1"); err != nil {
		t.Fatalf("create session: %v", err)
	}

	exp := &compliance.Exporter{
		Users:    users,
		Sessions: sessions,
		Extra: []compliance.SubjectExporter{
			staticExporter{key: "permissions", data: []string{"user:read"}},
		},
	}
	bundle, err := exp.ExportSubject(ctx, "u1")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	for _, key := range []string{"user", "sessions", "permissions"} {
		if _, ok := bundle.Data[key]; !ok {
			t.Errorf("bundle missing %q", key)
		}
	}
	if bundle.Subject != "u1" {
		t.Errorf("subject = %q, want u1", bundle.Subject)
	}
	// The whole bundle must be JSON-serializable for delivery.
	if _, err := json.Marshal(bundle); err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
}

func TestExportSubject_ExtraErrorIsBestEffort(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(ctx, &core.User{ID: "u1"}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	exp := &compliance.Exporter{
		Users: users,
		Extra: []compliance.SubjectExporter{
			staticExporter{key: "audit", err: context.DeadlineExceeded},
		},
	}
	bundle, err := exp.ExportSubject(ctx, "u1")
	if err == nil {
		t.Fatal("expected aggregated error from failing extra exporter")
	}
	// Partial bundle still returned with the user that did succeed.
	if _, ok := bundle.Data["user"]; !ok {
		t.Error("partial bundle missing user despite extra-exporter failure")
	}
}

func TestExportSubject_EmptyUserID(t *testing.T) {
	t.Parallel()
	exp := &compliance.Exporter{Users: defaultimpl.NewMemoryUserProvider()}
	if _, err := exp.ExportSubject(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty user id")
	}
}
