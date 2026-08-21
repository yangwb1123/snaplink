package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	permsqlite "github.com/yangwb1123/snaplink/domains/permissions/sqlite"
)

func TestResourceCatalog_PersistsAcrossRestart(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "resources.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	ctx := context.Background()
	want := &permissions.Resource{
		ID: "resource-1", TenantID: "tenant-a", ClientID: "client-a",
		Type: permissions.ResourceTypeHTTPAPI, Name: "get-user",
		RequiresAuth: true, RequiredPermissions: []string{"user:read"},
		Attributes: map[string]string{"method": "GET", "path": "/users/:id"},
	}
	p, err := permsqlite.New(dsn)
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	if err := p.RegisterResource(ctx, want); err != nil {
		t.Fatalf("RegisterResource: %v", err)
	}
	created, err := p.GetResource(ctx, want.ID)
	if err != nil {
		t.Fatalf("first GetResource: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	p, err = permsqlite.New(dsn)
	if err != nil {
		t.Fatalf("second New: %v", err)
	}
	defer func() { _ = p.Close() }()
	got, err := p.GetResource(ctx, want.ID)
	if err != nil {
		t.Fatalf("second GetResource: %v", err)
	}
	if got.Attributes["path"] != "/users/:id" || !got.RequiresAuth {
		t.Fatalf("persisted resource mismatch: %+v", got)
	}
	if !got.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("created_at changed across restart: got %v want %v", got.CreatedAt, created.CreatedAt)
	}
	decision, err := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "tenant-a", ClientID: "client-a", Type: permissions.ResourceTypeHTTPAPI,
		Match: map[string]string{"method": "GET", "path": "/users/42"},
	})
	if err != nil {
		t.Fatalf("ResolveResource: %v", err)
	}
	if !decision.Found || decision.ResourceID != want.ID {
		t.Fatalf("decision = %+v", decision)
	}
}
