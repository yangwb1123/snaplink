package postgres

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	_ "modernc.org/sqlite"
)

func openSQLiteTenantUserStore(t *testing.T) (*TenantUserStore, *sql.DB) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "tenant-memberships.db")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	store, err := NewTenantUserStoreWithDB(context.Background(), db, DialectCockroach)
	if err != nil {
		_ = db.Close()
		t.Fatalf("NewTenantUserStoreWithDB: %v", err)
	}
	return store, db
}

func TestTenantUserStorePostgresBehavior(t *testing.T) {
	t.Parallel()
	store, db := openSQLiteTenantUserStore(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	created := time.Date(2026, 8, 30, 12, 0, 0, 123456789, time.UTC)
	first := &core.TenantMembership{TenantID: "tenant-a", UserID: "user-a", Role: core.TenantRoleMember, CreatedAt: created}
	if err := store.Add(ctx, first); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := store.Get(ctx, first.TenantID, first.UserID)
	if err != nil || got.Role != first.Role || !got.CreatedAt.Equal(created) {
		t.Fatalf("Get roundtrip = %+v, err=%v", got, err)
	}
	updatedAt := created.Add(time.Minute)
	if err := store.Add(ctx, &core.TenantMembership{TenantID: first.TenantID, UserID: first.UserID, Role: core.TenantRoleAdmin, CreatedAt: updatedAt}); err != nil {
		t.Fatalf("upsert role: %v", err)
	}
	if err := store.Add(ctx, &core.TenantMembership{TenantID: first.TenantID, UserID: "user-b", Role: core.TenantRoleMember, CreatedAt: created}); err != nil {
		t.Fatalf("add second tenant member: %v", err)
	}
	if err := store.Add(ctx, &core.TenantMembership{TenantID: "tenant-b", UserID: first.UserID, Role: core.TenantRoleMember, CreatedAt: created}); err != nil {
		t.Fatalf("add second tenant: %v", err)
	}
	got, err = store.Get(ctx, first.TenantID, first.UserID)
	if err != nil || got.Role != core.TenantRoleAdmin || !got.CreatedAt.Equal(updatedAt) {
		t.Fatalf("Get after upsert = %+v, err=%v", got, err)
	}
	byTenant, err := store.ListByTenant(ctx, first.TenantID)
	if err != nil || len(byTenant) != 2 || byTenant[0].UserID != "user-a" || byTenant[1].UserID != "user-b" {
		t.Fatalf("ListByTenant = %+v, err=%v", byTenant, err)
	}
	byUser, err := store.ListByUser(ctx, first.UserID)
	if err != nil || len(byUser) != 2 || byUser[0].TenantID != "tenant-a" || byUser[1].TenantID != "tenant-b" {
		t.Fatalf("ListByUser = %+v, err=%v", byUser, err)
	}
	if err := store.Remove(ctx, first.TenantID, first.UserID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := store.Remove(ctx, first.TenantID, first.UserID); err != nil {
		t.Fatalf("idempotent Remove: %v", err)
	}
	if _, err := store.Get(ctx, first.TenantID, first.UserID); !errors.Is(err, core.ErrNoMembership) {
		t.Fatalf("Get after removal error = %v, want ErrNoMembership", err)
	}
}
