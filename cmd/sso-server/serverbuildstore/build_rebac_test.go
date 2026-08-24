package serverbuildstore

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/lifecycle/rebac"
)

func TestBuildReBACOptionsDisabled(t *testing.T) {
	opts, err := BuildReBACOptions(config.ReBACConfig{}, testLogger())
	if err != nil || len(opts) != 0 {
		t.Fatalf("opts=%d err=%v, want disabled no-op", len(opts), err)
	}
}

func TestBuildReBACOptionsMemory(t *testing.T) {
	opts, err := BuildReBACOptions(config.ReBACConfig{Enabled: true, Backend: "memory"}, testLogger())
	if err != nil {
		t.Fatalf("BuildReBACOptions: %v", err)
	}
	if len(opts) != 2 {
		t.Fatalf("got %d options, want store + engine", len(opts))
	}
	srv := sso.NewServer(opts...)
	if srv.RebacStore() == nil || srv.RebacEngine() == nil || srv.RebacEngine().HotRuntime() == nil {
		t.Fatal("stock options did not wire the ReBAC store, engine, and runtime")
	}
	if err := srv.RebacEngine().HotRuntime().Close(context.Background()); err != nil {
		t.Fatalf("close ReBAC runtime: %v", err)
	}
}

func TestBuildReBACOptionsRejectsUnknownBackend(t *testing.T) {
	_, err := BuildReBACOptions(config.ReBACConfig{Enabled: true, Backend: "redis"}, testLogger())
	if err == nil {
		t.Fatal("unknown ReBAC backend was accepted")
	}
}

func TestBuildReBACOptionsSQLite(t *testing.T) {
	dsn := fmt.Sprintf("file:%s?_journal=WAL", filepath.Join(t.TempDir(), "rebac.db"))
	opts, err := BuildReBACOptions(config.ReBACConfig{
		Enabled: true, Backend: "sqlite",
		SQLite: config.ReBACSQLiteConfig{DSN: dsn},
	}, testLogger())
	if err != nil {
		t.Fatalf("BuildReBACOptions sqlite: %v", err)
	}
	srv := sso.NewServer(opts...)
	store, engine := srv.RebacStore(), srv.RebacEngine()
	if store == nil || engine == nil {
		t.Fatal("SQLite options did not wire store and engine")
	}
	tuple := rebac.Tuple{Object: "document:42", Relation: "viewer", Subject: "user:alice"}
	if err := store.Write(context.Background(), tuple); err != nil {
		t.Fatalf("write tuple: %v", err)
	}
	allowed, err := engine.Check(context.Background(), tuple.Object, tuple.Relation, tuple.Subject)
	if err != nil || !allowed {
		t.Fatalf("check tuple: allowed=%v err=%v", allowed, err)
	}
	if err := engine.HotRuntime().Close(context.Background()); err != nil {
		t.Fatalf("close SQLite ReBAC runtime: %v", err)
	}
}
