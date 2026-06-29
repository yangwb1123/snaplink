package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/shared/core"
)

func newDeviceSecretStore(t *testing.T) *sqlitestores.DeviceSecretStore {
	t.Helper()
	dsn := "file:devsec_" + t.Name() + "?mode=memory&cache=shared&_pragma=busy_timeout(5000)"
	s, err := sqlitestores.NewDeviceSecretStore(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSQLiteDeviceSecretStore_IssueConsume(t *testing.T) {
	t.Parallel()
	s := newDeviceSecretStore(t)
	ctx := context.Background()
	ds := &core.DeviceSecret{Secret: "x1", Subject: "u1", SID: "s1", ClientID: "a", ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.Issue(ctx, ds); err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := s.Consume(ctx, "x1")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.Subject != "u1" || got.SID != "s1" || got.ClientID != "a" {
		t.Errorf("binding=%+v", got)
	}
	// Single-use.
	if _, err := s.Consume(ctx, "x1"); !errors.Is(err, core.ErrDeviceSecretNotFound) {
		t.Errorf("second consume err=%v", err)
	}
}

func TestSQLiteDeviceSecretStore_Missing(t *testing.T) {
	t.Parallel()
	s := newDeviceSecretStore(t)
	if _, err := s.Consume(context.Background(), "nope"); !errors.Is(err, core.ErrDeviceSecretNotFound) {
		t.Errorf("err=%v want ErrDeviceSecretNotFound", err)
	}
}

func TestSQLiteDeviceSecretStore_Expired(t *testing.T) {
	t.Parallel()
	s := newDeviceSecretStore(t)
	ctx := context.Background()
	_ = s.Issue(ctx, &core.DeviceSecret{Secret: "old", Subject: "u", ClientID: "c", ExpiresAt: time.Now().Add(-time.Second)})
	if _, err := s.Consume(ctx, "old"); !errors.Is(err, core.ErrDeviceSecretNotFound) {
		t.Errorf("expired err=%v want ErrDeviceSecretNotFound", err)
	}
}
