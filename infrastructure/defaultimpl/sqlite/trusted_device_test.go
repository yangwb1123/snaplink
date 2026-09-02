package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/shared/core"
)

// newTrustedDeviceStore opens a real temp-file SQLite database (not
// mode=memory) so persistence-across-reopen can be exercised by closing and
// reopening the SAME dsn.
func newTrustedDeviceStore(t *testing.T, dsn string) *sqlitestores.TrustedDeviceStore {
	t.Helper()
	s, err := sqlitestores.NewTrustedDeviceStore(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s
}

func tempTrustedDeviceDSN(t *testing.T) string {
	t.Helper()
	return "file:" + filepath.Join(t.TempDir(), "trusted_devices.db")
}

func TestSQLiteTrustedDeviceStore_TrustThenVerify(t *testing.T) {
	t.Parallel()
	dsn := tempTrustedDeviceDSN(t)
	s := newTrustedDeviceStore(t, dsn)
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	token, dev, err := s.Trust(ctx, "alice", "client-a", "Chrome on macOS", time.Hour)
	if err != nil {
		t.Fatalf("trust: %v", err)
	}
	if token == "" {
		t.Fatal("empty token returned")
	}
	if dev == nil || dev.ID == "" {
		t.Fatalf("no device record returned: %+v", dev)
	}
	if dev.UserID != "alice" || dev.ClientID != "client-a" || dev.Label != "Chrome on macOS" {
		t.Fatalf("device record mismatch: %+v", dev)
	}

	ok, err := s.Verify(ctx, "alice", "client-a", token)
	if err != nil || !ok {
		t.Fatalf("verify = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestSQLiteTrustedDeviceStore_TrustDefaultsTTL(t *testing.T) {
	t.Parallel()
	s := newTrustedDeviceStore(t, tempTrustedDeviceDSN(t))
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	_, dev, err := s.Trust(ctx, "alice", "client-a", "", 0)
	if err != nil {
		t.Fatalf("trust: %v", err)
	}
	want := dev.CreatedAt.Add(core.DefaultTrustedDeviceTTL)
	if dev.ExpiresAt.Before(want.Add(-time.Second)) || dev.ExpiresAt.After(want.Add(time.Second)) {
		t.Errorf("ExpiresAt = %v, want ~%v (DefaultTrustedDeviceTTL applied)", dev.ExpiresAt, want)
	}
}

// TestSQLiteTrustedDeviceStore_PlaintextNotStored proves the store never
// persists a usable copy of the token — only its SHA-256 hash — by reading
// the raw column back via the exported DB() accessor (no white-box package
// access needed: DB() is part of the store's public surface for the
// storage-health reporter, so a black-box test can use it the same way).
func TestSQLiteTrustedDeviceStore_PlaintextNotStored(t *testing.T) {
	t.Parallel()
	s := newTrustedDeviceStore(t, tempTrustedDeviceDSN(t))
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	token, dev, err := s.Trust(ctx, "alice", "client-a", "", time.Hour)
	if err != nil {
		t.Fatalf("trust: %v", err)
	}

	var hash string
	if err := s.DB().QueryRowContext(ctx,
		`SELECT token_hash FROM trusted_devices WHERE id = ?`, dev.ID).Scan(&hash); err != nil {
		t.Fatalf("query raw row: %v", err)
	}
	if hash == token {
		t.Fatalf("stored token_hash equals the plaintext token — hashing not applied")
	}
	if len(hash) != 64 { // SHA-256 hex digest length
		t.Fatalf("stored hash %q is %d chars, want a 64-char SHA-256 hex digest", hash, len(hash))
	}
}

// TestSQLiteTrustedDeviceStore_AntiEnumerationCollapse is the explicit
// anti-enumeration proof required by core.TrustedDeviceStore's doc comment:
// unknown token, expired grant, wrong user, and wrong client MUST all
// collapse to the exact same (false, nil) — never a distinguishable error —
// mirroring memorystorecredential's
// TestMemoryTrustedDeviceStore_VerifyScopedToUserAndClient /
// TestMemoryTrustedDeviceStore_VerifyRejectsExpired pair, combined into one
// table so the "all four are indistinguishable" property is checked in one
// place.
func TestSQLiteTrustedDeviceStore_AntiEnumerationCollapse(t *testing.T) {
	t.Parallel()
	s := newTrustedDeviceStore(t, tempTrustedDeviceDSN(t))
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	liveToken, _, err := s.Trust(ctx, "alice", "client-a", "", time.Hour)
	if err != nil {
		t.Fatalf("trust live: %v", err)
	}
	expiredToken, _, err := s.Trust(ctx, "alice", "client-a", "", time.Millisecond)
	if err != nil {
		t.Fatalf("trust expiring: %v", err)
	}
	time.Sleep(5 * time.Millisecond)

	cases := []struct {
		name     string
		user     string
		clientID string
		token    string
	}{
		{"unknown token", "alice", "client-a", "not-a-real-token"},
		{"expired grant", "alice", "client-a", expiredToken},
		{"wrong user", "mallory", "client-a", liveToken},
		{"wrong client", "alice", "client-b", liveToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := s.Verify(ctx, tc.user, tc.clientID, tc.token)
			if err != nil {
				t.Fatalf("verify returned an error (must be nil/false, never a distinguishable error): %v", err)
			}
			if ok {
				t.Fatalf("verify(%s) = true, want false — the four failure modes must be indistinguishable", tc.name)
			}
		})
	}

	// Sanity: the SAME live token, on the SAME user+client, still verifies —
	// proves the negative cases above are about the failure dimension being
	// tested, not a broken store.
	ok, err := s.Verify(ctx, "alice", "client-a", liveToken)
	if err != nil || !ok {
		t.Fatalf("control verify = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestSQLiteTrustedDeviceStore_VerifyEmptyInputs(t *testing.T) {
	t.Parallel()
	s := newTrustedDeviceStore(t, tempTrustedDeviceDSN(t))
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	if ok, err := s.Verify(ctx, "", "client-a", "whatever"); err != nil || ok {
		t.Errorf("empty user = (%v, %v), want (false, nil)", ok, err)
	}
	if ok, err := s.Verify(ctx, "alice", "client-a", ""); err != nil || ok {
		t.Errorf("empty token = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestSQLiteTrustedDeviceStore_ListByUserOmitsHashAndOtherUsers(t *testing.T) {
	t.Parallel()
	s := newTrustedDeviceStore(t, tempTrustedDeviceDSN(t))
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	_, _, _ = s.Trust(ctx, "alice", "client-a", "phone", time.Hour)
	_, _, _ = s.Trust(ctx, "alice", "client-b", "laptop", time.Hour)
	_, _, _ = s.Trust(ctx, "mallory", "client-a", "other", time.Hour)

	devices, err := s.ListByUser(ctx, "alice")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("len(devices) = %d, want 2", len(devices))
	}
	for _, d := range devices {
		if d.UserID != "alice" {
			t.Errorf("leaked another user's device: %+v", d)
		}
	}

	if other, _ := s.ListByUser(ctx, "carol"); len(other) != 0 {
		t.Errorf("carol should have no devices, got %d", len(other))
	}

	// core.TrustedDevice has no hash-carrying field at all, so the mere fact
	// ListByUser returns []core.TrustedDevice structurally guarantees no
	// hash leaks through this path — this assertion documents that intent.
	var _ []core.TrustedDevice = devices
}

func TestSQLiteTrustedDeviceStore_ListOmitsExpired(t *testing.T) {
	t.Parallel()
	s := newTrustedDeviceStore(t, tempTrustedDeviceDSN(t))
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	if _, _, err := s.Trust(ctx, "alice", "client-old", "old", time.Millisecond); err != nil {
		t.Fatalf("expired trust: %v", err)
	}
	_, live, err := s.Trust(ctx, "alice", "client-live", "live", time.Hour)
	if err != nil {
		t.Fatalf("live trust: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	devices, err := s.ListByUser(ctx, "alice")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(devices) != 1 || devices[0].ID != live.ID {
		t.Fatalf("devices = %#v, want only live device", devices)
	}
}

func TestSQLiteTrustedDeviceStore_RevokeIsOwnershipScopedAndIdempotent(t *testing.T) {
	t.Parallel()
	s := newTrustedDeviceStore(t, tempTrustedDeviceDSN(t))
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	token, dev, err := s.Trust(ctx, "alice", "client-a", "", time.Hour)
	if err != nil {
		t.Fatalf("trust: %v", err)
	}

	// Cross-user revoke touches nothing.
	if err := s.Revoke(ctx, "mallory", dev.ID); err != nil {
		t.Fatalf("cross-user revoke: %v", err)
	}
	if ok, _ := s.Verify(ctx, "alice", "client-a", token); !ok {
		t.Fatal("cross-user revoke removed alice's device")
	}

	// Owner revoke removes it.
	if err := s.Revoke(ctx, "alice", dev.ID); err != nil {
		t.Fatalf("owner revoke: %v", err)
	}
	if ok, _ := s.Verify(ctx, "alice", "client-a", token); ok {
		t.Fatal("device still verifies after revoke")
	}

	// Idempotent: revoking again (or an unknown id) is a no-op, not an error.
	if err := s.Revoke(ctx, "alice", dev.ID); err != nil {
		t.Fatalf("repeat revoke: %v", err)
	}
	if err := s.Revoke(ctx, "alice", "no-such-id"); err != nil {
		t.Fatalf("revoke unknown id: %v", err)
	}
}

func TestSQLiteTrustedDeviceStore_RevokeAll(t *testing.T) {
	t.Parallel()
	s := newTrustedDeviceStore(t, tempTrustedDeviceDSN(t))
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	tokenA, _, _ := s.Trust(ctx, "alice", "client-a", "", time.Hour)
	tokenB, _, _ := s.Trust(ctx, "alice", "client-b", "", time.Hour)
	otherToken, _, _ := s.Trust(ctx, "mallory", "client-a", "", time.Hour)

	n, err := s.RevokeAll(ctx, "alice")
	if err != nil {
		t.Fatalf("revoke-all: %v", err)
	}
	if n != 2 {
		t.Fatalf("revoke-all count = %d, want 2", n)
	}
	if ok, _ := s.Verify(ctx, "alice", "client-a", tokenA); ok {
		t.Error("tokenA still verifies after revoke-all")
	}
	if ok, _ := s.Verify(ctx, "alice", "client-b", tokenB); ok {
		t.Error("tokenB still verifies after revoke-all")
	}
	// A different user's grant is untouched.
	if ok, _ := s.Verify(ctx, "mallory", "client-a", otherToken); !ok {
		t.Error("revoke-all for alice touched mallory's grant")
	}

	// Revoking an unknown user is a clean 0, nil.
	if n, err := s.RevokeAll(ctx, "nobody"); n != 0 || err != nil {
		t.Fatalf("revoke-all unknown user = (%d, %v), want (0, nil)", n, err)
	}
}

// TestSQLiteTrustedDeviceStore_PersistsAcrossReopen proves the whole point of
// this store existing: unlike MemoryTrustedDeviceStore, a grant survives a
// process restart because it's the SAME on-disk file being reopened, not a
// fresh in-process map.
func TestSQLiteTrustedDeviceStore_PersistsAcrossReopen(t *testing.T) {
	t.Parallel()
	dsn := tempTrustedDeviceDSN(t)
	ctx := context.Background()

	s1 := newTrustedDeviceStore(t, dsn)
	token, dev, err := s1.Trust(ctx, "alice", "client-a", "phone", time.Hour)
	if err != nil {
		t.Fatalf("trust: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen against the same dsn — a fresh *TrustedDeviceStore, no shared
	// in-process state with s1.
	s2 := newTrustedDeviceStore(t, dsn)
	t.Cleanup(func() { _ = s2.Close() })

	ok, err := s2.Verify(ctx, "alice", "client-a", token)
	if err != nil || !ok {
		t.Fatalf("verify after reopen = (%v, %v), want (true, nil)", ok, err)
	}
	devices, err := s2.ListByUser(ctx, "alice")
	if err != nil || len(devices) != 1 || devices[0].ID != dev.ID {
		t.Fatalf("ListByUser after reopen = %+v, %v; want the one grant from before restart", devices, err)
	}
}

func TestSQLiteTrustedDeviceStore_WithDBAndMaxVersion(t *testing.T) {
	t.Parallel()
	if v := sqlitestores.TrustedDeviceMaxVersion(); v != 1 {
		t.Errorf("TrustedDeviceMaxVersion() = %d, want 1", v)
	}

	dsn := tempTrustedDeviceDSN(t)
	base := newTrustedDeviceStore(t, dsn)
	db := base.DB()
	t.Cleanup(func() { _ = base.Close() })

	s2, err := sqlitestores.NewTrustedDeviceStoreWithDB(db)
	if err != nil {
		t.Fatalf("NewTrustedDeviceStoreWithDB: %v", err)
	}
	if s2.DB() != db {
		t.Error("NewTrustedDeviceStoreWithDB did not wrap the given *sql.DB")
	}
	if err := s2.Ping(context.Background()); err != nil {
		t.Errorf("ping: %v", err)
	}
}

var _ core.TrustedDeviceStore = (*sqlitestores.TrustedDeviceStore)(nil)
