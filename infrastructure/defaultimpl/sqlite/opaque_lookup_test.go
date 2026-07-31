package sqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

var (
	lookupKeyCurrent  = []byte("0123456789abcdef0123456789abcdef")
	lookupKeyPrevious = []byte("abcdef0123456789abcdef0123456789")
)

func TestOpaqueLookupHMACProtectsSQLiteArtifacts(t *testing.T) {
	t.Run("authorization code", testAuthCodeLookupHMAC)
	t.Run("refresh token", testRefreshTokenLookupHMAC)
	t.Run("device codes", testDeviceCodeLookupHMAC)
	t.Run("PAR request URI", testPARLookupHMAC)
}

func testAuthCodeLookupHMAC(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.NewAuthCodeStore(filepath.Join(t.TempDir(), "auth.db"))
	mustLookup(t, err)
	defer func() { _ = store.Close() }()
	store.SetLookupHMACKeys(lookupKeyCurrent)
	mustLookup(t, store.Issue(ctx, "raw-auth-code", &oauth.AuthCode{
		UserID: "u", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute),
	}))
	assertStoredLookupIsHashed(t, store.DB(), "auth_codes", "code", "raw-auth-code")
	_, err = store.Consume(ctx, "raw-auth-code")
	mustLookup(t, err)
}

func testRefreshTokenLookupHMAC(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.NewRefreshTokenStore(filepath.Join(t.TempDir(), "refresh.db"))
	mustLookup(t, err)
	defer func() { _ = store.Close() }()
	store.SetLookupHMACKeys(lookupKeyCurrent)
	mustLookup(t, store.Issue(ctx, "raw-refresh-token", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", FamilyID: "f",
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}))
	assertStoredLookupIsHashed(t, store.DB(), "refresh_tokens", "token", "raw-refresh-token")
	_, err = store.Inspect(ctx, "raw-refresh-token")
	mustLookup(t, err)
}

func testDeviceCodeLookupHMAC(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.NewDeviceCodeStore(filepath.Join(t.TempDir(), "device.db"))
	mustLookup(t, err)
	defer func() { _ = store.Close() }()
	store.SetLookupHMACKeys(lookupKeyCurrent)
	mustLookup(t, store.Issue(ctx, &oauth.DeviceCode{
		DeviceCode: "raw-device-code", UserCode: "RAW-USER",
		ClientID: "c", ExpiresAt: time.Now().Add(time.Minute),
	}))
	assertStoredLookupIsHashed(t, store.DB(), "device_codes", "device_code", "raw-device-code")
	assertStoredLookupIsHashed(t, store.DB(), "device_codes", "user_code", "RAW-USER")
	mustLookup(t, store.Approve(ctx, "RAW-USER", "u", "password", nil))
	_, err = store.ConsumeIfApproved(ctx, "raw-device-code")
	mustLookup(t, err)
}

func testPARLookupHMAC(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.NewPARStore(filepath.Join(t.TempDir(), "par.db"))
	mustLookup(t, err)
	defer func() { _ = store.Close() }()
	store.SetLookupHMACKeys(lookupKeyCurrent)
	raw, err := store.Issue(ctx, &oauth.PARRequest{
		ClientID: "c", ExpiresAt: time.Now().Add(time.Minute),
	})
	mustLookup(t, err)
	assertStoredLookupIsHashed(t, store.DB(), "par_requests", "request_uri", raw)
	_, err = store.Consume(ctx, raw)
	mustLookup(t, err)
}

func TestOpaqueLookupHMACReadsPreviousKeyAndLegacyPlaintext(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.NewRefreshTokenStore(filepath.Join(t.TempDir(), "rotation.db"))
	mustLookup(t, err)
	defer func() { _ = store.Close() }()
	info := func() *oauth.RefreshToken {
		return &oauth.RefreshToken{UserID: "u", ClientID: "c", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	}
	store.SetLookupHMACKeys(lookupKeyPrevious)
	mustLookup(t, store.Issue(ctx, "old-key-token", info()))
	store.SetLookupHMACKeys(lookupKeyCurrent, lookupKeyPrevious)
	_, err = store.Consume(ctx, "old-key-token")
	mustLookup(t, err)

	store.SetLookupHMACKeys()
	mustLookup(t, store.Issue(ctx, "legacy-token", info()))
	store.SetLookupHMACKeys(lookupKeyCurrent, lookupKeyPrevious)
	_, err = store.Consume(ctx, "legacy-token")
	mustLookup(t, err)
}

func assertStoredLookupIsHashed(t *testing.T, db interface {
	QueryRow(query string, args ...any) *sql.Row
}, table, column, raw string) {
	t.Helper()
	var stored string
	mustLookup(t, db.QueryRow("SELECT "+column+" FROM "+table+" LIMIT 1").Scan(&stored))
	if stored == raw || !strings.HasPrefix(stored, "h1:") {
		t.Fatalf("%s.%s stored %q; want an h1 HMAC lookup key", table, column, stored)
	}
}

func mustLookup(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
