package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/protocols/oauth"
)

const reaperTestInterval = 5 * time.Millisecond

func TestAuthCodeStoreReapsExpiredRows(t *testing.T) {
	t.Parallel()
	s, err := NewAuthCodeStore(reaperDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	err = s.Issue(context.Background(), "expired", &oauth.AuthCode{
		UserID: "u", ClientID: "c", ExpiresAt: time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.StartReaper(reaperTestInterval)
	awaitEmptyTable(t, s.db, "auth_codes")
}

func TestRefreshTokenStoreReapsExpiredRowsAndLedger(t *testing.T) {
	t.Parallel()
	s, err := NewRefreshTokenStore(reaperDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	err = s.Issue(context.Background(), "expired", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", FamilyID: "family",
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.StartReaper(reaperTestInterval)
	awaitEmptyTable(t, s.db, "refresh_tokens")
	awaitEmptyTable(t, s.db, "refresh_token_families")
}

func TestDeviceCodeStoreReapsExpiredRows(t *testing.T) {
	t.Parallel()
	s, err := NewDeviceCodeStore(reaperDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	err = s.Issue(context.Background(), &oauth.DeviceCode{
		DeviceCode: "device", UserCode: "user", ClientID: "c",
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.StartReaper(reaperTestInterval)
	awaitEmptyTable(t, s.db, "device_codes")
}

func TestPARStoreReapsExpiredRows(t *testing.T) {
	t.Parallel()
	s, err := NewPARStore(reaperDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	_, err = s.Issue(context.Background(), &oauth.PARRequest{
		ClientID: "c", ExpiresAt: time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.StartReaper(reaperTestInterval)
	awaitEmptyTable(t, s.db, "par_requests")
}

func reaperDSN(t *testing.T) string {
	return fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
}

func awaitEmptyTable(t *testing.T, db queryRower, table string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		var count int
		if err := db.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM `+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			return
		}
		time.Sleep(reaperTestInterval)
	}
	t.Fatalf("%s still contains expired rows", table)
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
