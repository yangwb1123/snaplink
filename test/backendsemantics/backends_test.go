// Package backendsemantics asserts that the memory and SQLite (pure-Go,
// temp-file) implementations of one storage SPI honor the SAME observable
// contract — sentinel errors included — so operators can switch backends
// without behavior drift. A driver-specific error (sql.ErrNoRows) leaking
// where an oauth.Err* / contract sentinel is required would silently break
// the oracle-leak collapse the handlers rely on; every negative assertion
// therefore checks BOTH errors.Is(err, sentinel) and !errors.Is(err,
// sql.ErrNoRows). Table-driven over real backend constructors — no mocks,
// per AGENTS.md.
package backendsemantics

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/security"
)

// sqliteDSN yields a per-test on-disk database under t.TempDir so every
// subtest run starts from an empty schema and leaves nothing behind.
func sqliteDSN(t *testing.T, name string) string {
	t.Helper()
	return "file:" + filepath.Join(t.TempDir(), name) + "?_journal=WAL&_pragma=busy_timeout(5000)"
}

func closeOnCleanup(t *testing.T, c interface{ Close() error }) {
	t.Helper()
	t.Cleanup(func() { _ = c.Close() })
}

// assertSentinel is the shared negative-path check: the store returned the
// contract sentinel and did NOT leak the driver's sql.ErrNoRows.
func assertSentinel(t *testing.T, err, sentinel error) {
	t.Helper()
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel %v", err, sentinel)
	}
	if errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("driver error sql.ErrNoRows leaked through: %v", err)
	}
}

// Backend constructor tables. Each entry builds a FRESH store; SQLite
// entries own their connection via t.Cleanup.

var authCodeBackends = []struct {
	name string
	make func(t *testing.T) oauth.AuthCodeStore
}{
	{"memory", func(t *testing.T) oauth.AuthCodeStore { return defaultimpl.NewMemoryAuthCodeStore() }},
	{"sqlite", func(t *testing.T) oauth.AuthCodeStore {
		s, err := sqlite.NewAuthCodeStore(sqliteDSN(t, "authcodes.db"))
		if err != nil {
			t.Fatalf("sqlite auth code store: %v", err)
		}
		closeOnCleanup(t, s)
		return s
	}},
}

var refreshBackends = []struct {
	name string
	make func(t *testing.T) oauth.RefreshTokenStore
}{
	{"memory", func(t *testing.T) oauth.RefreshTokenStore { return defaultimpl.NewMemoryRefreshTokenStore() }},
	{"sqlite", func(t *testing.T) oauth.RefreshTokenStore {
		s, err := sqlite.NewRefreshTokenStore(sqliteDSN(t, "refresh.db"))
		if err != nil {
			t.Fatalf("sqlite refresh token store: %v", err)
		}
		closeOnCleanup(t, s)
		return s
	}},
}

var jtiBackends = []struct {
	name string
	make func(t *testing.T) security.JTIReplayStore
}{
	{"memory", func(t *testing.T) security.JTIReplayStore { return defaultimpl.NewMemoryJTIReplayStore() }},
	{"sqlite", func(t *testing.T) security.JTIReplayStore {
		s, err := sqlite.NewJTIReplayStore(sqliteDSN(t, "jti.db"))
		if err != nil {
			t.Fatalf("sqlite jti replay store: %v", err)
		}
		closeOnCleanup(t, s)
		return s
	}},
}

var parBackends = []struct {
	name string
	make func(t *testing.T) oauth.PARStore
}{
	{"memory", func(t *testing.T) oauth.PARStore { return defaultimpl.NewMemoryPARStore() }},
	{"sqlite", func(t *testing.T) oauth.PARStore {
		s, err := sqlite.NewPARStore(sqliteDSN(t, "par.db"))
		if err != nil {
			t.Fatalf("sqlite par store: %v", err)
		}
		closeOnCleanup(t, s)
		return s
	}},
}

var deviceCodeBackends = []struct {
	name string
	make func(t *testing.T) oauth.DeviceCodeStore
}{
	{"memory", func(t *testing.T) oauth.DeviceCodeStore { return defaultimpl.NewMemoryDeviceCodeStore() }},
	{"sqlite", func(t *testing.T) oauth.DeviceCodeStore {
		s, err := sqlite.NewDeviceCodeStore(sqliteDSN(t, "device.db"))
		if err != nil {
			t.Fatalf("sqlite device code store: %v", err)
		}
		closeOnCleanup(t, s)
		return s
	}},
}
