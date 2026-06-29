package sqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"

	_ "modernc.org/sqlite"
)

// pinger is the shared shape every store exposes for /readyz wiring and the
// storage-health schema reporter. Constructing each store against ONE shared
// *sql.DB exercises the per-namespace migration path plus the DB()/Ping()
// boilerplate uniformly — these helpers are otherwise untouched by the
// behavioural tests.
type pinger interface {
	DB() *sql.DB
	Ping(context.Context) error
}

// newSharedDB opens a temp-file DB so several WithDB stores can share one
// connection pool the way a single-DSN production deployment does.
func newSharedDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "shared.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestWithDBConstructors_ShareOnePoolAndExposeHealth constructs every
// *WithDB store against the SAME *sql.DB (the production single-DSN shape),
// then asserts each exposes a live DB() handle and a healthy Ping. This
// covers the NewXxxWithDB / DB() / Ping() boilerplate across the package in
// one place.
func TestWithDBConstructors_ShareOnePoolAndExposeHealth(t *testing.T) {
	t.Parallel()
	db := newSharedDB(t)
	ctx := context.Background()

	// Error-free constructors.
	stores := []pinger{
		sqlite.NewAuthCodeStoreWithDB(db),
		sqlite.NewDeviceCodeStoreWithDB(db),
		sqlite.NewRefreshTokenStoreWithDB(db),
		sqlite.NewClientStoreWithDB(db),
		sqlite.NewUserProviderWithDB(db),
		sqlite.NewRevocationStoreWithDB(db),
	}

	// Constructors that return (store, error).
	type ctor struct {
		name string
		new  func(*sql.DB) (pinger, error)
	}
	ctors := []ctor{
		{"totp_enrollment", func(d *sql.DB) (pinger, error) { return sqlite.NewTOTPEnrollmentStoreWithDB(d) }},
		{"device_secrets", func(d *sql.DB) (pinger, error) { return sqlite.NewDeviceSecretStoreWithDB(d) }},
		{"mfa_challenges", func(d *sql.DB) (pinger, error) { return sqlite.NewMFAChallengeStoreWithDB(d) }},
		{"email_change", func(d *sql.DB) (pinger, error) { return sqlite.NewEmailChangeStoreWithDB(d) }},
		{"invitation", func(d *sql.DB) (pinger, error) { return sqlite.NewInvitationStoreWithDB(d) }},
		{"ip_failure", func(d *sql.DB) (pinger, error) { return sqlite.NewIPFailureCounterWithDB(d) }},
		{"consent", func(d *sql.DB) (pinger, error) { return sqlite.NewConsentStoreWithDB(d) }},
		{"tenant_user", func(d *sql.DB) (pinger, error) { return sqlite.NewTenantUserStoreWithDB(d) }},
		{"pairwise", func(d *sql.DB) (pinger, error) { return sqlite.NewPairwiseSubjectStoreWithDB(d) }},
		{"account_lockout", func(d *sql.DB) (pinger, error) { return sqlite.NewAccountLockoutWithDB(d) }},
		{"jti_replay", func(d *sql.DB) (pinger, error) { return sqlite.NewJTIReplayStoreWithDB(d) }},
		{"ciba", func(d *sql.DB) (pinger, error) { return sqlite.NewCIBAStoreWithDB(d) }},
		{"password_credentials", func(d *sql.DB) (pinger, error) { return sqlite.NewPasswordCredentialStoreWithDB(d) }},
		{"push_approvals", func(d *sql.DB) (pinger, error) { return sqlite.NewPushApprovalStoreWithDB(d) }},
		{"password_reset", func(d *sql.DB) (pinger, error) { return sqlite.NewPasswordResetStoreWithDB(d) }},
		{"recent_login", func(d *sql.DB) (pinger, error) { return sqlite.NewRecentLoginStoreWithDB(d) }},
		{"subject_client_index", func(d *sql.DB) (pinger, error) { return sqlite.NewSubjectClientIndexWithDB(d) }},
		{"par", func(d *sql.DB) (pinger, error) { return sqlite.NewPARStoreWithDB(d) }},
		{"sessions", func(d *sql.DB) (pinger, error) { return sqlite.NewSessionManagerWithDB(d, time.Hour) }},
	}
	for _, c := range ctors {
		s, err := c.new(db)
		if err != nil {
			t.Fatalf("%s WithDB: %v", c.name, err)
		}
		stores = append(stores, s)
	}

	for i, s := range stores {
		if s.DB() != db {
			t.Errorf("store #%d DB() did not return the shared handle", i)
		}
		if err := s.Ping(ctx); err != nil {
			t.Errorf("store #%d Ping: %v", i, err)
		}
	}
}

// TestOpenDSNConstructors_BadPathReturnError points every open-dsn
// constructor at an unopenable file (parent directory does not exist) so the
// ping/migrate failure branch — which Closes the half-open handle and wraps
// the error — is exercised for each. Without this only the happy path runs.
func TestOpenDSNConstructors_BadPathReturnError(t *testing.T) {
	t.Parallel()
	const bad = "file:/no_such_dir_for_sqlite_tests/x/store.db"
	type erring struct {
		name string
		open func() error
	}
	all := []erring{
		{"revocations", func() error { _, e := sqlite.NewRevocationStore(bad); return e }},
		{"account_lockout", func() error { _, e := sqlite.NewAccountLockout(bad); return e }},
		{"device_secrets", func() error { _, e := sqlite.NewDeviceSecretStore(bad); return e }},
		{"refresh_tokens", func() error { _, e := sqlite.NewRefreshTokenStore(bad); return e }},
		{"auth_codes", func() error { _, e := sqlite.NewAuthCodeStore(bad); return e }},
		{"consent", func() error { _, e := sqlite.NewConsentStore(bad); return e }},
		{"ip_failure", func() error { _, e := sqlite.NewIPFailureCounter(bad); return e }},
		{"email_change", func() error { _, e := sqlite.NewEmailChangeStore(bad); return e }},
		{"password_reset", func() error { _, e := sqlite.NewPasswordResetStore(bad); return e }},
		{"pairwise", func() error { _, e := sqlite.NewPairwiseSubjectStore(bad); return e }},
		{"push_approvals", func() error { _, e := sqlite.NewPushApprovalStore(bad); return e }},
		{"invitation", func() error { _, e := sqlite.NewInvitationStore(bad); return e }},
		{"clients", func() error { _, e := sqlite.NewClientStore(bad); return e }},
		{"device_codes", func() error { _, e := sqlite.NewDeviceCodeStore(bad); return e }},
		{"ciba", func() error { _, e := sqlite.NewCIBAStore(bad); return e }},
		{"jti_replay", func() error { _, e := sqlite.NewJTIReplayStore(bad); return e }},
		{"mfa_challenges", func() error { _, e := sqlite.NewMFAChallengeStore(bad); return e }},
		{"totp_enrollment", func() error { _, e := sqlite.NewTOTPEnrollmentStore(bad); return e }},
		{"par", func() error { _, e := sqlite.NewPARStore(bad); return e }},
		{"tenant_user", func() error { _, e := sqlite.NewTenantUserStore(bad); return e }},
		{"password_credentials", func() error { _, e := sqlite.NewPasswordCredentialStore(bad); return e }},
		{"recent_login", func() error { _, e := sqlite.NewRecentLoginStore(bad); return e }},
		{"subject_client_index", func() error { _, e := sqlite.NewSubjectClientIndex(bad); return e }},
		{"users", func() error { _, e := sqlite.NewUserProvider(bad); return e }},
		{"sessions", func() error { _, e := sqlite.NewSessionManager(bad, time.Hour); return e }},
	}
	for _, c := range all {
		if err := c.open(); err == nil {
			t.Errorf("%s: bad path returned nil error", c.name)
		}
	}
}

// TestWithDBConstructors_ClosedDBMigrateError feeds an already-closed
// *sql.DB to every (store, error)-returning WithDB constructor so the
// migrate-failure branch — the one the shared-pool happy path never takes —
// is exercised for each.
func TestWithDBConstructors_ClosedDBMigrateError(t *testing.T) {
	t.Parallel()
	closed := func(t *testing.T) *sql.DB {
		db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "closed.db"))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		_ = db.Close()
		return db
	}
	type erring struct {
		name string
		new  func(*sql.DB) error
	}
	all := []erring{
		{"totp_enrollment", func(d *sql.DB) error { _, e := sqlite.NewTOTPEnrollmentStoreWithDB(d); return e }},
		{"device_secrets", func(d *sql.DB) error { _, e := sqlite.NewDeviceSecretStoreWithDB(d); return e }},
		{"mfa_challenges", func(d *sql.DB) error { _, e := sqlite.NewMFAChallengeStoreWithDB(d); return e }},
		{"email_change", func(d *sql.DB) error { _, e := sqlite.NewEmailChangeStoreWithDB(d); return e }},
		{"invitation", func(d *sql.DB) error { _, e := sqlite.NewInvitationStoreWithDB(d); return e }},
		{"ip_failure", func(d *sql.DB) error { _, e := sqlite.NewIPFailureCounterWithDB(d); return e }},
		{"consent", func(d *sql.DB) error { _, e := sqlite.NewConsentStoreWithDB(d); return e }},
		{"tenant_user", func(d *sql.DB) error { _, e := sqlite.NewTenantUserStoreWithDB(d); return e }},
		{"pairwise", func(d *sql.DB) error { _, e := sqlite.NewPairwiseSubjectStoreWithDB(d); return e }},
		{"account_lockout", func(d *sql.DB) error { _, e := sqlite.NewAccountLockoutWithDB(d); return e }},
		{"jti_replay", func(d *sql.DB) error { _, e := sqlite.NewJTIReplayStoreWithDB(d); return e }},
		{"ciba", func(d *sql.DB) error { _, e := sqlite.NewCIBAStoreWithDB(d); return e }},
		{"password_credentials", func(d *sql.DB) error { _, e := sqlite.NewPasswordCredentialStoreWithDB(d); return e }},
		{"push_approvals", func(d *sql.DB) error { _, e := sqlite.NewPushApprovalStoreWithDB(d); return e }},
		{"password_reset", func(d *sql.DB) error { _, e := sqlite.NewPasswordResetStoreWithDB(d); return e }},
		{"recent_login", func(d *sql.DB) error { _, e := sqlite.NewRecentLoginStoreWithDB(d); return e }},
		{"subject_client_index", func(d *sql.DB) error { _, e := sqlite.NewSubjectClientIndexWithDB(d); return e }},
		{"par", func(d *sql.DB) error { _, e := sqlite.NewPARStoreWithDB(d); return e }},
		{"sessions", func(d *sql.DB) error { _, e := sqlite.NewSessionManagerWithDB(d, time.Hour); return e }},
	}
	for _, c := range all {
		if err := c.new(closed(t)); err == nil {
			t.Errorf("%s WithDB(closed): want migrate error, got nil", c.name)
		}
	}
}

// TestStandaloneStores_PingAndCloseLifecycle drives the open-dsn
// constructors plus the Close/Ping-after-close error path that the shared-DB
// test cannot (closing a shared handle would break its siblings).
func TestStandaloneStores_PingAndCloseLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	type closer interface {
		pinger
		Close() error
	}
	cases := []struct {
		name string
		open func(dsn string) (closer, error)
	}{
		{"revocations", func(dsn string) (closer, error) { return sqlite.NewRevocationStore(dsn) }},
		{"account_lockout", func(dsn string) (closer, error) { return sqlite.NewAccountLockout(dsn) }},
		{"device_secrets", func(dsn string) (closer, error) { return sqlite.NewDeviceSecretStore(dsn) }},
		{"refresh_tokens", func(dsn string) (closer, error) { return sqlite.NewRefreshTokenStore(dsn) }},
		{"auth_codes", func(dsn string) (closer, error) { return sqlite.NewAuthCodeStore(dsn) }},
		{"consent", func(dsn string) (closer, error) { return sqlite.NewConsentStore(dsn) }},
		{"ip_failure", func(dsn string) (closer, error) { return sqlite.NewIPFailureCounter(dsn) }},
		{"email_change", func(dsn string) (closer, error) { return sqlite.NewEmailChangeStore(dsn) }},
		{"password_reset", func(dsn string) (closer, error) { return sqlite.NewPasswordResetStore(dsn) }},
		{"pairwise", func(dsn string) (closer, error) { return sqlite.NewPairwiseSubjectStore(dsn) }},
		{"push_approvals", func(dsn string) (closer, error) { return sqlite.NewPushApprovalStore(dsn) }},
		{"invitation", func(dsn string) (closer, error) { return sqlite.NewInvitationStore(dsn) }},
		{"clients", func(dsn string) (closer, error) { return sqlite.NewClientStore(dsn) }},
		{"device_codes", func(dsn string) (closer, error) { return sqlite.NewDeviceCodeStore(dsn) }},
		{"ciba", func(dsn string) (closer, error) { return sqlite.NewCIBAStore(dsn) }},
		{"jti_replay", func(dsn string) (closer, error) { return sqlite.NewJTIReplayStore(dsn) }},
		{"mfa_challenges", func(dsn string) (closer, error) { return sqlite.NewMFAChallengeStore(dsn) }},
		{"totp_enrollment", func(dsn string) (closer, error) { return sqlite.NewTOTPEnrollmentStore(dsn) }},
		{"par", func(dsn string) (closer, error) { return sqlite.NewPARStore(dsn) }},
		{"tenant_user", func(dsn string) (closer, error) { return sqlite.NewTenantUserStore(dsn) }},
		{"password_credentials", func(dsn string) (closer, error) { return sqlite.NewPasswordCredentialStore(dsn) }},
		{"recent_login", func(dsn string) (closer, error) { return sqlite.NewRecentLoginStore(dsn) }},
		{"subject_client_index", func(dsn string) (closer, error) { return sqlite.NewSubjectClientIndex(dsn) }},
		{"users", func(dsn string) (closer, error) { return sqlite.NewUserProvider(dsn) }},
		{"sessions", func(dsn string) (closer, error) { return sqlite.NewSessionManager(dsn, time.Hour) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dsn := "file:" + filepath.Join(t.TempDir(), c.name+".db")
			s, err := c.open(dsn)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if err := s.Ping(ctx); err != nil {
				t.Fatalf("Ping (live): %v", err)
			}
			if s.DB() == nil {
				t.Fatalf("DB() nil on live store")
			}
			if err := s.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			// Idempotent Close.
			if err := s.Close(); err != nil {
				t.Errorf("second Close: %v", err)
			}
			// Ping after Close reports the closed-store error (not a panic).
			if err := s.Ping(ctx); err == nil {
				t.Errorf("Ping after Close: want error, got nil")
			}
		})
	}
}
