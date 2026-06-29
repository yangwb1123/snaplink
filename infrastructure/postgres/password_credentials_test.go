package postgres

import (
	"context"
	"testing"

	"github.com/snaplink/sso/shared/core"
	"golang.org/x/crypto/bcrypt"
)

func freshPasswordCredentialStore(t *testing.T) *PasswordCredentialStore {
	t.Helper()
	s, err := NewPasswordCredentialStore(testConfig(t))
	if err != nil {
		t.Fatalf("NewPasswordCredentialStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.db.ExecContext(context.Background(), "TRUNCATE password_credentials"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return s
}

func TestPasswordCredentials_SetVerify(t *testing.T) {
	t.Parallel()
	s := freshPasswordCredentialStore(t)
	ctx := context.Background()

	// Unknown user: VerifyPassword must collapse to ErrPasswordMismatch (the
	// caller MUST NOT distinguish missing from wrong).
	if err := s.VerifyPassword(ctx, "u1", "hunter2"); err != core.ErrPasswordMismatch {
		t.Fatalf("unknown-user VerifyPassword err = %v, want ErrPasswordMismatch", err)
	}

	if err := s.SetPassword(ctx, "u1", "hunter2"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := s.VerifyPassword(ctx, "u1", "hunter2"); err != nil {
		t.Fatalf("VerifyPassword (correct) = %v, want nil", err)
	}
	// Wrong password for a known user → same sentinel as unknown user.
	if err := s.VerifyPassword(ctx, "u1", "wrong"); err != core.ErrPasswordMismatch {
		t.Fatalf("VerifyPassword (wrong) = %v, want ErrPasswordMismatch", err)
	}

	// Empty userID is rejected with the same sentinel (never inserts a row).
	if err := s.SetPassword(ctx, "", "x"); err != core.ErrPasswordMismatch {
		t.Fatalf("SetPassword(empty userID) = %v, want ErrPasswordMismatch", err)
	}
}

func TestPasswordCredentials_UpsertReplacesInFull(t *testing.T) {
	t.Parallel()
	s := freshPasswordCredentialStore(t)
	ctx := context.Background()

	if err := s.SetPassword(ctx, "u1", "first"); err != nil {
		t.Fatalf("SetPassword first: %v", err)
	}
	// Re-setting the password replaces the stored hash in full: the old
	// password must no longer verify, the new one must.
	if err := s.SetPassword(ctx, "u1", "second"); err != nil {
		t.Fatalf("SetPassword second: %v", err)
	}
	if err := s.VerifyPassword(ctx, "u1", "first"); err != core.ErrPasswordMismatch {
		t.Fatalf("old password still verifies after upsert: %v", err)
	}
	if err := s.VerifyPassword(ctx, "u1", "second"); err != nil {
		t.Fatalf("new password does not verify after upsert: %v", err)
	}

	// Exactly one row for the user after two SetPassword calls (PRIMARY KEY
	// upsert, not insert).
	var count int
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM password_credentials WHERE user_id = $1", "u1").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("row count after upsert = %d, want 1", count)
	}
}

func TestPasswordCredentials_SetPasswordHashImporter(t *testing.T) {
	t.Parallel()
	s := freshPasswordCredentialStore(t)
	ctx := context.Background()

	// Pre-compute a bcrypt hash and import it without the plaintext.
	hash, err := bcrypt.GenerateFromPassword([]byte("imported-secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	if err := s.SetPasswordHash(ctx, "u1", string(hash)); err != nil {
		t.Fatalf("SetPasswordHash: %v", err)
	}
	if err := s.VerifyPassword(ctx, "u1", "imported-secret"); err != nil {
		t.Fatalf("VerifyPassword after import = %v, want nil", err)
	}
	if err := s.VerifyPassword(ctx, "u1", "wrong"); err != core.ErrPasswordMismatch {
		t.Fatalf("VerifyPassword (wrong, imported) = %v, want ErrPasswordMismatch", err)
	}

	// A non-bcrypt value MUST be rejected so a plaintext can never be stored
	// masquerading as a hash.
	if err := s.SetPasswordHash(ctx, "u2", "not-a-bcrypt-hash"); err == nil {
		t.Fatal("SetPasswordHash accepted a non-bcrypt value, want error")
	}
	// The rejected import must not have created a credential.
	if err := s.VerifyPassword(ctx, "u2", "not-a-bcrypt-hash"); err != core.ErrPasswordMismatch {
		t.Fatalf("rejected import left a usable credential: %v", err)
	}

	// Empty userID is rejected with the sentinel.
	if err := s.SetPasswordHash(ctx, "", string(hash)); err != core.ErrPasswordMismatch {
		t.Fatalf("SetPasswordHash(empty userID) = %v, want ErrPasswordMismatch", err)
	}
}

func TestPasswordCredentials_UpdatedAtNanoRoundTrip(t *testing.T) {
	t.Parallel()
	s := freshPasswordCredentialStore(t)
	ctx := context.Background()

	if err := s.SetPassword(ctx, "u1", "hunter2"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	// updated_at is a BIGINT of Unix nanoseconds — assert it survived the
	// round-trip with sub-second precision (a timestamptz column would truncate
	// or drift; BIGINT preserves the exact int64).
	var ns int64
	if err := s.db.QueryRowContext(ctx,
		"SELECT updated_at FROM password_credentials WHERE user_id = $1", "u1").Scan(&ns); err != nil {
		t.Fatalf("read updated_at: %v", err)
	}
	if ns <= 0 {
		t.Fatalf("updated_at = %d, want a positive Unix-nano value", ns)
	}
	if ns%1_000_000_000 == 0 {
		// Practically certain to be non-zero sub-second for time.Now().UnixNano();
		// a zero remainder would suggest second-granularity truncation.
		t.Fatalf("updated_at = %d has no sub-second component (precision lost?)", ns)
	}
}

func TestPasswordCredentials_PingAndDB(t *testing.T) {
	t.Parallel()
	s := freshPasswordCredentialStore(t)
	ctx := context.Background()

	if err := s.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if s.DB() == nil {
		t.Fatal("DB() returned nil on an open store")
	}

	// Close is idempotent; Ping after Close reports closed (no panic).
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close (idempotent): %v", err)
	}
	if err := s.Ping(ctx); err == nil {
		t.Fatal("Ping after Close = nil, want closed error")
	}
}
