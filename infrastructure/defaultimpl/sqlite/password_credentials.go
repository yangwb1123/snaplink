package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/domains/identitylink"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security/passwordhash"
	"golang.org/x/crypto/bcrypt"
)

// passwordCredentialsSchema stores one bcrypt hash per user for the
// self-service password-change flow (POST /me/password). PRIMARY KEY on
// user_id makes SetPassword an atomic upsert; updated_at is Unix
// nanoseconds per the repo timestamp convention.
const passwordCredentialsSchema = `
CREATE TABLE IF NOT EXISTS password_credentials (
    user_id    TEXT    PRIMARY KEY,
    hash       TEXT    NOT NULL,
    updated_at INTEGER
);
`

// PasswordCredentialStore is the SQLite-backed implementation of
// [core.PasswordCredentialStore]. Replaces MemoryPasswordCredentialStore
// for multi-replica deployments — a password set on replica A is durable
// in the shared file so replica B (and a restart) verifies against it too.
//
// Passwords are bcrypt-hashed at rest (bcrypt.DefaultCost). The dummy hash
// is generated at construction so the unknown-user path in VerifyPassword
// spends a comparable amount of time as a real compare, matching the memory
// peer's anti-enumeration timing parity. When a higher-cost hash is imported
// via SetPasswordHash the dummy is re-minted to that cost (raiseDummyCost) so
// the miss path stays comparable to the SLOWEST stored hash — a cost-10 dummy
// against a cost-12 imported hash would otherwise be a timing oracle. NOTE:
// the dummy cost is process-local and resets to DefaultCost on restart; cmd
// re-imports seeded hashes at boot, which re-raises it.
type PasswordCredentialStore struct {
	db        *sql.DB
	mu        sync.RWMutex
	dummy     []byte // cost-matched dummy for unknown-user timing parity
	dummyCost int    // bcrypt cost the current dummy was minted at
}

// newDummyHash builds the cost-matched dummy used on the unknown-user
// path. Generated once so VerifyPassword never pays a fresh GenerateFromPassword.
func newDummyHash() []byte {
	dummy, _ := passwordhash.DummyHash(passwordhash.DefaultCost)
	return dummy
}

// raiseDummyCost re-mints the timing-equalization dummy at cost when cost
// exceeds the current dummy cost, keeping the unknown-user path comparable to
// the slowest stored hash. A GenerateFromPassword failure leaves the existing
// dummy in place (best-effort timing parity).
func (s *PasswordCredentialStore) raiseDummyCost(cost int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cost <= s.dummyCost || cost > bcrypt.MaxCost {
		return
	}
	if d, err := bcrypt.GenerateFromPassword([]byte("dummy-for-timing-equalization-only"), cost); err == nil {
		s.dummy = d
		s.dummyCost = cost
	}
}

// NewPasswordCredentialStore opens dsn, migrates the schema, and returns
// the store. Caller owns Close().
func NewPasswordCredentialStore(dsn string) (*PasswordCredentialStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := ensureSchema(db, "password_credentials", passwordCredentialsSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate password_credentials: %w", err)
	}
	return &PasswordCredentialStore{db: db, dummy: newDummyHash(), dummyCost: passwordhash.DefaultCost}, nil
}

// NewPasswordCredentialStoreWithDB wraps an existing *sql.DB (shared-pool
// deployments). Caller owns the connection lifecycle.
func NewPasswordCredentialStoreWithDB(db *sql.DB) (*PasswordCredentialStore, error) {
	if err := ensureSchema(db, "password_credentials", passwordCredentialsSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate password_credentials: %w", err)
	}
	return &PasswordCredentialStore{db: db, dummy: newDummyHash(), dummyCost: passwordhash.DefaultCost}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *PasswordCredentialStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for an operator-facing schema
// reporter (sso.WithStorageHealth via migrate.Status). Nil after Close;
// callers MUST NOT close it.
func (s *PasswordCredentialStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck] wiring.
func (s *PasswordCredentialStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: password credential store closed")
	}
	return s.db.PingContext(ctx)
}

// SetPassword stores newPassword for userID, hashing it at rest. The
// PRIMARY KEY upsert creates the credential when absent and replaces it
// otherwise (matching the memory peer's map-write semantics).
func (s *PasswordCredentialStore) SetPassword(ctx context.Context, userID, newPassword string) error {
	if userID == "" {
		return core.ErrPasswordMismatch
	}
	h, err := passwordhash.Hash(newPassword, passwordhash.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO password_credentials (user_id, hash, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET hash = excluded.hash, updated_at = excluded.updated_at`,
		userID, string(h), time.Now().UnixNano())
	if err != nil {
		return fmt.Errorf("sqlite: upsert password_credential: %w", err)
	}
	return nil
}

// SetPasswordHash seeds a PRE-COMPUTED bcrypt hash for userID (satisfies
// sso.PasswordHashImporter) — used to import existing users (e.g. YAML seeds)
// into the store without their plaintext. Rejects a non-bcrypt value so a
// plaintext can never be stored masquerading as a hash. Same PRIMARY KEY
// upsert as SetPassword.
func (s *PasswordCredentialStore) SetPasswordHash(ctx context.Context, userID, bcryptHash string) error {
	if userID == "" {
		return core.ErrPasswordMismatch
	}
	if !passwordhash.IsBcrypt(bcryptHash) {
		return errors.New("sqlite: SetPasswordHash requires a bcrypt hash")
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO password_credentials (user_id, hash, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET hash = excluded.hash, updated_at = excluded.updated_at`,
		userID, bcryptHash, time.Now().UnixNano())
	if err != nil {
		return fmt.Errorf("sqlite: upsert password_credential hash: %w", err)
	}
	// Keep the miss-path dummy as slow as the slowest imported hash so an
	// unknown-username login isn't measurably faster (enumeration timing
	// oracle). A malformed hash yields cost 0, a no-op against the dummy.
	if cost, ok := passwordhash.Cost(bcryptHash); ok {
		s.raiseDummyCost(cost)
	}
	return nil
}

// VerifyPassword returns nil when plaintext matches the stored hash for
// userID, and core.ErrPasswordMismatch on mismatch OR unknown user. The
// unknown path runs a cost-matched dummy compare so its timing is
// indistinguishable from a real mismatch (anti-enumeration) before
// collapsing to the same error — the caller MUST NOT distinguish.
func (s *PasswordCredentialStore) VerifyPassword(ctx context.Context, userID, plaintext string) error {
	var hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT hash FROM password_credentials WHERE user_id = ?`, userID).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		// Unknown user: compare against the dummy so timing matches a real
		// mismatch, then collapse to the same error (anti-enumeration).
		s.mu.RLock()
		dummy := s.dummy
		s.mu.RUnlock()
		_ = bcrypt.CompareHashAndPassword(dummy, []byte(plaintext))
		return core.ErrPasswordMismatch
	}
	if err != nil {
		return fmt.Errorf("sqlite: get password_credential: %w", err)
	}
	if !passwordhash.Verify(hash, plaintext) {
		return core.ErrPasswordMismatch
	}
	return nil
}

// PasswordChangedAt implements sso.PasswordAgeReader: returns the time
// userID's current credential was set, read from the SAME updated_at column
// SetPassword/SetPasswordHash already stamp (Unix nanoseconds) — no schema
// change needed, no migration/MaxVersion bump. Returns an error for an
// unknown user or a NULL updated_at (a row written before this column existed
// in some hand-rolled deployment) so the login-time expiry gate
// (interfaces/sso rejectExpiredPassword) fails open rather than misreading a
// missing timestamp as "always expired".
func (s *PasswordCredentialStore) PasswordChangedAt(ctx context.Context, userID string) (time.Time, error) {
	var ns sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT updated_at FROM password_credentials WHERE user_id = ?`, userID).Scan(&ns)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, fmt.Errorf("sqlite: no password_credential for user")
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("sqlite: get password_credential updated_at: %w", err)
	}
	if !ns.Valid {
		return time.Time{}, fmt.Errorf("sqlite: password_credential has no updated_at for user")
	}
	return time.Unix(0, ns.Int64), nil
}

// DeletePassword implements sso.PasswordCredentialDeleter: removes userID's
// stored credential row, if any — used by the admin user-CRUD delete path so
// a deleted user's credential doesn't linger as an orphaned, unreachable hash.
// Idempotent: deleting a non-existent row is not an error.
func (s *PasswordCredentialStore) DeletePassword(ctx context.Context, userID string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM password_credentials WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("sqlite: delete password_credential: %w", err)
	}
	return nil
}

// HasPassword implements identitylink.PasswordPresenceChecker: reports
// whether userID has a stored credential row, WITHOUT the timing-
// equalization VerifyPassword performs. Safe to expose directly — this is a
// governance/guard query (the self-service identity-unlink "don't lock
// yourself out" check) on the CALLER's OWN authenticated subject, not a login
// path, so there is no anti-enumeration concern to preserve. Mirrors
// infrastructure/defaultimpl/memorystorecredential's implementation — before
// this method existed, a deployment using this (the pure-Go, no-CGO default)
// backend for password credentials always read as PasswordPresenceChecker-
// unimplemented, so the self-service unlink guard fell CLOSED (assumed no
// password) even for a user who had one, over-conservatively blocking their
// last identity-unlink.
func (s *PasswordCredentialStore) HasPassword(ctx context.Context, userID string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM password_credentials WHERE user_id = ?`, userID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sqlite: has password_credential: %w", err)
	}
	return true, nil
}

// NeedsRehash implements core.PasswordRehashNeeder: reports whether the
// stored hash is below the policy target (progressive upgrade on login).
func (s *PasswordCredentialStore) NeedsRehash(ctx context.Context, userID string) (bool, error) {
	var hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT hash FROM password_credentials WHERE user_id = ?`, userID).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sqlite: get password_credential: %w", err)
	}
	return passwordhash.NeedsRehash(hash, passwordhash.DefaultCost), nil
}

var (
	_ sso.PasswordCredentialStore          = (*PasswordCredentialStore)(nil)
	_ sso.PasswordHashImporter             = (*PasswordCredentialStore)(nil)
	_ sso.PasswordAgeReader                = (*PasswordCredentialStore)(nil)
	_ sso.PasswordCredentialDeleter        = (*PasswordCredentialStore)(nil)
	_ identitylink.PasswordPresenceChecker = (*PasswordCredentialStore)(nil)
)
