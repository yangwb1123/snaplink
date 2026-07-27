package redis

import (
	"context"
	"errors"
	"fmt"
	"strings"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/domains/identitylink"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
	"golang.org/x/crypto/bcrypt"
)

// Key layout. One key per user holds the bcrypt hash string.
const pwcredKeyPrefix = "sso:pwcred:" // sso:pwcred:<userID> -> bcrypt hash

// PasswordCredentialStore is the Redis-backed [sso.PasswordCredentialStore].
// This is the scale peer for the self-service password-change flow AND for a
// password authenticator's VerifyPassword, which runs on the hot path of every
// password login — a multi-replica fleet shares one credential store so a
// password set on replica A verifies on replica B without a sticky session.
//
// Passwords are bcrypt-hashed at rest. The dummy hash is generated ONCE in the
// constructor so the unknown-user path in VerifyPassword spends a comparable
// amount of time as a real compare, matching the memory + SQLite peers'
// anti-enumeration timing parity.
type PasswordCredentialStore struct {
	rdb   goredis.Cmdable
	dummy []byte // cost-matched dummy for unknown-user timing parity
}

// NewPasswordCredentialStore builds a PasswordCredentialStore over an existing
// go-redis client (or cluster client — any goredis.Cmdable). The caller owns
// the client lifecycle. The dummy hash is generated once here so VerifyPassword
// never pays a fresh GenerateFromPassword on the unknown-user path.
func NewPasswordCredentialStore(rdb goredis.Cmdable) *PasswordCredentialStore {
	dummy, _ := bcrypt.GenerateFromPassword([]byte("dummy-for-timing-equalization-only"), bcrypt.DefaultCost)
	return &PasswordCredentialStore{rdb: rdb, dummy: dummy}
}

// Ping reports Redis connection health for [sso.WithReadyCheck] wiring.
func (s *PasswordCredentialStore) Ping(ctx context.Context) error {
	return s.rdb.Ping(ctx).Err()
}

func pwcredKey(userID string) string { return pwcredKeyPrefix + userID }

// SetPassword stores newPassword for userID, hashing it at rest. SET overwrites
// any prior hash so the credential is created when absent and replaced
// otherwise (matching the memory peer's map-write semantics).
func (s *PasswordCredentialStore) SetPassword(ctx context.Context, userID, newPassword string) error {
	if userID == "" {
		return core.ErrPasswordMismatch
	}
	h, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := s.rdb.Set(ctx, pwcredKey(userID), string(h), 0).Err(); err != nil {
		return fmt.Errorf("redis: set password_credential: %w", err)
	}
	return nil
}

// SetPasswordHash seeds a PRE-COMPUTED bcrypt hash for userID (satisfies
// sso.PasswordHashImporter) — used to import existing users (e.g. YAML seeds)
// into the store without their plaintext. Rejects a non-bcrypt value so a
// plaintext can never be stored masquerading as a hash. Same SET overwrite as
// SetPassword.
func (s *PasswordCredentialStore) SetPasswordHash(ctx context.Context, userID, bcryptHash string) error {
	if userID == "" {
		return core.ErrPasswordMismatch
	}
	if !strings.HasPrefix(bcryptHash, "$2") {
		return errors.New("redis: SetPasswordHash requires a bcrypt hash")
	}
	if err := s.rdb.Set(ctx, pwcredKey(userID), bcryptHash, 0).Err(); err != nil {
		return fmt.Errorf("redis: set password_credential hash: %w", err)
	}
	return nil
}

// VerifyPassword returns nil when plaintext matches the stored hash for userID,
// and core.ErrPasswordMismatch on mismatch OR unknown user. The unknown path
// runs a cost-matched dummy compare so its timing is indistinguishable from a
// real mismatch (anti-enumeration) before collapsing to the same error — the
// caller MUST NOT distinguish.
func (s *PasswordCredentialStore) VerifyPassword(ctx context.Context, userID, plaintext string) error {
	hash, err := s.rdb.Get(ctx, pwcredKey(userID)).Result()
	if errors.Is(err, goredis.Nil) {
		// Unknown user: compare against the dummy so timing matches a real
		// mismatch, then collapse to the same error (anti-enumeration).
		_ = bcrypt.CompareHashAndPassword(s.dummy, []byte(plaintext))
		return core.ErrPasswordMismatch
	}
	if err != nil {
		return fmt.Errorf("redis: get password_credential: %w", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) != nil {
		return core.ErrPasswordMismatch
	}
	return nil
}

// HasPassword implements identitylink.PasswordPresenceChecker: reports
// whether userID has a stored credential key, WITHOUT the timing-
// equalization VerifyPassword performs. Safe to expose directly — this is a
// governance/guard query (the self-service identity-unlink "don't lock
// yourself out" check) on the CALLER's OWN authenticated subject, not a login
// path, so there is no anti-enumeration concern to preserve. Mirrors the
// memory/SQLite/Postgres peers' implementation — before this method existed,
// a deployment using this backend for password credentials always read as
// PasswordPresenceChecker-unimplemented, so the self-service unlink guard
// fell CLOSED (assumed no password) even for a user who had one,
// over-conservatively blocking their last identity-unlink.
func (s *PasswordCredentialStore) HasPassword(ctx context.Context, userID string) (bool, error) {
	n, err := s.rdb.Exists(ctx, pwcredKey(userID)).Result()
	if err != nil {
		return false, fmt.Errorf("redis: has password_credential: %w", err)
	}
	return n > 0, nil
}

var (
	_ sso.PasswordCredentialStore          = (*PasswordCredentialStore)(nil)
	_ sso.PasswordHashImporter             = (*PasswordCredentialStore)(nil)
	_ identitylink.PasswordPresenceChecker = (*PasswordCredentialStore)(nil)
)
