package authenticators

import (
	"context"
	"errors"
	"maps"

	"github.com/snaplink/sso"
	"golang.org/x/crypto/bcrypt"
)

// DefaultStoredHashDummyCost is the bcrypt cost of the dummy hash used to
// equalize timing on a miss when the operator does not pin one. It is set
// ABOVE bcrypt.DefaultCost (10) because the imported hashes this verifier
// serves are typically minted at a modern cost (12+) or are a non-bcrypt KDF;
// a cost-10 dummy would finish measurably faster than a real verify, leaking
// "this username is unknown" as a timing side channel. Operators whose
// imported bcrypt hashes use a specific cost SHOULD pin it via
// WithStoredHashDummyCost so the miss path matches the hit path. A non-bcrypt
// imported corpus (argon2id / PBKDF2) cannot be matched exactly across formats
// — the dummy is a bcrypt floor, narrowing but not eliminating the gap; the
// only complete fix there is to import at a uniform KDF.
const DefaultStoredHashDummyCost = 12

// Attribute keys under which a migration tool (cmd/sso-import) persists a user's
// imported credential hash on the User record. The verifier and the importer
// MUST agree on these keys — they are the seam that lets a user migrated from a
// legacy IdP authenticate without a forced password reset.
const (
	AttrPasswordHash       = "password_hash"
	AttrPasswordHashFormat = "password_hash_format"
)

// errStoredHashInvalid is the single failure response for every miss (unknown
// user, no stored hash, wrong password, unsupported format) — oracle-safe, the
// caller collapses it to one login failure.
var errStoredHashInvalid = errors.New("password: invalid credentials")

// StoredHashVerifier authenticates against a credential hash stored on the User
// record's Attributes (written by cmd/sso-import during a legacy-IdP migration).
// It reads AttrPasswordHash + AttrPasswordHashFormat and checks the plaintext
// with the multi-format VerifyHash, so users migrated with argon2id / PBKDF2
// hashes can sign in. Pair with LazyRehashVerifier (see StoredHashRehashHooks)
// to upgrade verified non-bcrypt hashes to bcrypt on first login.
//
// Without this verifier the import tool's output is inert: the server's other
// password verifiers are bcrypt-only and never read these attributes, so
// imported non-bcrypt users could not authenticate at all.
//
// Anti-enumeration: an unknown user (or one with no stored hash) still runs a
// dummy bcrypt compare so the unknown-user and wrong-password paths take
// comparable time, matching the password authenticator's enumeration contract.
type StoredHashVerifier struct {
	users     sso.UserProvider
	dummyHash PasswordHash
}

// StoredHashOption tunes a StoredHashVerifier at construction.
type StoredHashOption func(*storedHashConfig)

type storedHashConfig struct {
	dummyCost int
}

// WithStoredHashDummyCost pins the bcrypt cost of the miss-path dummy hash so
// it matches the cost of the deployment's imported bcrypt hashes — the
// unknown-user verify then takes comparable time to a real one, closing the
// enumeration timing oracle. A cost outside bcrypt's accepted range, or <=0,
// falls back to DefaultStoredHashDummyCost. Set this to the SAME cost the
// imported bcrypt corpus uses; for a non-bcrypt corpus leave it at the default
// (an exact cross-format match is infeasible — see DefaultStoredHashDummyCost).
func WithStoredHashDummyCost(cost int) StoredHashOption {
	return func(c *storedHashConfig) { c.dummyCost = cost }
}

// NewStoredHashVerifier returns a verifier that reads imported hashes from the
// UserProvider. The login username is looked up via GetByID — migration tools
// set the user ID to the login identifier (sanitized email / username).
func NewStoredHashVerifier(users sso.UserProvider, opts ...StoredHashOption) *StoredHashVerifier {
	cfg := storedHashConfig{dummyCost: DefaultStoredHashDummyCost}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.dummyCost < bcrypt.MinCost || cfg.dummyCost > bcrypt.MaxCost {
		cfg.dummyCost = DefaultStoredHashDummyCost
	}
	// Precompute one dummy bcrypt hash at the configured cost for timing
	// equalization on misses. Computed once at construction so the per-login
	// miss path only runs the (cost-bounded) compare, not a fresh generate.
	b, _ := bcrypt.GenerateFromPassword([]byte("stored-hash-verifier-dummy-timing-equalizer"), cfg.dummyCost)
	return &StoredHashVerifier{users: users, dummyHash: PasswordHash{Format: HashFormatBcrypt, Hash: string(b)}}
}

// Verify implements PasswordVerifier.
func (v *StoredHashVerifier) Verify(ctx context.Context, username, password string) (*sso.AuthResult, error) {
	u, err := v.users.GetByID(ctx, username)
	if err != nil || u == nil || u.Attributes == nil || u.Attributes[AttrPasswordHash] == "" {
		_ = VerifyHash(ctx, v.dummyHash, password) // timing equalization on a miss
		return nil, errStoredHashInvalid
	}
	format := u.Attributes[AttrPasswordHashFormat]
	if format == "" {
		format = HashFormatBcrypt
	}
	if err := VerifyHash(ctx, PasswordHash{Format: format, Hash: u.Attributes[AttrPasswordHash]}, password); err != nil {
		return nil, errStoredHashInvalid
	}
	return &sso.AuthResult{UserID: u.ID, Provider: "password"}, nil
}

// StoredHashRehashHooks returns the NeedsRehash + Updater closures for a
// LazyRehashVerifier wrapping a StoredHashVerifier. NeedsRehash reports true
// when the stored format is non-bcrypt (an imported legacy hash); Updater
// rewrites AttrPasswordHash + AttrPasswordHashFormat in place to the new bcrypt
// hash so the user is migrated transparently on first login.
func StoredHashRehashHooks(users sso.UserProvider) (
	needsRehash func(ctx context.Context, username string) (bool, error),
	updater func(ctx context.Context, username, newBcryptHash string) error,
) {
	needsRehash = func(ctx context.Context, username string) (bool, error) {
		u, err := users.GetByID(ctx, username)
		if err != nil || u == nil || u.Attributes == nil {
			return false, err
		}
		f := u.Attributes[AttrPasswordHashFormat]
		return f != "" && f != HashFormatBcrypt, nil
	}
	updater = func(ctx context.Context, username, newBcryptHash string) error {
		u, err := users.GetByID(ctx, username)
		if err != nil || u == nil {
			return err
		}
		// Clone the user + Attributes before mutating: a UserProvider may return
		// a shared pointer (the memory impl does), so an in-place map write would
		// race concurrent readers (other logins, the StoredHashVerifier itself).
		// CreateOrUpdate then swaps in the fresh map atomically under its lock.
		cp := *u
		cp.Attributes = make(map[string]string, len(u.Attributes)+2)
		maps.Copy(cp.Attributes, u.Attributes)
		cp.Attributes[AttrPasswordHash] = newBcryptHash
		cp.Attributes[AttrPasswordHashFormat] = HashFormatBcrypt
		return users.CreateOrUpdate(ctx, &cp)
	}
	return needsRehash, updater
}

// ChainPasswordVerifier tries each underlying verifier in order and returns the
// first success, composing independent credential sources behind one password
// authenticator (e.g. the self-service password store AND an imported-hash
// store). Each underlying verifier owns its own anti-enumeration timing; the
// chain itself adds no oracle — every verifier runs on a failed login.
type ChainPasswordVerifier struct {
	verifiers []PasswordVerifier
}

// NewChainPasswordVerifier composes verifiers in priority order.
func NewChainPasswordVerifier(vs ...PasswordVerifier) *ChainPasswordVerifier {
	return &ChainPasswordVerifier{verifiers: vs}
}

// Verify implements PasswordVerifier.
func (c *ChainPasswordVerifier) Verify(ctx context.Context, username, password string) (*sso.AuthResult, error) {
	lastErr := errStoredHashInvalid
	for _, v := range c.verifiers {
		res, err := v.Verify(ctx, username, password)
		if err == nil {
			return res, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

var (
	_ PasswordVerifier = (*StoredHashVerifier)(nil)
	_ PasswordVerifier = (*ChainPasswordVerifier)(nil)
)
