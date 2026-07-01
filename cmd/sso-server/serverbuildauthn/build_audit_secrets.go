package serverbuildauthn

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/spi"

	"github.com/snaplink/sso/domains/authenticators"
	auditsqlite "github.com/snaplink/sso/platform/audit/sqlite"

	"github.com/snaplink/sso/config"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	postgresbackend "github.com/snaplink/sso/infrastructure/postgres"

	"golang.org/x/crypto/bcrypt"
)

// BuildPrimaryAuditSink constructs the [audit.Sink] cmd places at
// the root of the sink composition (the one /audit query reads from
// + that gets wrapped by MultiSink+Webhook+Async). Backend selects
// between in-process MemorySink and the SQLite-backed Sink. Returns
// the sink + a short identifier used as the ReadyCheck suffix.
func BuildPrimaryAuditSink(cfg config.AuditConfig, logger spi.Logger, pg *sql.DB, dialect postgresbackend.Dialect) (audit.Sink, string, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		logger.Info("audit: primary sink", "backend", "memory", "capacity", cfg.MemoryCapacity)
		return audit.NewMemorySink(cfg.MemoryCapacity), "memory", nil
	case "sqlite":
		if cfg.Sqlite.DSN == "" {
			return nil, "", errors.New("audit.sqlite.dsn required when audit.backend=sqlite")
		}
		sink, err := auditsqlite.New(cfg.Sqlite.DSN)
		if err != nil {
			return nil, "", fmt.Errorf("open sqlite audit sink: %w", err)
		}
		logger.Info("audit: primary sink", "backend", "sqlite", "dsn", cfg.Sqlite.DSN)
		return sink, "sqlite", nil
	case "postgres":
		if pg == nil {
			return nil, "", errors.New("audit.backend=postgres but no postgres block configured (set postgres.dsn)")
		}
		sink, err := postgresbackend.NewAuditSinkWithDB(pg, dialect)
		if err != nil {
			return nil, "", fmt.Errorf("open postgres audit sink: %w", err)
		}
		logger.Info("audit: primary sink", "backend", "postgres (cluster-shared)")
		return sink, "postgres", nil
	default:
		return nil, "", fmt.Errorf("audit.backend must be one of memory|sqlite|postgres, got %q", cfg.Backend)
	}
}

// LoadSecretFile reads a secret material file and returns the content
// with a trailing newline (if any) stripped. Empty contents fail so
// operators see the misconfiguration at boot rather than shipping
// with an authenticator that admits the empty string as a credential.
// Matches the file-based secret pattern bootstrap.admin_password_file
// uses — keeps secrets out of YAML where readers + version control
// would expose them.
func LoadSecretFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	s := strings.TrimRight(string(raw), "\r\n")
	if s == "" {
		return "", fmt.Errorf("%s: empty secret", path)
	}
	return s, nil
}

// LoadEd25519PublicKeyPEM reads a PEM file containing a "PUBLIC KEY"
// block and returns the parsed Ed25519 key. Refuses any other key
// type to keep operators from accidentally feeding RSA/ECDSA pubkeys
// that the verifier would silently reject at signature time.
func LoadEd25519PublicKeyPEM(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block found", path)
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%s: PEM type %q; want PUBLIC KEY", path, block.Type)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pub key in %s: %w", path, err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: parsed key is %T; want ed25519.PublicKey", path, parsed)
	}
	return pub, nil
}

// LoadCertPool reads one or more PEM files and returns an x509.CertPool
// containing every CERTIFICATE block found across them. Empty paths
// list returns an empty (but non-nil) pool — the certificate
// authenticator refuses to validate against an empty trust store anyway,
// so the caller can surface that as a config error if it cares.
//
// A single bad file (missing, unparseable, no PEM blocks) fails the
// whole load so operators see the misconfiguration at boot instead of
// silently shipping with a partial trust store that admits some
// expected certs but rejects others.
func LoadCertPool(paths []string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, p := range paths {
		if p == "" {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		appended := 0
		rest := raw
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse cert in %s: %w", p, err)
			}
			pool.AddCert(cert)
			appended++
		}
		if appended == 0 {
			return nil, fmt.Errorf("%s: no CERTIFICATE PEM blocks found", p)
		}
	}
	return pool, nil
}

// passwordSeed stores one cmd-side username->bcrypt-hash entry.
type passwordSeed struct {
	hash      []byte
	subjectID string
}

// BuildBcryptPasswordVerifier returns a PasswordVerifier closed over
// an in-memory username->bcrypt-hash map seeded from YAML. Bad
// entries (missing field, unreadable file, malformed hash) log + skip
// at boot rather than crashing; an empty map yields a verifier that
// rejects every credential.
//
// Unknown-username and wrong-password paths both run one bcrypt
// compare so wall-clock response time can't enumerate the seed
// list. The dummy hash is generated at verifier-build time at the
// cost of the FIRST loaded seed (or bcrypt.DefaultCost when no
// seeds are present), so the dummy and real-hash bcrypt compares
// sit in the same order of magnitude — without that, an attacker
// could split "real cost-10 user" from "dummy cost-12 unknown user"
// by latency.
// BuildStoredPasswordVerifier seeds the password store from the YAML users (by
// bcrypt hash, via the PasswordHashImporter seam) and returns a verifier that
// authenticates AGAINST the store — so a password later changed through
// /me/password is the one login checks. Preserves the YAML verifier's contract:
// AuthResult{UserID: subjectID, ExternalID: username}, anti-enumeration (a
// cost-matched dummy compare on an unknown username, run by the store), and
// skip+log of malformed seeds.
func BuildStoredPasswordVerifier(store sso.PasswordCredentialStore, users []config.PasswordUserConfig, logger spi.Logger) (authenticators.PasswordVerifier, int, error) {
	importer, ok := store.(sso.PasswordHashImporter)
	if !ok {
		return nil, 0, errors.New("password store does not support hash import (cannot seed YAML users)")
	}
	subjectByUser := make(map[string]string, len(users))
	seeded := 0
	for _, u := range users {
		if u.Username == "" || u.BcryptHashFile == "" || u.SubjectID == "" {
			logger.Error("password seed skipped (missing field)", "username", u.Username, "subject_id", u.SubjectID)
			continue
		}
		hash, err := LoadBcryptHashFile(u.BcryptHashFile)
		if err != nil {
			logger.Error("password seed skipped (load hash)", "username", u.Username, "file", u.BcryptHashFile, "error", err)
			continue
		}
		if err := importer.SetPasswordHash(context.Background(), u.SubjectID, string(hash)); err != nil {
			logger.Error("password seed skipped (store import)", "username", u.Username, "error", err)
			continue
		}
		subjectByUser[u.Username] = u.SubjectID
		seeded++
	}
	verifier := authenticators.PasswordVerifierFunc(func(ctx context.Context, user, pass string) (*sso.AuthResult, error) {
		subjectID, ok := subjectByUser[user]
		if !ok {
			// Unknown username: still spend a compare via the store so timing
			// can't enumerate the seed list, then collapse to one error.
			_ = store.VerifyPassword(ctx, "", pass)
			return nil, errors.New("password: invalid credentials")
		}
		if err := store.VerifyPassword(ctx, subjectID, pass); err != nil {
			return nil, errors.New("password: invalid credentials")
		}
		return &sso.AuthResult{UserID: subjectID, ExternalID: user}, nil
	})
	return verifier, seeded, nil
}

func BuildBcryptPasswordVerifier(users []config.PasswordUserConfig, logger spi.Logger) (authenticators.PasswordVerifier, int) {
	seeds := make(map[string]passwordSeed, len(users))
	dummyCost := bcrypt.DefaultCost
	seeded := 0
	for _, u := range users {
		if u.Username == "" || u.BcryptHashFile == "" || u.SubjectID == "" {
			logger.Error("password seed skipped (missing field)",
				"username", u.Username, "subject_id", u.SubjectID)
			continue
		}
		hash, err := LoadBcryptHashFile(u.BcryptHashFile)
		if err != nil {
			logger.Error("password seed skipped (load hash)",
				"username", u.Username, "file", u.BcryptHashFile, "error", err)
			continue
		}
		if seeded == 0 {
			if c, err := bcrypt.Cost(hash); err == nil {
				dummyCost = c
			}
		}
		seeds[u.Username] = passwordSeed{hash: hash, subjectID: u.SubjectID}
		seeded++
	}
	dummy, err := bcrypt.GenerateFromPassword([]byte("dummy-for-timing-equalization-only"), dummyCost)
	if err != nil {
		panic(fmt.Sprintf("bcrypt dummy hash gen: %v", err))
	}
	verifier := authenticators.PasswordVerifierFunc(func(_ context.Context, user, pass string) (*sso.AuthResult, error) {
		entry, ok := seeds[user]
		hash := dummy
		if ok {
			hash = entry.hash
		}
		// Run bcrypt unconditionally so unknown-user and wrong-password
		// take the same wall-clock time. The error is collapsed to a
		// single string regardless of which branch failed.
		if err := bcrypt.CompareHashAndPassword(hash, []byte(pass)); err != nil || !ok {
			return nil, errors.New("password: invalid credentials")
		}
		return &sso.AuthResult{UserID: entry.subjectID, ExternalID: user}, nil
	})
	return verifier, seeded
}

// LoadBcryptHashFile reads a bcrypt hash from disk. The file's first
// line (newline-stripped) is the hash. Refuses anything that doesn't
// start with the bcrypt format prefix so a misconfigured file
// (plaintext password, sha256 hash, accidentally swapped file) fails
// at boot rather than producing an authenticator that silently never
// matches.
func LoadBcryptHashFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	// Bcrypt hashes are single-line ASCII; tolerate trailing newline
	// from `echo` and strip any leading/trailing whitespace from
	// hand-edited files. Reject internal newlines to catch the
	// "wrote the wrong file" case.
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return nil, fmt.Errorf("%s: empty file", path)
	}
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("%s: multi-line content; expected a single bcrypt hash", path)
	}
	if !strings.HasPrefix(s, "$2a$") && !strings.HasPrefix(s, "$2b$") && !strings.HasPrefix(s, "$2y$") {
		return nil, fmt.Errorf("%s: not a bcrypt hash (must start with $2a$/$2b$/$2y$)", path)
	}
	return []byte(s), nil
}

// BuildPasswordHealthChecker constructs the configured login-time
// credential-health checker. Kind selects the implementation: "" /
// "dictionary" is the fully-offline DictionaryPasswordHealthChecker
// (default, back-compatible); "hibp" is the online Have I Been Pwned
// k-anonymity breach checker (only a 5-char SHA-1 prefix ever leaves the
// process; fail-open so an outage never blocks login). An unknown Kind is
// a loud boot error rather than a silent fallback.
func BuildPasswordHealthChecker(h *config.PasswordHealthConfig, logger spi.Logger) (spi.PasswordHealthChecker, error) {
	switch h.Kind {
	case "", "dictionary":
		checker, err := defaultimpl.NewDictionaryPasswordHealthChecker(defaultimpl.DictionaryPasswordHealthConfig{
			WeakPasswordFile: h.WeakPasswordFile,
		})
		if err != nil {
			return nil, err
		}
		logger.Info("password health checker enabled", "kind", "dictionary", "weak_password_file", h.WeakPasswordFile)
		return checker, nil
	case "hibp":
		opts := []defaultimpl.HIBPOption{
			// Surface fail-open HIBP outages in production; the check still
			// never blocks a login (the checker swallows the error itself).
			defaultimpl.WithHIBPLogger(logger),
		}
		var baseURL string
		if hc := h.HIBP; hc != nil {
			baseURL = hc.BaseURL
			if hc.BaseURL != "" {
				opts = append(opts, defaultimpl.WithHIBPBaseURL(hc.BaseURL))
			}
			if hc.Timeout > 0 {
				opts = append(opts, defaultimpl.WithHIBPTimeout(hc.Timeout))
			}
			if hc.MinCount > 0 {
				opts = append(opts, defaultimpl.WithHIBPMinCount(hc.MinCount))
			}
			if hc.UserAgent != "" {
				opts = append(opts, defaultimpl.WithHIBPUserAgent(hc.UserAgent))
			}
		}
		checker, err := defaultimpl.NewHIBPPasswordHealthChecker(opts...)
		if err != nil {
			return nil, err
		}
		// Log only the (non-secret) base URL — never a password or hash.
		logger.Info("password health checker enabled", "kind", "hibp", "base_url", baseURL)
		return checker, nil
	default:
		return nil, fmt.Errorf("unknown password health kind %q (want \"dictionary\" or \"hibp\")", h.Kind)
	}
}
