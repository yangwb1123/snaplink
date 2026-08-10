package importcmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/infrastructure/auditoutbox"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/infrastructure/postgres/tenantcommerce"
	sso "github.com/yangwb1123/snaplink/interfaces/sso"
)

// Backend selector values — match the server's identity.backend vocabulary
// (cmd/sso-server/serverbuildstore.BuildUserProvider).
const (
	backendSQLite   = "sqlite"
	backendPostgres = "postgres"
)

// importEventType is the bounded governance vocabulary value for a bulk
// user import (dotted snaplink.<domain>.<class> convention, mirroring
// snaplink.audit.login_failure). The relay is type-agnostic; the value
// stays single-source here so recipients can match on it.
const importEventType = commerce.EventType("snaplink.audit.user.import")

// userStore is the store seam the importer needs: the portable
// core.UserProvider read/write contract plus the pair-write ImportUser
// (user upsert + governance outbox event in one transaction) plus the
// Close lifecycle. *sqlite.UserProvider satisfies it directly; the
// postgres backend is adapted via postgresUserStore (the pair-write for
// postgres lives in tenantcommerce — the cycle constraint of §1.1).
type userStore interface {
	sso.UserProvider
	ImportUser(ctx context.Context, u *sso.User, event *commerce.OutboxEvent) error
	Close() error
}

// postgresUserStore adapts *postgres.UserProvider to the widened seam:
// the pair-write delegates to tenantcommerce.ImportUserTx over the same
// pool the provider migrated.
type postgresUserStore struct {
	*postgres.UserProvider
}

func (s postgresUserStore) ImportUser(ctx context.Context, u *sso.User, event *commerce.OutboxEvent) error {
	return tenantcommerce.ImportUserTx(ctx, s.DB(), u, event)
}

// openDB dials the selected backend and runs its schema migration, so import
// works against a fresh database with no separate migrate step. It also
// ensures the governance outbox table exists (audit_outbox for sqlite,
// tenant_commerce_outbox for postgres) BEFORE any row is written — a fresh
// DB therefore fails fast, and the relay workers drain the import events
// with zero config change. The postgres package blank-imports the pgx
// driver itself; the sqlite driver comes from this package's
// modernc.org/sqlite blank import (main.go).
func openDB(backend, dsn, dialect string) (userStore, error) {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "", backendSQLite:
		p, err := sqlite.NewUserProvider(dsn)
		if err != nil {
			return nil, fmt.Errorf("sqlite: %w", err)
		}
		if err := auditoutbox.Migrate(context.Background(), p.DB()); err != nil {
			_ = p.Close()
			return nil, err
		}
		return p, nil
	case backendPostgres:
		p, err := postgres.NewUserProvider(postgres.Config{
			DSN:     dsn,
			Dialect: postgres.Dialect(dialect), // "" normalizes to postgres
		})
		if err != nil {
			return nil, err // already "postgres: ..."-prefixed by the package
		}
		// NewWithDB only ensures the schema; the store is discarded — it
		// owns no pool and has no Close, so the provider keeps ownership.
		if _, err := tenantcommerce.NewWithDB(p.DB(), postgres.Dialect(dialect)); err != nil {
			_ = p.Close()
			return nil, err
		}
		return postgresUserStore{p}, nil
	default:
		return nil, fmt.Errorf("unknown --backend %q (supported: sqlite, postgres)", backend)
	}
}

// runImport writes the users to the database in batches. Batching bounds
// error reporting to a manageable chunk size — writes are per-row
// ImportUser transactions on every backend, so one bad row doesn't abort
// the batch and one bad batch doesn't abort the import.
func runImport(ctx context.Context, p userStore, tenantID string, users []importedUser, batchSize int) error {
	if batchSize <= 0 {
		batchSize = 100
	}
	total := 0
	skipped := 0
	for i := 0; i < len(users); i += batchSize {
		end := i + batchSize
		if end > len(users) {
			end = len(users)
		}
		batch := users[i:end]
		n, err := writeBatch(ctx, p, tenantID, batch)
		total += n
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: batch %d-%d: %v (skipped %d in this batch)\n",
				progName, i+1, end, err, len(batch)-n)
			skipped += len(batch) - n
		}
	}
	fmt.Printf("%s: imported %d users", progName, total)
	if skipped > 0 {
		fmt.Printf(", skipped %d", skipped)
	}
	fmt.Println()
	return nil
}

// writeBatch imports each user in the batch via the pair-write seam,
// accumulating errors. It returns the count of successfully written users.
// All users are attempted even if some fail.
func writeBatch(ctx context.Context, p userStore, tenantID string, batch []importedUser) (int, error) {
	ok := 0
	var errs []string
	for _, u := range batch {
		ssoUser := toSSOUser(u)
		if err := p.ImportUser(ctx, ssoUser, newImportFact(tenantID, ssoUser)); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", u.ID, err))
			continue
		}
		ok++
	}
	if len(errs) > 0 {
		return ok, fmt.Errorf("%d write error(s): %s", len(errs), strings.Join(errs, "; "))
	}
	return ok, nil
}

// newImportFact builds the bounded, redacted governance event for one
// imported user. The event ID AND idempotency key are the deterministic
// "import:<tenant>:<userID>" composite — mandatory for the sqlite
// ON CONFLICT(id) DO NOTHING path (a random ID would violate the
// (tenant_id, idempotency_key) unique index on re-import) and it gives
// the relay a stable dedupe identity. The payload carries only user_id
// and provider — never the password hash, hash format, email, or any
// attribute material (the OutboxEvent contract: no credentials/PAN).
func newImportFact(tenantID string, u *sso.User) *commerce.OutboxEvent {
	now := time.Now().UTC()
	payload := map[string]string{
		"user_id":  u.ID,
		"provider": u.Provider,
	}
	key := "import:" + tenantID + ":" + u.ID
	return &commerce.OutboxEvent{
		ID:               key,
		TenantID:         tenantID,
		Type:             importEventType,
		AggregateType:    "user",
		AggregateID:      u.ID,
		AggregateVersion: 1,
		IdempotencyKey:   key,
		OccurredAt:       now,
		Payload:          payload,
		PayloadDigest:    digestPayload(payload),
		Status:           commerce.OutboxPending,
		CreatedAt:        now,
	}
}

// digestPayload is the canonical sha256 hex digest of the JSON encoding
// (json.Marshal sorts map keys, so identical payloads always digest
// identically) — the same scheme commerce.service.go and
// auditoutbox/fact.go use, so fact-equality checks agree across backends.
func digestPayload(payload map[string]string) string {
	encoded, _ := json.Marshal(payload)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// toSSOUser converts an importedUser to a core.User, placing the password
// hash and format into Attributes so the LazyRehashVerifier can read them
// on first login without a dedicated column (the User schema is stable; new
// columns need a migration, but Attributes is already present and the store
// survives schema evolution without a migration for attribute additions).
func toSSOUser(u importedUser) *sso.User {
	attrs := make(map[string]string)
	if u.Hash != "" {
		attrs["password_hash"] = u.Hash
	}
	if u.HashFormat != "" {
		attrs["password_hash_format"] = u.HashFormat
	}
	return &sso.User{
		ID:         u.ID,
		ExternalID: u.ExternalID,
		Provider:   u.Provider,
		Email:      u.Email,
		Name:       u.Name,
		Attributes: attrs,
	}
}

// ---- dry-run ----

func runDryRun(users []importedUser) {
	fmt.Printf("%s: dry-run — would import %d users\n", progName, len(users))
	const preview = 5
	n := len(users)
	if n > preview {
		n = preview
	}
	for _, u := range users[:n] {
		hashSummary := "(no hash)"
		if u.HashFormat != "" {
			hashSummary = "[" + u.HashFormat + "]"
		}
		fmt.Printf("  id=%-40s email=%-30s hash=%s\n", u.ID, u.Email, hashSummary)
	}
	if len(users) > preview {
		fmt.Printf("  ... and %d more\n", len(users)-preview)
	}
}
