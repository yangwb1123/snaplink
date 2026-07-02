package importcmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/infrastructure/postgres"
	sso "github.com/snaplink/sso/interfaces/sso"
)

// Backend selector values — match the server's identity.backend vocabulary
// (cmd/sso-server/serverbuildstore.BuildUserProvider).
const (
	backendSQLite   = "sqlite"
	backendPostgres = "postgres"
)

// userStore is the store seam the importer needs: the portable
// core.UserProvider read/write contract plus lifecycle Close.
// *sqlite.UserProvider and *postgres.UserProvider both satisfy it.
type userStore interface {
	sso.UserProvider
	Close() error
}

// openDB dials the selected backend and runs its schema migration, so import
// works against a fresh database with no separate migrate step. The postgres
// package blank-imports the pgx driver itself; the sqlite driver comes from
// this package's modernc.org/sqlite blank import (main.go).
func openDB(backend, dsn, dialect string) (userStore, error) {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "", backendSQLite:
		p, err := sqlite.NewUserProvider(dsn)
		if err != nil {
			return nil, fmt.Errorf("sqlite: %w", err)
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
		return p, nil
	default:
		return nil, fmt.Errorf("unknown --backend %q (supported: sqlite, postgres)", backend)
	}
}

// runImport writes the users to the database in batches. Batching bounds
// error reporting to a manageable chunk size — writes are per-row
// CreateOrUpdate upserts on every backend, not a single transaction, so one
// bad row doesn't abort the batch and one bad batch doesn't abort the import.
func runImport(ctx context.Context, p userStore, users []importedUser, batchSize int) error {
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
		n, err := writeBatch(ctx, p, batch)
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

// writeBatch calls CreateOrUpdate for each user in the batch, accumulating
// errors. It returns the count of successfully written users. All users are
// attempted even if some fail.
func writeBatch(ctx context.Context, p userStore, batch []importedUser) (int, error) {
	ok := 0
	var errs []string
	for _, u := range batch {
		ssoUser := toSSOUser(u)
		if err := p.CreateOrUpdate(ctx, ssoUser); err != nil {
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
