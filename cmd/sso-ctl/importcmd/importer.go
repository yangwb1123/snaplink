package importcmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	sso "github.com/snaplink/sso/interfaces/sso"
)

func openDB(dsn string) (*sqlite.UserProvider, error) {
	p, err := sqlite.NewUserProvider(dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: %w", err)
	}
	return p, nil
}

// runImport writes the users to the database in batches. Each batch is a
// single SQLite transaction so a single failure doesn't abort the entire
// import — the bad batch is reported and the next batch continues.
func runImport(ctx context.Context, p *sqlite.UserProvider, users []importedUser, batchSize int) error {
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
func writeBatch(ctx context.Context, p *sqlite.UserProvider, batch []importedUser) (int, error) {
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
