// sso-import is an operator CLI for bulk-importing users from external
// identity providers (Auth0, Keycloak, generic CSV) into the SSO server's
// SQLite user store. It writes directly to the database without requiring a
// running server instance, making it safe to use as a migration pre-step
// before the first deploy or as part of a scripted cutover.
//
// Supported formats:
//
//	auth0     Auth0 Users Export JSON (array of user objects)
//	keycloak  Keycloak realm export JSON (the "users" array from a full realm export)
//	csv       Generic CSV: username,email,name,password_hash,hash_format
//
// Usage:
//
//	sso-import --dsn file:/var/lib/sso/sso.db --format auth0 --file export.json
//	sso-import --dsn file:/var/lib/sso/sso.db --format csv  --file users.csv --dry-run
//	cat export.json | sso-import --dsn ./sso.db --format keycloak --file -
//
// The tool writes one user per row into the "users" table via an upsert
// (CREATE OR UPDATE semantics). Password hashes are stored in the
// Attributes map under the key "password_hash" (the hash string) and
// "password_hash_format" (the format tag). To let these users authenticate,
// enable `authenticators.password.imported_hash_login: true` in the server
// config — that chains an attribute-backed multi-format verifier wrapped in
// LazyRehashVerifier, which reads these attributes on first login to verify the
// legacy hash and transparently upgrade it to bcrypt.
//
// A --dry-run counts the records that would be imported and prints a sample
// without touching the database.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

const progName = "sso-import"

// importedUser is the normalised representation of one user extracted from
// any of the supported source formats. Hash and HashFormat are optional —
// some sources (e.g. SSO-provisioned users) don't export password hashes.
type importedUser struct {
	// ID is derived per-format; falls back to a sanitized email or username.
	ID string
	// ExternalID is the source-system's opaque identifier, preserved for
	// de-duplication and cross-reference.
	ExternalID string
	// Provider is the source format tag ("auth0", "keycloak", "csv").
	Provider string
	Email    string
	Name     string
	// Hash is the full encoded hash string (format-specific).
	Hash string
	// HashFormat is one of the PasswordHash format constants or empty when
	// no hash was exported.
	HashFormat string
}

func main() {
	fs := flag.NewFlagSet(progName, flag.ExitOnError)
	dsn := fs.String("dsn", "", "SQLite DSN for the SSO user store (required unless --dry-run)")
	format := fs.String("format", "", "input format: auth0 | keycloak | csv (required)")
	file := fs.String("file", "-", "path to the import file, or - for stdin")
	dryRun := fs.Bool("dry-run", false, "print what would be imported without writing")
	batchSize := fs.Int("batch-size", 100, "rows per transaction (ignored for dry-run)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `%s — bulk user import from Auth0 / Keycloak / CSV into SSO SQLite.

Usage:
  %s --dsn <sqlite-dsn> --format <fmt> [--file <path>] [--dry-run]

Flags:
`, progName, progName)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Formats:
  auth0     Auth0 Users Export JSON  (array of objects with email, password_hash, etc.)
  keycloak  Keycloak realm export JSON (the "users" array from a full realm dump)
  csv       Header row: username,email,name,password_hash,hash_format

Examples:
  %s --dsn file:/var/lib/sso/sso.db --format auth0 --file users.json
  cat realm.json | %s --dsn ./sso.db --format keycloak --file -
`, progName, progName)
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if *format == "" {
		fmt.Fprintln(os.Stderr, progName+": --format is required")
		fs.Usage()
		os.Exit(2)
	}
	if !*dryRun && *dsn == "" {
		fmt.Fprintln(os.Stderr, progName+": --dsn is required (or pass --dry-run to skip writing)")
		fs.Usage()
		os.Exit(2)
	}

	r, err := openInput(*file)
	if err != nil {
		fatalf("open input: %v", err)
	}
	defer func() { _ = r.Close() }()

	users, err := parseInput(*format, r)
	if err != nil {
		fatalf("parse %s: %v", *format, err)
	}

	if *dryRun {
		runDryRun(users)
		return
	}

	db, err := openDB(*dsn)
	if err != nil {
		fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := runImport(context.Background(), db, users, *batchSize); err != nil {
		fatalf("import: %v", err)
	}
}

// ---- input ----

func openInput(path string) (io.ReadCloser, error) {
	if path == "-" {
		return io.NopCloser(os.Stdin), nil
	}
	return os.Open(filepath.Clean(path))
}

// ---- utilities ----

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, progName+": "+format+"\n", args...)
	os.Exit(1)
}

// Ensure the sqlite driver is imported for its side-effect (registers "sqlite").
var _ *sql.DB
