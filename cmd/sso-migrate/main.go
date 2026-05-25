// sso-migrate is an operator CLI for offline inspection of a SQLite
// database's schema-migration state — useful for deploy pre-checks and
// disaster-recovery drills where the live server isn't running.
//
// Subcommands:
//
//	sso-migrate status --dsn <sqlite-dsn> [--json]
//
// status reads the schema_migrations_<namespace> tables the SDK's
// SQLite backends maintain and reports the latest applied version per
// namespace. It is read-only — migrations themselves are applied
// automatically when the server constructs each store (forward-only,
// idempotent), so this tool answers "what schema is this database on?"
// rather than mutating it.
//
// Pass a read-only DSN (e.g. `file:/var/lib/sso/sso.db?mode=ro`) to
// inspect a live database safely.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/snaplink/sso/migrate"

	_ "modernc.org/sqlite"
)

const progName = "sso-migrate"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "status":
		err = runStatus(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, progName+": unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, progName+":", err)
		os.Exit(1)
	}
}

// usage prints the standard "<prog> — <desc> / Usage / Subcommands" banner.
func usage() {
	fmt.Fprintln(os.Stderr, progName+` — offline SQLite schema-migration inspection.

Usage:
  `+progName+` status --dsn <sqlite-dsn> [--json]

Subcommands:
  status   Report the latest applied migration version per namespace.

Examples:
  `+progName+` status --dsn 'file:/var/lib/sso/sso.db?mode=ro'
  `+progName+` status --dsn ./sso.db --json`)
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	dsn := fs.String("dsn", "", "SQLite DSN to inspect (required; append ?mode=ro for a live DB)")
	asJSON := fs.Bool("json", false, "emit JSON instead of a table")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dsn == "" {
		return fmt.Errorf("--dsn is required")
	}

	db, err := sql.Open("sqlite", *dsn)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer db.Close()
	if err := db.PingContext(context.Background()); err != nil {
		return fmt.Errorf("open: %w", err)
	}

	st, err := migrate.Status(context.Background(), db)
	if err != nil {
		return err
	}
	return renderStatus(os.Stdout, st, *asJSON)
}

// renderStatus writes the status report to w — factored out so tests can
// assert on the rendered output without capturing os.Stdout.
func renderStatus(w io.Writer, st []migrate.NamespaceStatus, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	if len(st) == 0 {
		fmt.Fprintln(w, "(no migrated namespaces — empty or non-SSO database)")
		return nil
	}
	fmt.Fprintf(w, "%-24s  %-8s  %-28s  %s\n", "NAMESPACE", "VERSION", "LATEST MIGRATION", "APPLIED AT")
	for _, s := range st {
		applied := "-"
		if !s.AppliedAt.IsZero() {
			applied = s.AppliedAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%-24s  %-8d  %-28s  %s\n", s.Namespace, s.Version, s.Name, applied)
	}
	return nil
}
