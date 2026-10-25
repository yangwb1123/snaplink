// Command migration-readpath proves migrated rows are readable through the
// server's own PostgreSQL stores after an import.
//
// Store construction runs the store's idempotent schema migration, so this is
// NOT a read-only tool: the caller must pass -allow-idempotent-migrations and
// the command reports table digests before and after to show that no existing
// row content changed.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/yangwb1123/snaplink/infrastructure/postgres"
)

type clientCase struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Active       bool   `json:"active"`
	RedirectURIs int    `json:"redirect_uris"`
}

type userCase struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type sessionCase struct {
	ID      string `json:"id"`
	UserID  string `json:"user_id"`
	Revoked bool   `json:"revoked"`
	// ExpectUnreadable marks a row the live store must refuse to serve, such as
	// an already-expired historical session. A refusal is then the correct result.
	ExpectUnreadable bool `json:"expect_unreadable"`
}

type expectations struct {
	Clients  []clientCase  `json:"clients"`
	Users    []userCase    `json:"users"`
	Sessions []sessionCase `json:"sessions"`
}

type caseResult struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type digest struct {
	Rows int    `json:"rows"`
	Sum  string `json:"sum"`
}

type report struct {
	Result                string            `json:"result"`
	Scope                 string            `json:"scope"`
	Cases                 []caseResult      `json:"cases"`
	Before                map[string]digest `json:"digests_before"`
	After                 map[string]digest `json:"digests_after"`
	ExistingRowsUnchanged bool              `json:"existing_rows_unchanged"`
	MigrationsRun         bool              `json:"idempotent_store_migrations_ran"`
}

func validate(values expectations) error {
	total := len(values.Clients) + len(values.Users) + len(values.Sessions)
	if total == 0 {
		return errors.New("at least one expectation is required")
	}
	if total > 200 {
		return errors.New("expectation budget exceeded")
	}
	for _, c := range values.Clients {
		if c.ID == "" {
			return errors.New("client case requires id")
		}
	}
	for _, u := range values.Users {
		if u.ID == "" {
			return errors.New("user case requires id")
		}
	}
	for _, s := range values.Sessions {
		if s.ID == "" {
			return errors.New("session case requires id")
		}
	}
	return nil
}

func tableDigest(ctx context.Context, db *sql.DB, table string) (digest, error) {
	query := fmt.Sprintf(`SELECT count(*), coalesce(md5(string_agg(c, '' ORDER BY c)), '') FROM (SELECT row_to_json(t)::text AS c FROM %s t) s`, table)
	var out digest
	err := db.QueryRowContext(ctx, query).Scan(&out.Rows, &out.Sum)
	return out, err
}

func digests(ctx context.Context, db *sql.DB) (map[string]digest, error) {
	out := map[string]digest{}
	for _, table := range []string{"clients", "users", "sessions"} {
		value, err := tableDigest(ctx, db, table)
		if err != nil {
			return nil, err
		}
		out[table] = value
	}
	return out, nil
}

func checkClients(ctx context.Context, store *postgres.ClientStore, cases []clientCase) []caseResult {
	var out []caseResult
	for _, want := range cases {
		client, err := store.Get(ctx, want.ID)
		if err != nil {
			out = append(out, caseResult{Kind: "clients", ID: want.ID, Detail: "unreadable"})
			continue
		}
		ok := client.ID == want.ID && client.Name == want.Name && client.Active == want.Active &&
			len(client.RedirectURIs) == want.RedirectURIs
		out = append(out, caseResult{Kind: "clients", ID: want.ID, OK: ok, Detail: mismatch(ok, "client fields differ")})
	}
	return out
}

func checkUsers(ctx context.Context, provider *postgres.UserProvider, cases []userCase) []caseResult {
	var out []caseResult
	for _, want := range cases {
		user, err := provider.GetByID(ctx, want.ID)
		if err != nil {
			out = append(out, caseResult{Kind: "users", ID: want.ID, Detail: "unreadable"})
			continue
		}
		ok := user.ID == want.ID && user.Email == want.Email && user.Name == want.Name
		out = append(out, caseResult{Kind: "users", ID: want.ID, OK: ok, Detail: mismatch(ok, "user fields differ")})
	}
	return out
}

func checkSessions(ctx context.Context, manager *postgres.SessionManager, cases []sessionCase) []caseResult {
	var out []caseResult
	for _, want := range cases {
		session, err := manager.Get(ctx, want.ID)
		if err != nil {
			if want.ExpectUnreadable {
				out = append(out, caseResult{Kind: "sessions", ID: want.ID, OK: true})
				continue
			}
			out = append(out, caseResult{Kind: "sessions", ID: want.ID, Detail: "unreadable"})
			continue
		}
		if want.ExpectUnreadable {
			out = append(out, caseResult{Kind: "sessions", ID: want.ID, Detail: "row must not be served"})
			continue
		}
		ok := session.ID == want.ID && session.UserID == want.UserID && session.Revoked == want.Revoked
		out = append(out, caseResult{Kind: "sessions", ID: want.ID, OK: ok, Detail: mismatch(ok, "session fields differ")})
	}
	return out
}

func mismatch(ok bool, detail string) string {
	if ok {
		return ""
	}
	return detail
}

func allOK(cases []caseResult) bool {
	for _, c := range cases {
		if !c.OK {
			return false
		}
	}
	return true
}

func render(result report) string {
	body, _ := json.Marshal(result)
	return string(body) + "\n"
}

type options struct {
	dsnFile string
	expect  string
	allow   bool
}

func parseOptions(args []string, stderr *os.File) (options, bool) {
	flags := flag.NewFlagSet("migration-readpath", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dsnFile := flags.String("dsn-file", "", "file containing the PostgreSQL DSN")
	expectFile := flags.String("expect", "", "expectation JSON produced from the migrated source")
	allow := flags.Bool("allow-idempotent-migrations", false,
		"acknowledge that store construction runs its own idempotent migration")
	if err := flags.Parse(args); err != nil {
		return options{}, false
	}
	if *dsnFile == "" || *expectFile == "" {
		fmt.Fprintln(stderr, "dsn-file and expect are required")
		return options{}, false
	}
	if !*allow {
		fmt.Fprintln(stderr, "refusing: store construction migrates the candidate; pass -allow-idempotent-migrations after reviewing it")
		return options{}, false
	}
	return options{dsnFile: *dsnFile, expect: *expectFile, allow: *allow}, true
}

func loadExpectations(path string) (expectations, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return expectations{}, errors.New("expectation unreadable")
	}
	var values expectations
	if err := json.Unmarshal(raw, &values); err != nil {
		return expectations{}, errors.New("expectation json invalid")
	}
	return values, validate(values)
}

func openDatabase(path string) (*sql.DB, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("dsn unreadable")
	}
	return sql.Open("pgx", strings.TrimSpace(string(raw)))
}

func evaluate(ctx context.Context, db *sql.DB, values expectations) (report, error) {
	before, err := digests(ctx, db)
	if err != nil {
		return report{}, errors.New("pre-read digest failed")
	}
	clients, err := postgres.NewClientStoreWithDB(db, postgres.DialectPostgres)
	if err != nil {
		return report{}, errors.New("client store unavailable")
	}
	users, err := postgres.NewUserProviderWithDB(db, postgres.DialectPostgres)
	if err != nil {
		return report{}, errors.New("user provider unavailable")
	}
	sessions, err := postgres.NewSessionManagerWithDB(db, postgres.DialectPostgres, time.Hour)
	if err != nil {
		return report{}, errors.New("session manager unavailable")
	}
	cases := checkClients(ctx, clients, values.Clients)
	cases = append(cases, checkUsers(ctx, users, values.Users)...)
	cases = append(cases, checkSessions(ctx, sessions, values.Sessions)...)
	after, err := digests(ctx, db)
	if err != nil {
		return report{}, errors.New("post-read digest failed")
	}
	unchanged := before["clients"] == after["clients"] && before["users"] == after["users"] &&
		before["sessions"] == after["sessions"]
	result := report{Result: "failed", Scope: "server-store read path over migrated rows;NOT cutover",
		Cases: cases, Before: before, After: after, ExistingRowsUnchanged: unchanged, MigrationsRun: true}
	if allOK(cases) && unchanged {
		result.Result = "passed"
	}
	return result, nil
}

func run(args []string, stdout, stderr *os.File) int {
	opts, ok := parseOptions(args, stderr)
	if !ok {
		return 2
	}
	values, err := loadExpectations(opts.expect)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	db, err := openDatabase(opts.dsnFile)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := evaluate(ctx, db, values)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	fmt.Fprint(stdout, render(result))
	if result.Result != "passed" {
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
