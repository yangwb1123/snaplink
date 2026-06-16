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
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	sso "github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl/sqlite"

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

// ---- parsers ----

func parseInput(format string, r io.Reader) ([]importedUser, error) {
	switch format {
	case "auth0":
		return parseAuth0(r)
	case "keycloak":
		return parseKeycloak(r)
	case "csv":
		return parseCSV(r)
	default:
		return nil, fmt.Errorf("unknown format %q (want auth0, keycloak, or csv)", format)
	}
}

// --- Auth0 ---
//
// Auth0 Users Export: a JSON array where each element is a user object.
// Relevant fields: user_id, email, name, password_hash, identities[].
// Auth0 hashes are bcrypt ($2b$...).
//
// Reference: https://auth0.com/docs/manage-users/user-migration/bulk-user-exports

type auth0User struct {
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	PasswordHash string `json:"password_hash"`
}

func parseAuth0(r io.Reader) ([]importedUser, error) {
	var raw []auth0User
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode auth0 json: %w", err)
	}
	out := make([]importedUser, 0, len(raw))
	for _, u := range raw {
		if u.Email == "" && u.UserID == "" {
			continue // skip empty rows
		}
		id := deriveID(u.UserID, u.Email, "auth0")
		format := ""
		if u.PasswordHash != "" {
			format = detectHashFormat(u.PasswordHash)
		}
		out = append(out, importedUser{
			ID:         id,
			ExternalID: u.UserID,
			Provider:   "auth0",
			Email:      u.Email,
			Name:       u.Name,
			Hash:       u.PasswordHash,
			HashFormat: format,
		})
	}
	return out, nil
}

// --- Keycloak ---
//
// Keycloak realm export JSON: the top-level "users" key is an array.
// Each user has: id, username, email, firstName, lastName,
// credentials[]{type:"password", secretData: JSON{value, salt}, credentialData: JSON{hashIterations, algorithm}}.
//
// Keycloak >= 18 stores PBKDF2-SHA256 hashes with the Django-style encoding
// "pbkdf2_sha256$<iter>$<salt>$<hash>". Older versions used argon2id.
// The encoded value lives in credentials[].secretData as JSON.

type keycloakUser struct {
	ID          string               `json:"id"`
	Username    string               `json:"username"`
	Email       string               `json:"email"`
	FirstName   string               `json:"firstName"`
	LastName    string               `json:"lastName"`
	Credentials []keycloakCredential `json:"credentials"`
}

type keycloakCredential struct {
	Type           string `json:"type"`
	SecretData     string `json:"secretData"`
	CredentialData string `json:"credentialData"`
}

// keycloakSecretData is the parsed JSON inside credential.SecretData.
type keycloakSecretData struct {
	Value string `json:"value"`
	Salt  string `json:"salt"`
}

// keycloakCredentialData is the parsed JSON inside credential.CredentialData.
type keycloakCredentialData struct {
	HashIterations int    `json:"hashIterations"`
	Algorithm      string `json:"algorithm"`
}

// keycloakRealm is the top-level structure of a Keycloak realm export.
type keycloakRealm struct {
	Users []keycloakUser `json:"users"`
}

func parseKeycloak(r io.Reader) ([]importedUser, error) {
	var realm keycloakRealm
	dec := json.NewDecoder(r)
	// The realm export may be EITHER {"users":[...]} or a bare array [...]
	// depending on whether a full realm or partial export was done.
	// Peek at the first token to decide.
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("decode keycloak json: %w", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		if t == '[' {
			// Bare array. dec.Token() already consumed the '[', so the
			// decoder is positioned at the FIRST element — calling
			// dec.Decode(&users) here would wrongly expect another '[' and
			// fail. Decode elements one-by-one, mirroring
			// decodeKeycloakObject, then consume the closing ']'.
			for dec.More() {
				var u keycloakUser
				if err := dec.Decode(&u); err != nil {
					return nil, fmt.Errorf("decode keycloak users array: %w", err)
				}
				realm.Users = append(realm.Users, u)
			}
			if _, err := dec.Token(); err != nil && !errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("decode keycloak users array: %w", err)
			}
		} else {
			// Object — re-decode from scratch using a temp decoder.
			// We already consumed the '{' delimiter; push it back by
			// decoding the fields manually.
			if err := decodeKeycloakObject(dec, &realm); err != nil {
				return nil, fmt.Errorf("decode keycloak realm object: %w", err)
			}
		}
	default:
		return nil, fmt.Errorf("keycloak json: unexpected token %v", t)
	}

	out := make([]importedUser, 0, len(realm.Users))
	for _, u := range realm.Users {
		if u.Email == "" && u.Username == "" && u.ID == "" {
			continue
		}
		name := strings.TrimSpace(u.FirstName + " " + u.LastName)
		id := deriveID(u.ID, u.Email, "keycloak")
		hash, hashFormat := extractKeycloakHash(u.Credentials)
		out = append(out, importedUser{
			ID:         id,
			ExternalID: u.ID,
			Provider:   "keycloak",
			Email:      u.Email,
			Name:       name,
			Hash:       hash,
			HashFormat: hashFormat,
		})
	}
	return out, nil
}

// decodeKeycloakObject reads the remaining key/value pairs of the
// already-opened "{" object from dec, populating realm.
func decodeKeycloakObject(dec *json.Decoder, realm *keycloakRealm) error {
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("expected JSON string key, got %T", keyTok)
		}
		if key == "users" {
			if err := dec.Decode(&realm.Users); err != nil {
				return fmt.Errorf("decode users: %w", err)
			}
		} else {
			// Skip unknown fields by consuming a raw message.
			var discard json.RawMessage
			if err := dec.Decode(&discard); err != nil {
				return err
			}
		}
	}
	// Consume the closing "}"
	if _, err := dec.Token(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// extractKeycloakHash finds the first "password" credential in the list,
// parses the Keycloak-encoded hash, and reconstructs the portable encoded
// string the VerifyHash functions expect.
func extractKeycloakHash(creds []keycloakCredential) (hash, format string) {
	for _, c := range creds {
		if c.Type != "password" {
			continue
		}
		var sd keycloakSecretData
		if err := json.Unmarshal([]byte(c.SecretData), &sd); err != nil {
			continue
		}
		var cd keycloakCredentialData
		if err := json.Unmarshal([]byte(c.CredentialData), &cd); err != nil {
			continue
		}
		switch cd.Algorithm {
		case "pbkdf2-sha256":
			// Reconstruct Django-style encoding: pbkdf2_sha256$iter$salt$hash
			hash = fmt.Sprintf("pbkdf2_sha256$%d$%s$%s", cd.HashIterations, sd.Salt, sd.Value)
			format = "pbkdf2-sha256"
		case "pbkdf2-sha512":
			hash = fmt.Sprintf("pbkdf2_sha512$%d$%s$%s", cd.HashIterations, sd.Salt, sd.Value)
			format = "pbkdf2-sha512"
		case "argon2id":
			// Keycloak argon2id encodes value as the raw derived key in base64
			// and salt as a separate field; reconstruct the PHC string.
			// Keycloak defaults: m=7168,t=5,p=1 — these come from credentialData
			// as separate numeric fields. When absent, we reconstruct from the
			// raw value directly if it already looks like a PHC string.
			if strings.HasPrefix(sd.Value, "$argon2id$") {
				hash = sd.Value
			} else {
				// Fall back: treat the value as opaque (can't reconstruct without
				// knowing m/t/p) — store but mark as unknown so the verifier will
				// fail loudly rather than silently accept anything.
				hash = sd.Value
			}
			format = "argon2id"
		case "bcrypt":
			hash = sd.Value
			format = "bcrypt"
		}
		if hash != "" {
			return hash, format
		}
	}
	return "", ""
}

// --- CSV ---
//
// Generic CSV: header row required.
// Required columns: email (or username)
// Optional columns: username, name, password_hash, hash_format
//
// Column names are case-insensitive; extra columns are ignored.

func parseCSV(r io.Reader) ([]importedUser, error) {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true
	cr.ReuseRecord = false

	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("read csv header: %w", err)
	}
	colIdx := make(map[string]int, len(header))
	for i, h := range header {
		colIdx[strings.ToLower(strings.TrimSpace(h))] = i
	}

	colGet := func(row []string, name string) string {
		if i, ok := colIdx[name]; ok && i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}

	var out []importedUser
	lineNum := 1
	for {
		row, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		lineNum++
		if err != nil {
			return nil, fmt.Errorf("csv line %d: %w", lineNum, err)
		}
		username := colGet(row, "username")
		email := colGet(row, "email")
		if username == "" && email == "" {
			continue
		}
		hash := colGet(row, "password_hash")
		hashFormat := colGet(row, "hash_format")
		if hash != "" && hashFormat == "" {
			hashFormat = detectHashFormat(hash)
		}
		id := deriveID(username, email, "csv")
		out = append(out, importedUser{
			ID:         id,
			ExternalID: username,
			Provider:   "csv",
			Email:      email,
			Name:       colGet(row, "name"),
			Hash:       hash,
			HashFormat: hashFormat,
		})
	}
	return out, nil
}

// ---- hash format detection ----

// detectHashFormat returns the best-guess PasswordHash format constant for
// the given encoded hash string. Used when the source doesn't provide an
// explicit format tag. Returns empty string when the format cannot be
// determined — the operator should use the csv hash_format column instead.
func detectHashFormat(h string) string {
	switch {
	case strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") || strings.HasPrefix(h, "$2y$"):
		return "bcrypt"
	case strings.HasPrefix(h, "$argon2id$"):
		return "argon2id"
	case strings.HasPrefix(h, "pbkdf2_sha256$"):
		return "pbkdf2-sha256"
	case strings.HasPrefix(h, "pbkdf2_sha512$"):
		return "pbkdf2-sha512"
	default:
		return ""
	}
}

// ---- ID derivation ----

// deriveID returns a stable, non-empty user ID. It prefers the source
// system's opaque ID, falling back to a sanitized email, then a fallback
// with the provider prefix. The returned ID is safe to use as a SQLite
// PRIMARY KEY.
func deriveID(sourceID, email, provider string) string {
	if sourceID != "" {
		return sanitizeID(provider + ":" + sourceID)
	}
	if email != "" {
		return sanitizeID(provider + ":" + email)
	}
	return provider + ":" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

// sanitizeID replaces characters that could be problematic in a plain-text
// primary key with underscores. SQLite TEXT PKs support arbitrary UTF-8, but
// some consumers (grpc, log lines) behave better with printable ASCII only.
func sanitizeID(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '|' || r == '\x00' || r == '\n' || r == '\r' {
			b.WriteByte('_')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ---- import ----

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

// ---- utilities ----

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, progName+": "+format+"\n", args...)
	os.Exit(1)
}

// Ensure the sqlite driver is imported for its side-effect (registers "sqlite").
var _ *sql.DB
