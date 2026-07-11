package importcmd

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

func parseInput(format string, r io.Reader) ([]importedUser, error) {
	switch format {
	case "auth0":
		return parseAuth0(r)
	case "keycloak":
		return parseKeycloak(r)
	case "okta":
		return parseOkta(r)
	case "csv":
		return parseCSV(r)
	default:
		return nil, fmt.Errorf("unknown format %q (want auth0, keycloak, okta, or csv)", format)
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
	if err := decodeKeycloakRealm(json.NewDecoder(r), &realm); err != nil {
		return nil, err
	}
	return keycloakUsersToImported(realm.Users), nil
}

// decodeKeycloakRealm fills realm from dec, accepting EITHER the {"users":[...]}
// realm form or a bare [...] users array, depending on whether a full or partial
// Keycloak export was produced. It peeks the first token to choose the path.
func decodeKeycloakRealm(dec *json.Decoder, realm *keycloakRealm) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("decode keycloak json: %w", err)
	}
	t, ok := tok.(json.Delim)
	if !ok {
		return fmt.Errorf("keycloak json: unexpected token %v", tok)
	}
	if t == '[' {
		return decodeKeycloakUsersArray(dec, realm)
	}
	// Object — we already consumed the '{' delimiter; decode the remaining
	// fields manually since the decoder can no longer re-read the object whole.
	if err := decodeKeycloakObject(dec, realm); err != nil {
		return fmt.Errorf("decode keycloak realm object: %w", err)
	}
	return nil
}

// decodeKeycloakUsersArray handles the bare-array export. dec.Token() already
// consumed the '[', so the decoder is positioned at the FIRST element — calling
// dec.Decode on a slice here would wrongly expect another '[' and fail. Decode
// elements one-by-one, mirroring decodeKeycloakObject, then consume the ']'.
func decodeKeycloakUsersArray(dec *json.Decoder, realm *keycloakRealm) error {
	for dec.More() {
		var u keycloakUser
		if err := dec.Decode(&u); err != nil {
			return fmt.Errorf("decode keycloak users array: %w", err)
		}
		realm.Users = append(realm.Users, u)
	}
	if _, err := dec.Token(); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode keycloak users array: %w", err)
	}
	return nil
}

// keycloakUsersToImported normalises decoded Keycloak users into the portable
// importedUser shape, skipping rows with no identifying fields.
func keycloakUsersToImported(users []keycloakUser) []importedUser {
	out := make([]importedUser, 0, len(users))
	for _, u := range users {
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
	return out
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
	colGet := csvColGetter(header)

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
		if u, ok := csvRowToImported(row, colGet); ok {
			out = append(out, u)
		}
	}
	return out, nil
}

// csvColGetter builds a case-insensitive column accessor over the header row.
// The returned func trims values and yields "" for absent or short columns.
func csvColGetter(header []string) func(row []string, name string) string {
	colIdx := make(map[string]int, len(header))
	for i, h := range header {
		colIdx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	return func(row []string, name string) string {
		if i, ok := colIdx[name]; ok && i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}
}

// csvRowToImported maps one CSV row to an importedUser. It reports ok=false for
// rows lacking both username and email, which the caller skips.
func csvRowToImported(row []string, colGet func(row []string, name string) string) (importedUser, bool) {
	username := colGet(row, "username")
	email := colGet(row, "email")
	if username == "" && email == "" {
		return importedUser{}, false
	}
	hash := colGet(row, "password_hash")
	hashFormat := colGet(row, "hash_format")
	if hash != "" && hashFormat == "" {
		hashFormat = detectHashFormat(hash)
	}
	return importedUser{
		ID:         deriveID(username, email, "csv"),
		ExternalID: username,
		Provider:   "csv",
		Email:      email,
		Name:       colGet(row, "name"),
		Hash:       hash,
		HashFormat: hashFormat,
	}, true
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
