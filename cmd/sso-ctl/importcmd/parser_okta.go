package importcmd

// --- Okta ---
//
// Okta user export: either the JSON array returned by GET /api/v1/users or an
// NDJSON stream of the same user objects (one per line), the framing that
// streaming export tooling (e.g. Advanced Server Access) produces. Relevant
// fields: id, profile.{login,email,firstName,lastName}, and the hashed
// password import object credentials.password.hash{algorithm, workFactor,
// salt, saltOrder, value, iterationCount, keySize, digestAlgorithm}.
//
// Reference: https://developer.okta.com/docs/reference/api/users/
// (Hashed Password object).

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type oktaUser struct {
	ID          string          `json:"id"`
	Profile     oktaProfile     `json:"profile"`
	Credentials oktaCredentials `json:"credentials"`
}

type oktaProfile struct {
	Login     string `json:"login"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type oktaCredentials struct {
	Password *oktaPassword `json:"password"`
}

type oktaPassword struct {
	Hash *oktaPasswordHash `json:"hash"`
}

// oktaPasswordHash is Okta's hashed-password object. Salt is bcrypt's own
// radix-64 alphabet for BCRYPT and standard base64 for PBKDF2. SaltOrder
// (PREFIX/POSTFIX) only applies to the salted-digest algorithms (SHA-*/MD5),
// which the server's verifier matrix has no support for — it is decoded so
// the field round-trips in tooling but never used.
type oktaPasswordHash struct {
	Algorithm       string `json:"algorithm"`
	WorkFactor      int    `json:"workFactor"`
	Salt            string `json:"salt"`
	SaltOrder       string `json:"saltOrder"`
	Value           string `json:"value"`
	IterationCount  int    `json:"iterationCount"`
	KeySize         int    `json:"keySize"`
	DigestAlgorithm string `json:"digestAlgorithm"`
}

func parseOkta(r io.Reader) ([]importedUser, error) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("decode okta json: %w", err)
	}
	var raw []oktaUser
	if d, ok := tok.(json.Delim); ok && d == '[' {
		raw, err = decodeOktaArray(dec)
	} else {
		raw, err = decodeOktaNDJSON(dec, tok)
	}
	if err != nil {
		return nil, err
	}
	return oktaUsersToImported(raw)
}

// decodeOktaArray handles the '[...]' framing. The caller already consumed
// the '[' token, so — exactly like decodeKeycloakUsersArray — the decoder is
// positioned at the FIRST element and elements must be decoded one-by-one,
// then the trailing ']' consumed.
func decodeOktaArray(dec *json.Decoder) ([]oktaUser, error) {
	var out []oktaUser
	for dec.More() {
		var u oktaUser
		if err := dec.Decode(&u); err != nil {
			return nil, fmt.Errorf("decode okta users array: %w", err)
		}
		out = append(out, u)
	}
	if _, err := dec.Token(); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode okta users array: %w", err)
	}
	return out, nil
}

// decodeOktaNDJSON handles newline-delimited (or otherwise concatenated)
// top-level user objects. The framing probe consumed the first object's '{',
// so the first user is rebuilt from the token stream field-by-field
// (mirroring decodeKeycloakObject); the remaining objects decode whole —
// json.Decoder natively reads concatenated values, no line splitting needed.
func decodeOktaNDJSON(dec *json.Decoder, first json.Token) ([]oktaUser, error) {
	if d, ok := first.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("okta json: unexpected token %v (want an array or object stream)", first)
	}
	u, err := decodeOktaOpenObject(dec)
	if err != nil {
		return nil, fmt.Errorf("decode okta ndjson: %w", err)
	}
	out := []oktaUser{u}
	for {
		var next oktaUser
		if err := dec.Decode(&next); errors.Is(err, io.EOF) {
			return out, nil
		} else if err != nil {
			return nil, fmt.Errorf("decode okta ndjson: %w", err)
		}
		out = append(out, next)
	}
}

// decodeOktaOpenObject reads the key/value pairs of an object whose '{' was
// already consumed, re-marshals them, and unmarshals into oktaUser — the
// nested profile/credentials shapes make per-key manual assignment brittler
// than one rebuild round-trip.
func decodeOktaOpenObject(dec *json.Decoder) (oktaUser, error) {
	fields := make(map[string]json.RawMessage)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return oktaUser{}, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return oktaUser{}, fmt.Errorf("expected JSON string key, got %T", keyTok)
		}
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return oktaUser{}, err
		}
		fields[key] = val
	}
	if _, err := dec.Token(); err != nil && !errors.Is(err, io.EOF) { // consume '}'
		return oktaUser{}, err
	}
	blob, err := json.Marshal(fields)
	if err != nil {
		return oktaUser{}, err
	}
	var u oktaUser
	if err := json.Unmarshal(blob, &u); err != nil {
		return oktaUser{}, err
	}
	return u, nil
}

// oktaUsersToImported normalises decoded Okta users, skipping rows with no
// identifying fields (mirroring the other parsers). Unlike them it returns an
// error: an unmappable hash must abort the import, not silently produce a
// password-less user (see oktaHashToPortable).
func oktaUsersToImported(users []oktaUser) ([]importedUser, error) {
	out := make([]importedUser, 0, len(users))
	for _, u := range users {
		if u.ID == "" && u.Profile.Login == "" && u.Profile.Email == "" {
			continue
		}
		hash, format, err := oktaHashToPortable(oktaUserLabel(u), oktaHashOf(u))
		if err != nil {
			return nil, err
		}
		extID := u.ID
		if extID == "" {
			extID = u.Profile.Login
		}
		out = append(out, importedUser{
			ID:         deriveID(extID, u.Profile.Email, "okta"),
			ExternalID: extID,
			Provider:   "okta",
			Email:      u.Profile.Email,
			Name:       strings.TrimSpace(u.Profile.FirstName + " " + u.Profile.LastName),
			Hash:       hash,
			HashFormat: format,
		})
	}
	return out, nil
}

// oktaHashOf digs credentials.password.hash out of its two optional levels.
func oktaHashOf(u oktaUser) *oktaPasswordHash {
	if u.Credentials.Password == nil {
		return nil
	}
	return u.Credentials.Password.Hash
}

// oktaUserLabel names a user in per-record errors: login is Okta's canonical
// human identifier, with email/id fallbacks for partial records.
func oktaUserLabel(u oktaUser) string {
	if u.Profile.Login != "" {
		return u.Profile.Login
	}
	if u.Profile.Email != "" {
		return u.Profile.Email
	}
	return u.ID
}

// oktaHashToPortable maps Okta's hashed-password object onto the encodings
// domains/authenticators.VerifyHash parses. Unsupported algorithms (salted
// SHA-256/SHA-512/SHA-1/MD5) fail the parse loudly: importing a user whose
// hash the server can never verify would silently lock them out at login,
// which is strictly worse than making the operator re-export or accept a
// password reset for that cohort.
func oktaHashToPortable(label string, h *oktaPasswordHash) (hash, format string, err error) {
	if h == nil {
		return "", "", nil // no exported credential: import password-less
	}
	switch strings.ToUpper(strings.TrimSpace(h.Algorithm)) {
	case "BCRYPT":
		hash, err = oktaBcryptHash(label, h)
		if err != nil {
			return "", "", err
		}
		return hash, "bcrypt", nil
	case "PBKDF2":
		return oktaPBKDF2Hash(label, h)
	default:
		return "", "", fmt.Errorf(
			"okta user %q: unsupported hash algorithm %q (importable: BCRYPT, PBKDF2; the server verifies bcrypt, argon2id, pbkdf2-sha256, pbkdf2-sha512 — no salted-digest support)",
			label, h.Algorithm)
	}
}

// bcrypt modular-crypt layout: $2<minor>$<cost>$<22-char salt><31-char hash>,
// where both trailing fields use bcrypt's own radix-64 alphabet (./A-Za-z0-9
// — NOT standard base64). Okta splits that 53-char blob into salt (22 chars)
// and value (31 chars) plus workFactor, so reconstruction is pure
// concatenation with a zero-padded two-digit cost — no re-encoding.
const (
	oktaBcryptSaltLen = 22
	oktaBcryptHashLen = 31
)

func oktaBcryptHash(label string, h *oktaPasswordHash) (string, error) {
	// Some Okta exports carry the complete modular-crypt string in value.
	if strings.HasPrefix(h.Value, "$2") {
		return h.Value, nil
	}
	if len(h.Salt) != oktaBcryptSaltLen || len(h.Value) != oktaBcryptHashLen {
		return "", fmt.Errorf(
			"okta user %q: bcrypt import needs a %d-char radix-64 salt and %d-char value (got %d and %d) — cannot reconstruct a verifiable hash",
			label, oktaBcryptSaltLen, oktaBcryptHashLen, len(h.Salt), len(h.Value))
	}
	if h.WorkFactor < bcrypt.MinCost || h.WorkFactor > bcrypt.MaxCost {
		return "", fmt.Errorf("okta user %q: bcrypt workFactor %d outside %d..%d",
			label, h.WorkFactor, bcrypt.MinCost, bcrypt.MaxCost)
	}
	return fmt.Sprintf("$2a$%02d$%s%s", h.WorkFactor, h.Salt, h.Value), nil
}

// oktaPBKDF2Hash produces the Django-style "pbkdf2_shaN$iter$salt$hash"
// encoding that the server's PBKDF2 parser reads. Okta's salt/value are
// already standard base64, so they embed as-is. The verifier derives a
// FIXED-length key (32 bytes for SHA-256, 64 for SHA-512) and compares it to
// the decoded value, so any other key size can never verify — reject it here
// instead of locking the user out at login.
func oktaPBKDF2Hash(label string, h *oktaPasswordHash) (hash, format string, err error) {
	// Okta writes SHA256_HMAC / SHA512_HMAC; tolerate bare or dashed forms.
	digest := strings.ToUpper(strings.TrimSpace(h.DigestAlgorithm))
	digest = strings.ReplaceAll(strings.TrimSuffix(digest, "_HMAC"), "-", "")
	var prefix string
	var keyLen int
	switch digest {
	case "SHA256":
		prefix, keyLen, format = "pbkdf2_sha256", 32, "pbkdf2-sha256"
	case "SHA512":
		prefix, keyLen, format = "pbkdf2_sha512", 64, "pbkdf2-sha512"
	default:
		return "", "", fmt.Errorf("okta user %q: pbkdf2 digestAlgorithm %q unsupported (want SHA256 or SHA512)",
			label, h.DigestAlgorithm)
	}
	if h.IterationCount <= 0 {
		return "", "", fmt.Errorf("okta user %q: pbkdf2 iterationCount %d invalid", label, h.IterationCount)
	}
	if err := checkOktaPBKDF2Material(label, h, keyLen); err != nil {
		return "", "", err
	}
	return fmt.Sprintf("%s$%d$%s$%s", prefix, h.IterationCount, h.Salt, h.Value), format, nil
}

// checkOktaPBKDF2Material validates that salt/value decode as base64 (the
// verifier will decode them at every login) and that the stored derived key
// has the exact length the verifier derives.
func checkOktaPBKDF2Material(label string, h *oktaPasswordHash, keyLen int) error {
	if _, err := decodeOktaB64(h.Salt); err != nil {
		return fmt.Errorf("okta user %q: pbkdf2 salt is not base64: %v", label, err)
	}
	dk, err := decodeOktaB64(h.Value)
	if err != nil {
		return fmt.Errorf("okta user %q: pbkdf2 value is not base64: %v", label, err)
	}
	if len(dk) != keyLen {
		return fmt.Errorf(
			"okta user %q: pbkdf2 derived key is %d bytes but the server verifier derives %d (export keySize %d) — cannot import",
			label, len(dk), keyLen, h.KeySize)
	}
	return nil
}

// decodeOktaB64 mirrors the verifier's tolerance: standard base64 first,
// then the unpadded variant.
func decodeOktaB64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
