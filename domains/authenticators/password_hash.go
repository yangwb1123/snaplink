package authenticators

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Hash format identifiers. The Format field of PasswordHash MUST be one of
// these constants; unknown values are rejected at verify time (fail-loud).
const (
	HashFormatBcrypt       = "bcrypt"
	HashFormatArgon2id     = "argon2id"
	HashFormatPBKDF2SHA256 = "pbkdf2-sha256"
	HashFormatPBKDF2SHA512 = "pbkdf2-sha512"
)

// Hasher knows the cryptographic cost parameter used to hash passwords.
// Implementations return the current bcrypt cost, which callers (e.g.
// StoredHashVerifier) use to match the miss-path dummy hash cost to the
// hit-path cost, preventing a timing oracle on unknown usernames.
type Hasher interface {
	// Cost returns the bcrypt cost used for new hashes. Must be >=
	// bcrypt.MinCost and <= bcrypt.MaxCost when valid; a zero or
	// out-of-range value causes callers to fall back to their default.
	Cost() int
}

// bcryptHasher is a simple Hasher backed by a fixed bcrypt cost.
type bcryptHasher struct{ cost int }

// NewBcryptHasher returns a Hasher that reports the given bcrypt cost.
func NewBcryptHasher(cost int) Hasher { return &bcryptHasher{cost: cost} }

func (h *bcryptHasher) Cost() int { return h.cost }

// PasswordHash holds a stored hash with its format identifier.
// The Hash field is the full encoded string in the format-specific encoding:
//
//   - bcrypt:        "$2a$...", "$2b$...", "$2y$..."
//   - argon2id:      "$argon2id$v=19$m=<m>,t=<t>,p=<p>$<salt-b64>$<hash-b64>"
//   - pbkdf2-sha256: "pbkdf2_sha256$<iterations>$<salt-b64>$<hash-b64>"
//   - pbkdf2-sha512: "pbkdf2_sha512$<iterations>$<salt-b64>$<hash-b64>"
type PasswordHash struct {
	Format string // one of the HashFormat* constants
	Hash   string // full encoded hash string
}

// IsBcrypt reports whether h is stored as a bcrypt hash.
// Used by LazyRehashVerifier.NeedsRehash to decide if an upgrade is warranted.
func (h PasswordHash) IsBcrypt() bool {
	return h.Format == HashFormatBcrypt
}

// VerifyHash checks plaintext against a stored PasswordHash.
// Returns nil on match, a descriptive non-nil error on mismatch or any
// structural failure (bad encoding, unsupported format, invalid parameters).
//
// Timing guarantees:
//   - bcrypt:         constant-time by design (bcrypt.CompareHashAndPassword).
//   - argon2id:       constant-time via subtle.ConstantTimeCompare after derivation.
//   - pbkdf2-*:       constant-time via hmac.Equal after derivation.
//   - unknown format: returns an error immediately; the format tag reveals
//     nothing useful about the plaintext so there is no timing oracle.
func VerifyHash(_ context.Context, h PasswordHash, plaintext string) error {
	switch h.Format {
	case HashFormatBcrypt:
		return verifyBcrypt(h.Hash, plaintext)
	case HashFormatArgon2id:
		return verifyArgon2id(h.Hash, plaintext)
	case HashFormatPBKDF2SHA256:
		return verifyPBKDF2(h.Hash, plaintext, sha256.New, 32)
	case HashFormatPBKDF2SHA512:
		return verifyPBKDF2(h.Hash, plaintext, sha512.New, 64)
	default:
		return fmt.Errorf("password_hash: unsupported format %q", h.Format)
	}
}

// HashPassword produces a bcrypt PasswordHash for plaintext at DefaultCost.
// Used by LazyRehashVerifier when upgrading a legacy hash on first login.
func HashPassword(plaintext string) (PasswordHash, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return PasswordHash{}, fmt.Errorf("password_hash: bcrypt generate: %w", err)
	}
	return PasswordHash{Format: HashFormatBcrypt, Hash: string(b)}, nil
}

// --- bcrypt ---

func verifyBcrypt(encoded, plaintext string) error {
	err := bcrypt.CompareHashAndPassword([]byte(encoded), []byte(plaintext))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return errors.New("password_hash: bcrypt: credential mismatch")
	}
	if err != nil {
		return fmt.Errorf("password_hash: bcrypt: %w", err)
	}
	return nil
}

// --- argon2id ---
//
// Encoded format (PHC string): $argon2id$v=19$m=<m>,t=<t>,p=<p>$<salt-b64>$<hash-b64>
// where salt and hash are base64 without padding, matching the encoding
// produced by Python passlib, spring-security, and go-argon2.

func verifyArgon2id(encoded, plaintext string) error {
	m, t, p, salt, storedHash, err := parseArgon2id(encoded)
	if err != nil {
		return fmt.Errorf("password_hash: argon2id: %w", err)
	}
	derived := argon2.IDKey([]byte(plaintext), salt, t, m, p, uint32(len(storedHash)))
	if subtle.ConstantTimeCompare(derived, storedHash) != 1 {
		return errors.New("password_hash: argon2id: credential mismatch")
	}
	return nil
}

func parseArgon2id(encoded string) (m, t uint32, p uint8, salt, hashBytes []byte, err error) {
	// Expected: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
	// parts[0]="" [1]="argon2id" [2]="v=19" [3]="m=...,t=...,p=..." [4]=salt [5]=hash
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		err = errors.New("malformed argon2id hash: expected 6 $-delimited fields with argon2id identifier")
		return
	}
	if !strings.HasPrefix(parts[2], "v=") {
		err = errors.New("argon2id: missing version field")
		return
	}
	v, convErr := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if convErr != nil || v != 19 {
		err = fmt.Errorf("argon2id: unsupported version %q (only v=19 supported)", parts[2])
		return
	}
	m, t, p, err = parseArgon2Params(parts[3])
	if err != nil {
		return
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		err = fmt.Errorf("argon2id: decode salt: %w", err)
		return
	}
	hashBytes, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		err = fmt.Errorf("argon2id: decode hash: %w", err)
	}
	return
}

func parseArgon2Params(s string) (m, t uint32, p uint8, err error) {
	// "m=65536,t=3,p=4"
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			err = fmt.Errorf("argon2id: malformed param %q", kv)
			return
		}
		n, convErr := strconv.ParseUint(v, 10, 32)
		if convErr != nil {
			err = fmt.Errorf("argon2id: param %q value %q: %w", k, v, convErr)
			return
		}
		switch k {
		case "m":
			m = uint32(n)
		case "t":
			t = uint32(n)
		case "p":
			if n > 255 {
				err = fmt.Errorf("argon2id: p=%d exceeds uint8 range", n)
				return
			}
			p = uint8(n)
		}
	}
	if m == 0 || t == 0 || p == 0 {
		err = errors.New("argon2id: params m, t, and p must all be non-zero")
	}
	return
}

// EncodeArgon2id produces a PHC-format argon2id hash for plaintext.
// Exported for use in migration tooling and test vector generation.
func EncodeArgon2id(plaintext string, memory, time uint32, threads uint8, keyLen uint32) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password_hash: argon2id: generate salt: %w", err)
	}
	h := argon2.IDKey([]byte(plaintext), salt, time, memory, threads, keyLen)
	encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, time, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(h),
	)
	return encoded, nil
}

// --- PBKDF2 ---
//
// Encoded format: <algo>$<iterations>$<salt-b64>$<hash-b64>
// where algo is "pbkdf2_sha256" or "pbkdf2_sha512", and salt/hash are
// standard base64 (WITH padding) — matching Django / Keycloak / Auth0 exports.
//
// The leading algo tag is already captured in PasswordHash.Format; the
// encoded string repeats it to remain self-describing (some IdP exports omit
// the algo prefix, so both are accepted during parsing).

func verifyPBKDF2(encoded, plaintext string, newHash func() hash.Hash, hashLen int) error {
	iter, salt, storedHash, err := parsePBKDF2(encoded)
	if err != nil {
		return fmt.Errorf("password_hash: pbkdf2: %w", err)
	}
	derived := pbkdf2Key([]byte(plaintext), salt, iter, hashLen, newHash)
	if !hmac.Equal(derived, storedHash) {
		return errors.New("password_hash: pbkdf2: credential mismatch")
	}
	return nil
}

func parsePBKDF2(encoded string) (iterations int, salt, hashBytes []byte, err error) {
	// "pbkdf2_sha256$260000$<salt>$<hash>" — 4 $-separated fields.
	// Some exports omit the algorithm prefix, giving 3 fields. We accept both.
	parts := strings.SplitN(encoded, "$", 4)
	var iterStr, saltStr, hashStr string
	switch len(parts) {
	case 4:
		// parts[0] = algo, parts[1] = iterations, parts[2] = salt, parts[3] = hash
		iterStr, saltStr, hashStr = parts[1], parts[2], parts[3]
	case 3:
		// parts[0] = iterations, parts[1] = salt, parts[2] = hash
		iterStr, saltStr, hashStr = parts[0], parts[1], parts[2]
	default:
		err = errors.New("malformed pbkdf2 hash: expected 3 or 4 $-separated fields")
		return
	}
	iterations, err = strconv.Atoi(iterStr)
	if err != nil || iterations <= 0 {
		err = fmt.Errorf("pbkdf2: invalid iteration count %q", iterStr)
		return
	}
	// Try standard base64 first (Django/Keycloak), then raw (no-padding variant).
	salt, err = base64.StdEncoding.DecodeString(saltStr)
	if err != nil {
		salt, err = base64.RawStdEncoding.DecodeString(saltStr)
		if err != nil {
			err = fmt.Errorf("pbkdf2: decode salt: %w", err)
			return
		}
	}
	hashBytes, err = base64.StdEncoding.DecodeString(hashStr)
	if err != nil {
		hashBytes, err = base64.RawStdEncoding.DecodeString(hashStr)
		if err != nil {
			err = fmt.Errorf("pbkdf2: decode hash: %w", err)
		}
	}
	return
}

// pbkdf2Key implements PBKDF2 (RFC 2898 §5.2) using only the standard library.
// golang.org/x/crypto/pbkdf2 would work identically but importing it here
// just for this would pull in that sub-package; the algorithm is short enough
// to inline.
//
//	DK = T_1 || T_2 || ...
//	T_i = U_1 XOR U_2 XOR ... XOR U_c
//	U_1 = PRF(Password, Salt || INT(i))
//	U_j = PRF(Password, U_{j-1})
func pbkdf2Key(password, salt []byte, iter, keyLen int, newHash func() hash.Hash) []byte {
	prf := hmac.New(newHash, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	buf := make([]byte, len(salt)+4)
	copy(buf, salt)

	for block := 1; block <= numBlocks; block++ {
		buf[len(salt)] = byte(block >> 24)
		buf[len(salt)+1] = byte(block >> 16)
		buf[len(salt)+2] = byte(block >> 8)
		buf[len(salt)+3] = byte(block)

		prf.Reset()
		prf.Write(buf)
		U = prf.Sum(U[:0])

		T := make([]byte, hashLen)
		copy(T, U)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = prf.Sum(U[:0])
			for x := range T {
				T[x] ^= U[x]
			}
		}
		dk = append(dk, T...)
	}
	return dk[:keyLen]
}

// EncodePBKDF2SHA256 produces a Django-compatible pbkdf2_sha256 encoded string.
// Exported for use in migration tooling and test vector generation.
func EncodePBKDF2SHA256(plaintext string, iterations int) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password_hash: pbkdf2-sha256: generate salt: %w", err)
	}
	dk := pbkdf2Key([]byte(plaintext), salt, iterations, 32, sha256.New)
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s",
		iterations,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(dk),
	), nil
}
