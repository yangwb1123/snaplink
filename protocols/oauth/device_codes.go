package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"strings"
)

// UserCodeAlphabet is the human-friendly user_code alphabet — base32
// minus easily-confused glyphs (0/O, 1/I/L). Matches the alphabet
// defaultimpl uses for cross-store consistency.
const UserCodeAlphabet = "BCDFGHJKMNPQRSTVWXYZ23456789"

// GenerateDeviceCode mints a 32-byte base64url device_code per
// RFC 8628 §3.2. Length chosen for 192-bit collision resistance.
func GenerateDeviceCode() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// GenerateUserCode mints an 8-char dashed user_code (XXXX-XXXX) from
// the ambiguous-glyph-free alphabet. ~40 bits of entropy — enough
// for short-lived single-use codes whose verification endpoint is
// already throttled.
func GenerateUserCode() (string, error) {
	const length = 8
	out := make([]byte, length)
	for i := range length {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(UserCodeAlphabet))))
		if err != nil {
			return "", err
		}
		out[i] = UserCodeAlphabet[n.Int64()]
	}
	return string(out[:4]) + "-" + string(out[4:]), nil
}

// NormalizeUserCode strips dashes + uppercases for lookup tolerance —
// users mistype the format but rarely the characters themselves.
func NormalizeUserCode(s string) string {
	return strings.ToUpper(strings.ReplaceAll(s, "-", ""))
}
