package authenticators

import (
	"encoding/base32"
	"strings"

	"github.com/snaplink/sso/interfaces/sso"
)

// TOTPEnroller adapts this package's TOTP primitives + a TOTPAuthenticator's
// skew configuration to the sso.TOTPEnroller seam the server's self-service
// enrollment handlers call. The server cannot import this package directly
// (authenticators imports the server), so the dependency is inverted through
// that interface.
type TOTPEnroller struct {
	auth *TOTPAuthenticator
}

// NewTOTPEnroller wraps auth so its VerifyCode (and the package's secret
// primitives) back the /me/mfa/totp enrollment endpoints. Pass the SAME
// *TOTPAuthenticator that backs TOTP login so the configured skew window is
// shared and a newly enrolled factor verifies identically at login.
func NewTOTPEnroller(auth *TOTPAuthenticator) *TOTPEnroller {
	return &TOTPEnroller{auth: auth}
}

func (e *TOTPEnroller) GenerateSecret() ([]byte, error) { return GenerateTOTPSecret() }

func (e *TOTPEnroller) EncodeSecret(secret []byte) string { return EncodeTOTPSecret(secret) }

// DecodeSecret parses the base32-no-pad form (case-insensitive, whitespace-
// trimmed) the begin step handed out. Malformed input returns an error rather
// than panicking, so the confirm handler can collapse it to totp_invalid_code.
func (e *TOTPEnroller) DecodeSecret(encoded string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(strings.TrimSpace(encoded)))
}

func (e *TOTPEnroller) OTPAuthURI(issuer, account string, secret []byte) string {
	return OTPAuthURL(issuer, account, secret)
}

func (e *TOTPEnroller) VerifyCode(secret []byte, code string) bool {
	return e.auth.VerifyCode(secret, code)
}

var _ sso.TOTPEnroller = (*TOTPEnroller)(nil)
