package authenticators

import "time"

// Provider names returned from each Authenticator.Name().
const (
	MethodPassword    = "password"
	MethodPhone       = "phone"
	MethodEmail       = "email"
	MethodMagicLink   = "magiclink"
	MethodTempToken   = "temp_token"
	MethodKeyPair     = "keypair"
	MethodAPIKey      = "apikey"
	MethodCertificate = "certificate"
	MethodTOTP        = "totp"
	MethodOIDCFed     = "oidc_federation"
)

// AuthMethod tags placed on AuthResult.AuthMethods (used by relying parties to
// implement step-up auth, ACR/AMR claims, audit logs).
const (
	AuthMethodPwd      = "pwd"
	AuthMethodSMS      = "sms"
	AuthMethodEmailOTP = "email_otp"
	AuthMethodOTPLink  = "otp_link"
	AuthMethodSig      = "sig"
	AuthMethodAPIKey   = "api_key"
	AuthMethodX509     = "x509"
	AuthMethodOTP      = "otp" // RFC 8176 §2: generic OTP (TOTP / HOTP)
	AuthMethodFed      = "fed" // upstream IdP federation (Google / Microsoft / GitHub / generic OIDC)
)

// CodeStore key prefixes — kept distinct so a single shared store can hold
// codes for different channels without collision.
const (
	keyPrefixPhone = "phone:"
	keyPrefixEmail = "email:"
	// keyPrefixMagicLink is deliberately distinct from keyPrefixEmail: a magic
	// link and an email-OTP code can be requested for the same address around
	// the same time (both share the same CodeStore/email), and each flow must
	// verify only its OWN pending value — sharing a namespace would let one
	// flow silently invalidate or satisfy the other.
	keyPrefixMagicLink = "magiclink:"
)

// Replay-store key prefixes — namespace the optional JTIReplayStore seams so a
// single shared replay backend can hold entries for several authenticators
// without one authenticator's key colliding with another's.
const (
	subjectPrefixTOTPConsumed = "totp:"
)

// Subject ID prefixes used when an authenticator must synthesize one.
const (
	subjectPrefixPhone   = "phone:"
	subjectPrefixEmail   = "email:"
	subjectPrefixKeyPair = "key:"
	subjectPrefixAPIKey  = "apikey:"
	subjectPrefixCert    = "cert:"
)

// Defaults applied when an option is not provided.
const (
	DefaultCodeLength       = 6
	DefaultPhoneCodeTTL     = 5 * time.Minute
	DefaultEmailCodeTTL     = 10 * time.Minute
	DefaultTempTokenTTL     = 15 * time.Minute
	DefaultTempTokenBytes   = 32
	DefaultKeyPairClockSkew = 5 * time.Minute
	// DefaultMagicLinkTokenBytes is the crypto/rand BYTE length of the opaque
	// magic-link token before base64url encoding (matches DefaultTempTokenBytes
	// — the same construction TempTokenAuthenticator already uses for
	// single-use bearer tokens): 256 bits, well above the entropy a short
	// human-typed OTP needs, appropriate for a value that travels unattended
	// inside a URL rather than being read aloud/typed by a person.
	DefaultMagicLinkTokenBytes = 32
	// DefaultMagicLinkTTL is longer than DefaultEmailCodeTTL: a link is
	// checked/clicked (mail delivery + the user finding and opening the
	// message) rather than typed back immediately, so it needs more slack.
	DefaultMagicLinkTTL = 15 * time.Minute
)

// keyPairMessageSeparator joins the canonical fields signed by a keypair client.
const keyPairMessageSeparator = "|"

// numericDigits is the alphabet used by GenerateNumericCode.
const numericDigits = "0123456789"
