package authenticators

import "time"

// Provider names returned from each Authenticator.Name().
const (
	MethodPassword    = "password"
	MethodPhone       = "phone"
	MethodEmail       = "email"
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
)

// keyPairMessageSeparator joins the canonical fields signed by a keypair client.
const keyPairMessageSeparator = "|"

// numericDigits is the alphabet used by GenerateNumericCode.
const numericDigits = "0123456789"
