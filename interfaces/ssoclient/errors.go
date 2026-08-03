package ssoclient

import "errors"

// Facade-level error taxonomy for the AuthClient implementations.
//
// These sentinels are Go SDK errors, not wire codes: they are returned by
// ssoclient/local and ssoclient/remote and never surface on a server
// endpoint, so docs/error-codes.md is unaffected. A single facade-level
// sentinel per failure class lets App code write
// errors.Is(err, ssoclient.ErrAudienceMismatch) and behave identically
// regardless of which implementation backs the AuthClient — the point of
// the facade.
//
// The rs package keeps its own sentinels (rs.ErrIssuerMismatch etc.) and
// must not import this package; the duplication is deliberate and parity
// is test-enforced, not shared-code-enforced. Malformed/signature/expired
// failures stay plain per-implementation errors (pre-existing remote
// behavior); this file deliberately covers only the classes the two
// implementations must agree on.
var (
	// ErrIssuerRequired: remote.ValidateToken was called without the
	// WithIssuer option. Fail-closed config gate mirroring rs's ErrConfig
	// gate ("Issuer required", rs/validate.go) — the facade must not be
	// weaker than the rs layer it wraps.
	ErrIssuerRequired = errors.New("ssoclient: issuer required")

	// ErrIssuerMismatch: the token's `iss` claim differs from the
	// configured issuer. Exact string match (rs/claims.go). A missing
	// `iss` claim is the same class: "" never equals a configured issuer.
	ErrIssuerMismatch = errors.New("ssoclient: issuer mismatch")

	// ErrAudienceMismatch: the token's `aud` does not contain the
	// configured expected audience, or `aud` is missing. Containment
	// semantics mirror rs.Config.ExpectedAud (rs/claims.go); the gate is
	// skipped entirely when no expectation is configured.
	ErrAudienceMismatch = errors.New("ssoclient: audience mismatch")

	// ErrLogoutNotConfigured: Logout received a field whose capability is
	// not configured — an AccessToken without WithRevokeURL (remote) or
	// a SessionID without WithLogoutURL (remote) / WithSessionManager
	// (local). Replaces the former silent no-op: Logout never claims
	// success when no revocation request was sent.
	ErrLogoutNotConfigured = errors.New("ssoclient: logout not configured")
)
