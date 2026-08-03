package rs

import "errors"

// Error taxonomy: every validation failure wraps exactly one of these
// sentinels, so callers branch with errors.Is instead of string matching.
// These are Go SDK errors, NOT wire codes — the wire vocabulary of the RS
// middleware stays the standard RFC 6750 `invalid_token` /
// `insufficient_scope` challenge, deliberately collapsing the detailed cause
// so the 401 never becomes a token-validation oracle.
var (
	// ErrConfig marks a Config that cannot support the requested operation
	// (missing Issuer, no key source for local mode, no IntrospectURL for
	// remote mode).
	ErrConfig = errors.New("rs: invalid config")

	// ErrTokenMalformed covers everything that fails before claims can even
	// be read: not a 3-segment JWS, undecodable segments, missing REQUIRED
	// claims (RFC 9068 §2.2).
	ErrTokenMalformed = errors.New("rs: token malformed")

	// ErrTokenTypeMismatch rejects a JWT whose header typ is not the RFC
	// 9068 access-token type — a structurally valid ID/logout/SET token
	// presented as an access token.
	ErrTokenTypeMismatch = errors.New("rs: token typ is not an access token")

	// ErrSignatureInvalid covers key resolution and signature verification
	// failures, INCLUDING an alg outside the allowlist — one sentinel for
	// the whole class so a caller cannot accidentally build an oracle that
	// distinguishes "unknown kid" from "bad signature".
	ErrSignatureInvalid = errors.New("rs: token signature invalid")

	// ErrIssuerMismatch: `iss` differs from Config.Issuer.
	ErrIssuerMismatch = errors.New("rs: issuer mismatch")

	// ErrAudienceMismatch: `aud` does not contain Config.ExpectedAud.
	ErrAudienceMismatch = errors.New("rs: audience mismatch")

	// ErrServingRegionMismatch: the token's `serving_region` is missing or
	// not in Config.AllowedServingRegions — a governance denial
	// (region-constrained deployment), NOT a token-validity failure. The
	// middleware maps it to 403 region_not_allowed without a bearer
	// challenge, mirroring the AS's two-code discipline. A token without
	// the claim fails CLOSED when the allowlist is configured.
	ErrServingRegionMismatch = errors.New("rs: serving region mismatch")

	// ErrTokenExpired: `exp` is in the past beyond the skew tolerance.
	ErrTokenExpired = errors.New("rs: token expired")

	// ErrTokenNotYetValid: `nbf` (or `iat`) is in the future beyond the
	// skew tolerance.
	ErrTokenNotYetValid = errors.New("rs: token not yet valid")

	// ErrTokenInactive: the introspection endpoint answered
	// {"active": false} — revoked, expired, or never issued (RFC 7662
	// deliberately does not say which).
	ErrTokenInactive = errors.New("rs: token inactive")

	// ErrIntrospection: the introspection round-trip itself failed
	// (transport error, non-200, unparseable body). Distinct from
	// ErrTokenInactive so callers can choose their fail mode for AS
	// outages.
	ErrIntrospection = errors.New("rs: introspection request failed")

	// ErrDPoPInvalid covers every RFC 9449 proof failure: malformed proof,
	// bad signature, htm/htu mismatch, stale iat, missing ath binding,
	// thumbprint != cnf.jkt, or a cnf-bound token presented without a
	// proof.
	ErrDPoPInvalid = errors.New("rs: dpop proof invalid")

	// ErrDPoPReplayed: the proof jti was already seen inside its
	// acceptance window.
	ErrDPoPReplayed = errors.New("rs: dpop proof replayed")

	// ErrInsufficientScope: an authz helper found a required scope absent.
	ErrInsufficientScope = errors.New("rs: insufficient scope")

	// ErrSubjectMissing: RequireSubject found no `sub` claim (e.g. a
	// client_credentials token reaching a user-only endpoint).
	ErrSubjectMissing = errors.New("rs: subject missing")
)
