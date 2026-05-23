package sso

import (
	"context"
	"errors"
	"time"
)

// MFAProvider verifies a second factor on top of an already-validated
// primary credential. The SSO server invokes it from [Server.handleMFAComplete]
// when the configured [RiskScorer] returns [DecisionRequireMFA] and a
// provider is wired via [WithMFAProvider]. Without both, RequireMFA
// decays to Allow — the historical no-op behavior preserved for callers
// that pre-date MFA orchestration.
//
// Implementations are pluggable along the same SPI pattern as
// [Authenticator] and [RiskScorer]. A TOTP-backed default ships in
// [defaultimpl]; WebAuthn step-up is composable via the existing
// authenticators/webauthn Helper. Custom providers (push notification,
// hardware FIDO2, IdP step-up) implement the interface directly.
type MFAProvider interface {
	// SupportedMethods reports the factor method names this provider
	// can verify. Returned to the client in the mfa_required response
	// body so SPAs / mobile apps know which UI to render. Stable wire
	// strings (e.g. "totp", "webauthn"). Order is preserved into the
	// response — providers should list strongest factors first.
	SupportedMethods() []string

	// Verify checks one factor. subjectID is the user the primary
	// credential resolved to; method is one of SupportedMethods();
	// params is the method-specific payload (totp: {"code": "..."};
	// webauthn: {"assertion": "..."}).
	//
	// Return nil on success; any non-nil error is treated as a
	// verification failure and audited as mfa_failure with the
	// error string in the audit Reason. Errors are intentionally
	// collapsed to a single mfa_invalid wire response so probes
	// cannot distinguish "wrong code" from "method unsupported"
	// from "user not enrolled" (the same oracle-leak hardening
	// pattern enforced across the rest of the server).
	Verify(ctx context.Context, subjectID, method string, params map[string]string) error
}

// MFABeginner is an optional interface [MFAProvider] implementations
// satisfy when their factor requires server-side state before the
// client can construct the /auth/mfa response. The canonical example
// is WebAuthn — the client cannot sign an assertion until the server
// has chosen a fresh per-ceremony challenge and bound it to a session.
//
// When wired, the SSO server calls Begin during the mfa_required
// response construction (after challenge persistence, before writing
// the response). The returned map is forwarded to the client under
// the response's mfa_method_data["<method>"] bucket; clients echo
// the relevant keys back into the /auth/mfa params payload so the
// provider's Verify can resume the ceremony.
//
// Providers that don't need server-side setup (TOTP, simple OTP, an
// IdP redirect that the client initiates itself) MUST NOT implement
// this interface — the SSO server type-asserts so unimplemented is
// the default. Begin failures are non-fatal: the method is still
// listed in mfa_methods, just without an attached method_data entry
// (client can retry the Begin out-of-band if it wants).
//
// Begin MUST be safe to call before any user interaction has
// occurred for the method — the user picks which method they want
// AFTER seeing the mfa_required response, so the server pre-issues
// for every method whose provider supports Begin. Bounded resource
// consumption is the implementer's responsibility.
type MFABeginner interface {
	Begin(ctx context.Context, subjectID, method string) (map[string]string, error)
}

// MFAChallenge is the persisted in-flight MFA state between the
// initial /auth/login response (which returns mfa_required + the
// challenge ID) and the /auth/mfa completion call. Bound to a single
// (SubjectID, ClientID) pair, single-use, short-lived.
//
// The RequestState bytes are opaque to backends — the SSO server
// JSON-encodes the original login request + AuthResult so the post-MFA
// resume can mint the same response the no-MFA path would have minted.
// Backends just persist + return the blob unchanged.
type MFAChallenge struct {
	// ID is the opaque challenge identifier returned in the mfa_required
	// response. crypto/rand-derived (256 bits, base64url-encoded without
	// padding for URL-safe transport), single-use, anti-enumeration.
	ID string

	// SubjectID is the user the primary credential resolved to. Stored
	// for backend-side filter / operator debug only — the resume path
	// reads it from the decoded RequestState, not this field.
	SubjectID string

	// ClientID is the OAuth client the challenge was issued for. Same
	// storage-side use as SubjectID.
	ClientID string

	// CreatedAt + ExpiresAt are stored unix nanos in SQLite, time.Time
	// in memory. Stores prune expired entries lazily; the SSO server
	// treats any Consume past ExpiresAt as a miss collapsed to the
	// standard mfa_invalid wire response.
	CreatedAt time.Time
	ExpiresAt time.Time

	// RequestState is the JSON-encoded resume state (loginRequest +
	// AuthResult + assessment metadata). Opaque to MFAChallengeStore
	// backends — they persist the bytes verbatim and the SSO server
	// owns the schema.
	RequestState []byte
}

// MFAChallengeStore persists in-flight MFA challenges with single-use
// Consume semantics — same race-free atomic-delete-and-return pattern
// oauth.AuthCodeStore / oauth.DeviceCodeStore / oauth.PARStore enforce. Memory and
// SQLite peers ship in defaultimpl + defaultimpl/sqlite.
type MFAChallengeStore interface {
	// Put persists a freshly-issued challenge. c.ID + c.ExpiresAt
	// MUST be set by the caller. Returns nil on success.
	Put(ctx context.Context, c *MFAChallenge) error

	// Consume atomically deletes and returns the challenge with the
	// matching ID. Missing, expired, or already-consumed entries all
	// MUST return ErrMFAChallengeNotFound (single wire response per
	// the oracle-leak hardening contract).
	Consume(ctx context.Context, id string) (*MFAChallenge, error)
}

// ErrMFAChallengeNotFound is the sentinel MFAChallengeStore.Consume
// returns when an ID is missing, expired, or already-consumed.
// Callers MUST collapse all three cases to one wire response.
var ErrMFAChallengeNotFound = errors.New("sso: mfa challenge not found")

// DefaultMFAChallengeTTL is the default lifetime of an issued
// MFAChallenge when the server isn't given an explicit one. Five
// minutes balances UX (operators on shared devices reading a TOTP
// code, swapping to /auth/mfa UI) against attacker brute-force window
// (a 6-digit TOTP at 6 codes/30s burns through the space in ~83 days
// of nonstop attempts — five minutes keeps the per-challenge work
// factor irrelevant).
const DefaultMFAChallengeTTL = 5 * time.Minute
