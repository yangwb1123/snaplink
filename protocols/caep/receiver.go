package caep

import (
	"context"
	"encoding/json"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/security"
)

// The CAEP/SSF RECEIVER — the inbound half of OpenID Shared Signals.
//
// Where the Transmitter PUSHES signed Security Event Tokens (SETs) to
// relying parties, the Receiver CONSUMES SETs delivered by CONFIGURED
// trusted upstream transmitters (e.g. an upstream IdP this server
// federates from, or a peer SSO in a mesh) and acts on them by revoking
// the affected subject's LOCAL access. It is the SSF "push" delivery
// receiver (RFC 8935): an HTTP endpoint accepting a compact-JWS SET in
// the request body.
//
// # Security model (this is a revocation primitive driven by an EXTERNAL
// party, so every gate below is load-bearing)
//
//   - ONLY a SET signed by a CONFIGURED trusted transmitter can ever
//     trigger a revocation. The SET's `iss` MUST be in the operator's
//     trusted-transmitter allowlist, and its signature MUST verify
//     against THAT transmitter's published JWKS via the shared
//     security.VerifyCompactJWS (asymmetric-only, alg=none-blocked,
//     alg-confusion-safe — the SAME primitive the SPIFFE JWT-SVID path
//     uses). A forged / unsigned / wrong-key / untrusted-iss SET is
//     rejected and triggers NOTHING.
//   - aud-binding: the SET's `aud` MUST contain THIS server's configured
//     audience. A SET addressed to a DIFFERENT receiver MUST NOT act here
//     (a lax aud would let a SET legitimately minted for receiver-B be
//     replayed to revoke users at receiver-A — cross-receiver replay).
//   - jti replay: the SET's `jti` is consumed through the JTIReplayStore
//     (MarkSeen). A replayed SET (same jti within its lifetime) MUST NOT
//     re-trigger a revocation. Fail-closed: a SET already seen is rejected.
//   - temporal freshness: a SET MUST carry at least one of `iat`/`exp`,
//     bounded by a configurable skew — a stale/expired SET is rejected (it
//     widens the replay window and a late-delivered revocation signal has no
//     use), and a SET with NO temporal claim is rejected outright (it would
//     skip freshness entirely AND, lacking exp, replay indefinitely past the
//     default jti window).
//   - subject mapping PRECISION (the other crux): the SET's subject is
//     mapped to a LOCAL user via an explicit, configured strategy. A
//     subject that does NOT map to a KNOWN local user is a NO-OP (acked,
//     never acted on) — revoking a guessed / partial-match subject would
//     be wrongful revocation, i.e. a targeted denial-of-service against
//     whoever the attacker can make the subject string resolve to.
//
// Once a SET is FULLY validated AND its subject maps to a local user, the
// action is fail-TOWARD-revoking: revoking local access is the safe
// direction, so a downstream store error during the revoke is surfaced
// (the caller decides) but the validated intent stands. Validation itself
// is strictly fail-CLOSED: any failure → no action.
//
// # Acknowledgement semantics (RFC 8935)
//
// A VALID SET is ACKED (the transmitter did its job) even when it maps to
// no local subject or carries only unknown event types — the receiver
// simply has nothing to do. Only a MALFORMED / UNSIGNED / UNTRUSTED-iss /
// WRONG-aud / EXPIRED / REPLAYED SET is an error. The error is oracle-safe:
// it does not reveal WHICH check failed beyond the SSF-standard codes.
//
// # Dependency-free
//
// The Receiver reuses security.VerifyCompactJWS (signature), the existing
// security.JTIReplayStore (replay), and the existing revocation seams
// (SubjectRevoker over SessionManager + RefreshTokenSubjectIndex). No new
// dependency; the package import graph stays core + audit + security.

// SubjectMapMode selects how a SET's subject identifier is mapped onto a
// LOCAL user id. The mapping is the security crux of the receiver: it MUST
// be precise (a mismatch is wrongful revocation), so the strategy is an
// EXPLICIT operator choice per trusted transmitter, never a guess.
type SubjectMapMode int

const (
	// SubjectMapOpaque treats the SET's `sub_id` opaque `id` as the LOCAL
	// user id directly. This is the symmetric inverse of THIS project's
	// own Transmitter, which emits {format:"opaque", id:<local subject>}
	// (security_event_token.go). It maps ONLY when a local user with that
	// EXACT id exists; an unknown id is a no-op. Use it for a peer SSO that
	// shares this server's subject namespace (or itself federates from the
	// same IdP, so the `sub` is already the shared subject).
	SubjectMapOpaque SubjectMapMode = iota

	// SubjectMapIssSub treats the SET's `sub_id` as the RFC 9493 `iss_sub`
	// format {format:"iss_sub", iss:<upstream-iss>, sub:<upstream-sub>} and
	// resolves it through the federation link:
	// UserProvider.GetByExternalID(provider, sub). The provider name is the
	// per-transmitter Provider, which is REQUIRED (operator-pinned, never
	// derived from the SET's attacker-controlled sub_id.iss), so a local user
	// federated from that upstream (User.Provider == provider, User.ExternalID
	// == upstream sub) is matched EXACTLY. A subject with no such federation
	// link — or one whose sub_id.iss names a FOREIGN provider — is a no-op.
	// Use it for a PARTIALLY-trusted upstream IdP whose subject namespace
	// differs from this server's: a transmitter in this mode can only revoke
	// subjects under ITS configured provider, never another upstream's.
	SubjectMapIssSub
)

// Subject-identifier `format` values (RFC 9493 §3) the receiver
// understands. A SET whose sub_id uses an unrecognised format maps to no
// subject (no-op + ack) rather than being guessed.
const (
	subjectFormatOpaque = "opaque"
	subjectFormatIssSub = "iss_sub"
)

// DefaultReceiverMaxClockSkew bounds SET iat/exp freshness validation.
// SETs are short-lived (the Transmitter defaults to a 2-minute TTL); a
// small skew tolerates clock drift between the upstream transmitter and
// this server without meaningfully widening the replay window.
const DefaultReceiverMaxClockSkew = 60 * time.Second

// EventSSFEventReceived is the internal audit event recorded when a
// validated SET is processed (whether or not it found a local subject to
// act on). It carries the transmitter iss + the event type + the mapped
// local subject via SetMeta — NEVER the raw SET (which is a signed bearer
// artefact). Operator-facing signal, not a wire code.
const EventSSFEventReceived audit.EventType = "ssf_event_received"

// EventSSFRevocation is the internal audit event recorded when a validated
// SET caused a LOCAL revocation (sessions + refresh tokens killed for the
// mapped subject). Distinct from ssf_event_received so an operator can
// alert specifically on receiver-driven revocations.
const EventSSFRevocation audit.EventType = "ssf_revocation"

// Receiver-side metric outcome labels for sso_ssf_sets_received_total.
// Bounded cardinality by construction.
const (
	// ReceiverOutcomeRevoked — a validated SET mapped to a local subject
	// and a revocation was performed.
	ReceiverOutcomeRevoked = "revoked"
	// ReceiverOutcomeNoop — a validated SET was acked but did nothing
	// (unmapped subject or only unknown events).
	ReceiverOutcomeNoop = "noop"
	// ReceiverOutcomeRejected — the SET failed validation (bad sig /
	// untrusted iss / wrong aud / expired / replayed / malformed).
	ReceiverOutcomeRejected = "rejected"
)

// ReceiverMetricFunc records one inbound-SET outcome. Wired by cmd to the
// sso_ssf_sets_received_total{outcome} counter; nil ⇒ no metric. Mirrors
// the transmitter's MetricFunc seam (keeps caep free of a prometheus dep).
type ReceiverMetricFunc func(outcome string)

// TrustedTransmitter describes ONE upstream transmitter the receiver will
// accept SETs from. The set of these IS the trust allowlist: a SET whose
// `iss` matches none of them is rejected before any signature work.
type TrustedTransmitter struct {
	// Issuer is the exact `iss` value the upstream stamps into its SETs.
	// Matched case-sensitively against the SET's `iss` — only an exact
	// match selects this transmitter's JWKS for verification.
	Issuer string

	// JWKS supplies this transmitter's published signing public keys (its
	// trust bundle). security.NewStaticJWKS from an operator-supplied JWKS
	// file is the in-scope minimum; any security.JWKSSource works. The SET
	// signature is verified against THESE keys, so a SET signed by anyone
	// else is rejected.
	JWKS security.JWKSSource

	// SubjectMode selects how this transmitter's SET subjects map to local
	// users (opaque vs iss_sub). Default (zero) is SubjectMapOpaque.
	SubjectMode SubjectMapMode

	// Provider is the local federation provider name used to resolve an
	// iss_sub subject (UserProvider.GetByExternalID(Provider, sub)). Only
	// consulted under SubjectMapIssSub, where it is REQUIRED: it MUST be
	// operator-pinned to THIS transmitter's trusted federated namespace and is
	// NEVER derived from the SET's sub_id.iss (which the transmitter controls,
	// so trusting it would let a transmitter revoke users federated from ANY
	// other provider — a cross-IdP subject hijack). NewReceiver rejects an
	// empty Provider when SubjectMode is SubjectMapIssSub. Ignored under
	// SubjectMapOpaque.
	Provider string

	// AllowedEvents, when non-empty, restricts which SSF event URIs from
	// THIS transmitter are honored (e.g. accept only session-revoked from a
	// given peer). Empty ⇒ every event the receiver knows how to act on is
	// honored. An event not in this set is treated as unknown (ack + no-op),
	// never an error — narrowing what a given transmitter may trigger.
	AllowedEvents []string

	// AllowedAlgs restricts the asymmetric JWS algs accepted from this
	// transmitter's bundle. Empty ⇒ the receiver default (ES256, RS256,
	// PS256, EdDSA). A symmetric alg here is rejected by VerifyCompactJWS.
	AllowedAlgs []string
}

// trustedEntry is the normalized internal form of a TrustedTransmitter:
// the alg allowlist materialized into a set and the allowed-events
// materialized into a set for O(1) checks.
type trustedEntry struct {
	jwks          security.JWKSSource
	subjectMode   SubjectMapMode
	provider      string
	allowedAlgs   map[string]struct{}
	allowedEvents map[string]struct{} // nil ⇒ all known events honored
}

// SubjectRevoker performs the local "revoke ALL of this subject's access"
// action once a SET is fully validated and its subject is mapped. It is a
// narrow seam (one method) so the receiver depends on a behavior, not on a
// concrete store wiring — StoreRevoker (revoker.go) is the default
// implementation composing the existing SessionManager +
// RefreshTokenSubjectIndex seams (the same ones /token/revoke-all and the
// compliance Eraser drive).
type SubjectRevoker interface {
	// RevokeAllForSubject revokes every refresh token and destroys every
	// session for the LOCAL user id. It returns counts for audit. It MUST be
	// idempotent (a second call finds nothing) and best-effort across the
	// two stores (a failure in one is reported, not a reason to skip the
	// other) — revoking is the safe direction.
	RevokeAllForSubject(ctx context.Context, localUserID string) (RevocationResult, error)
}

// RevocationResult reports what a RevokeAllForSubject did (for audit).
type RevocationResult struct {
	RefreshTokensRevoked int
	SessionsDestroyed    int
	// TrustedDevicesRevoked counts "remember this device" MFA-skip grants
	// killed by the optional fourth leg (WithTrustedDeviceRevocation). Zero
	// when that leg isn't wired — distinct from "wired but nothing to
	// revoke", which the receiver's audit trail doesn't need to tell apart.
	TrustedDevicesRevoked int
}

// SubjectResolver maps a SET subject identifier to a LOCAL user id. The
// default resolver (userProviderResolver) uses core.UserProvider; the seam
// is exported so an operator with a bespoke external-id store can plug a
// custom precise mapping. The crux invariant: return ("", false) — NOT a
// guessed id — for any subject that does not map to a KNOWN local user.
type SubjectResolver interface {
	// ResolveLocalSubject maps the SET subject to a local user id. ok=false
	// means "no known local user" — the caller MUST treat that as a no-op
	// (ack, no revocation). An error is a transient lookup failure (the
	// caller fails closed: no action, and the delivery is NOT acked so the
	// transmitter may retry).
	ResolveLocalSubject(ctx context.Context, mode SubjectMapMode, provider string, sub setSubjectID) (localUserID string, ok bool, err error)
}

// setSubjectID is the RFC 9493 Subject Identifier carried in a SET's
// `sub_id`. The receiver parses the two formats it acts on (opaque,
// iss_sub) plus the bare `sub` string fallback (some transmitters carry
// the subject as a top-level `sub` claim instead of sub_id).
type setSubjectID struct {
	Format string `json:"format"`
	ID     string `json:"id"`  // opaque
	Iss    string `json:"iss"` // iss_sub
	Sub    string `json:"sub"` // iss_sub
}

// inboundSETClaims is the SET payload subset the receiver validates +
// acts on. `aud` is string-or-array per RFC 7519 §4.1.3 (setAudClaim,
// jws.go).
type inboundSETClaims struct {
	Iss    string                     `json:"iss"`
	Jti    string                     `json:"jti"`
	Iat    int64                      `json:"iat"`
	Exp    int64                      `json:"exp"`
	Aud    setAudClaim                `json:"aud"`
	SubID  *setSubjectID              `json:"sub_id"`
	Sub    string                     `json:"sub"` // top-level subject fallback
	Events map[string]json.RawMessage `json:"events"`
}

// ReceiverResult is the outcome of processing one inbound SET, returned so
// the HTTP handler can choose the ack status + audit shape WITHOUT the
// receiver knowing about HTTP.
type ReceiverResult struct {
	// Acked is true when the SET was valid SSF and the transmitter's
	// delivery is complete (202) — including the valid-but-no-op cases
	// (unmapped subject / unknown event). False only on a validation
	// failure (the caller returns an SSF error).
	Acked bool

	// Acted is true when a revocation was actually performed.
	Acted bool

	// Issuer / EventTypes / LocalSubject are populated for audit on a valid
	// SET (Acked). They are SAFE to audit (no token bytes).
	Issuer       string
	EventTypes   []string
	LocalSubject string

	// Revocation carries the counts when Acted.
	Revocation RevocationResult

	// RejectCode is the SSF-standard error code when !Acked. One of the
	// ErrReceiver* / SSF codes below; the handler maps it to a 400. It does
	// NOT distinguish which internal check failed beyond the standard codes
	// (oracle-safe).
	RejectCode string
}

// SSF / RFC 8935 receiver error codes (the `err` field of the SSF error
// response). Deliberately COARSE so the receiver never leaks which precise
// validation gate failed (signature vs aud vs replay vs expiry) — an
// attacker probing the endpoint learns only the SSF-standard category.
const (
	// ErrReceiverInvalidRequest — the body is not a parseable compact-JWS
	// SET (RFC 8935 "invalid_request"). The ONLY shape error distinct from
	// the trust failures below.
	ErrReceiverInvalidRequest = "invalid_request"

	// ErrReceiverInvalidKey — the SET could not be authenticated: bad
	// signature, untrusted/unknown `iss`, wrong `aud`, expired, replayed,
	// or otherwise not from a trusted transmitter addressed to this
	// receiver. RFC 8935 §2.4 uses "invalid_key" for an authentication
	// failure of the SET; ALL trust failures collapse to it (oracle-safe).
	ErrReceiverInvalidKey = "invalid_key"
)

// Receiver consumes inbound SETs from configured trusted transmitters and
// revokes local access for the mapped subject.
type Receiver struct {
	// trusted maps an upstream `iss` → its normalized trust entry. The set
	// of keys IS the allowlist.
	trusted map[string]trustedEntry

	// audience is THIS server's identifier the SET `aud` MUST contain.
	audience string

	maxClockSkew time.Duration

	// jtiReplay consumes the SET jti (MarkSeen) so a replayed SET can't
	// re-trigger. REQUIRED — without a replay store the receiver cannot
	// guarantee single-action delivery, so NewReceiver rejects a nil one.
	jtiReplay security.JTIReplayStore

	// revoker performs the local revocation once a SET is validated +
	// mapped. REQUIRED.
	revoker SubjectRevoker

	// resolver maps a SET subject → local user id. REQUIRED.
	resolver SubjectResolver

	recorder *audit.Recorder    // audit sink; may be nil (no audit)
	metric   ReceiverMetricFunc // may be nil
	logger   Logger             // may be nil

	now func() time.Time // injectable clock for tests; nil ⇒ time.Now
}
