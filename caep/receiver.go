package caep

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/security"
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

// ReceiverOption configures a Receiver at construction.
type ReceiverOption func(*Receiver)

// WithReceiverMaxClockSkew overrides DefaultReceiverMaxClockSkew. Values
// < 0 are ignored.
func WithReceiverMaxClockSkew(d time.Duration) ReceiverOption {
	return func(r *Receiver) {
		if d >= 0 {
			r.maxClockSkew = d
		}
	}
}

// WithReceiverAuditRecorder wires the audit Recorder the receiver writes
// ssf_event_received / ssf_revocation events to. nil ⇒ no audit.
func WithReceiverAuditRecorder(rec *audit.Recorder) ReceiverOption {
	return func(r *Receiver) { r.recorder = rec }
}

// WithReceiverMetric wires the inbound-SET outcome counter.
func WithReceiverMetric(fn ReceiverMetricFunc) ReceiverOption {
	return func(r *Receiver) { r.metric = fn }
}

// WithReceiverLogger wires error logging. nil ⇒ silent.
func WithReceiverLogger(l Logger) ReceiverOption {
	return func(r *Receiver) { r.logger = l }
}

// WithReceiverSubjectResolver overrides the default UserProvider-backed
// subject resolver with a custom precise mapping. The custom resolver MUST
// honor the crux invariant (return ok=false, never a guess, for an unknown
// subject).
func WithReceiverSubjectResolver(res SubjectResolver) ReceiverOption {
	return func(r *Receiver) {
		if res != nil {
			r.resolver = res
		}
	}
}

// defaultReceiverAlgs is the asymmetric-alg allowlist used when a
// TrustedTransmitter declares none. Mirrors the SPIFFE validator default
// (ES256/RS256/PS256/EdDSA — every alg the in-process issuers emit, none
// symmetric). VerifyCompactJWS independently REFUSES any symmetric alg in
// the set, so even a misconfigured override can't open RS/HS confusion.
var defaultReceiverAlgs = []string{jwsAlgES256, jwsAlgRS256, jwsAlgPS256, jwsAlgEdDSA}

// NewReceiver builds a Receiver.
//
//   - audience — THIS server's identifier the SET `aud` MUST contain
//     (strict aud-binding; empty is a misconfiguration → error).
//   - jtiReplay — the replay store the SET jti is consumed through
//     (required; a nil one cannot guarantee single-action delivery).
//   - revoker — performs the local revocation (required).
//   - userProvider — backs the DEFAULT subject resolver; may be nil ONLY
//     if a custom resolver is supplied via WithReceiverSubjectResolver.
//   - transmitters — the trusted-transmitter allowlist; at least one is
//     required and each MUST carry a non-empty Issuer + a JWKS source.
//
// Any violation returns an error rather than building a half-wired
// receiver that would silently accept or reject everything.
func NewReceiver(audience string, jtiReplay security.JTIReplayStore, revoker SubjectRevoker, userProvider core.UserProvider, transmitters []TrustedTransmitter, opts ...ReceiverOption) (*Receiver, error) {
	if audience == "" {
		return nil, errors.New("caep: receiver audience required (aud-binding cannot be lax)")
	}
	if jtiReplay == nil {
		return nil, errors.New("caep: receiver requires a JTIReplayStore (replay defense is mandatory)")
	}
	if revoker == nil {
		return nil, errors.New("caep: receiver requires a SubjectRevoker")
	}
	if len(transmitters) == 0 {
		return nil, errors.New("caep: receiver requires at least one trusted transmitter")
	}

	trusted := make(map[string]trustedEntry, len(transmitters))
	for _, tt := range transmitters {
		iss := strings.TrimSpace(tt.Issuer)
		if iss == "" {
			return nil, errors.New("caep: trusted transmitter requires an issuer")
		}
		if tt.JWKS == nil {
			return nil, errors.New("caep: trusted transmitter " + iss + " requires a JWKS source")
		}
		if _, dup := trusted[iss]; dup {
			return nil, errors.New("caep: duplicate trusted transmitter issuer " + iss)
		}
		// iss_sub mode REQUIRES an operator-pinned Provider. The empty-provider
		// default is INSECURE: the resolver must look up the federation link
		// under a provider name fixed by the operator to THIS transmitter's
		// trusted namespace, NOT one derived from the SET's attacker-controlled
		// sub_id.iss (a cross-IdP subject hijack — see userProviderResolver).
		// Fail LOUD at construction rather than silently accept a config that
		// would let a transmitter revoke users federated from any provider.
		if tt.SubjectMode == SubjectMapIssSub && strings.TrimSpace(tt.Provider) == "" {
			return nil, errors.New("caep: trusted transmitter " + iss + " uses subject_mode iss_sub but has no provider (the provider MUST be operator-pinned to this transmitter's federated namespace; an empty provider is insecure)")
		}
		algs := tt.AllowedAlgs
		if len(algs) == 0 {
			algs = defaultReceiverAlgs
		}
		algSet := make(map[string]struct{}, len(algs))
		for _, a := range algs {
			algSet[a] = struct{}{}
		}
		var evSet map[string]struct{}
		if len(tt.AllowedEvents) > 0 {
			evSet = make(map[string]struct{}, len(tt.AllowedEvents))
			for _, e := range tt.AllowedEvents {
				evSet[e] = struct{}{}
			}
		}
		trusted[iss] = trustedEntry{
			jwks:          tt.JWKS,
			subjectMode:   tt.SubjectMode,
			provider:      tt.Provider,
			allowedAlgs:   algSet,
			allowedEvents: evSet,
		}
	}

	r := &Receiver{
		trusted:      trusted,
		audience:     audience,
		maxClockSkew: DefaultReceiverMaxClockSkew,
		jtiReplay:    jtiReplay,
		revoker:      revoker,
	}
	for _, opt := range opts {
		opt(r)
	}
	if r.resolver == nil {
		if userProvider == nil {
			return nil, errors.New("caep: receiver requires a UserProvider (or a custom SubjectResolver)")
		}
		r.resolver = &userProviderResolver{users: userProvider}
	}
	if r.now == nil {
		r.now = time.Now
	}
	return r, nil
}

// knownReceiverEvent reports whether the receiver knows how to ACT on an
// SSF event URI. Only the revocation-relevant CAEP/RISC events are
// actionable; any other URI is ignored (ack + no-op), so a transmitter
// emitting a richer event set never causes a spurious action or an error.
func knownReceiverEvent(uri string) bool {
	switch uri {
	case EventURICAEPSessionRevoked,
		EventURIRISCAccountDisabled,
		EventURICAEPTokenClaimsChange,
		EventURICAEPTokenRevoked:
		return true
	default:
		return false
	}
}

// Receive validates one inbound SET (the compact-JWS body) and, when fully
// valid AND mapped to a local subject, revokes that subject's local access.
// It returns a ReceiverResult the HTTP handler renders into an ack (202) or
// an SSF error (400). It NEVER returns an error for a validation failure —
// the failure is encoded in ReceiverResult.RejectCode (oracle-safe). A
// non-nil error means a transient internal failure (e.g. a revoke-store
// outage AFTER full validation) the handler maps to a 500; the validated
// intent is real, so the transmitter should retry.
//
// Validation order (each trust failure collapses to the SAME coarse
// ErrReceiverInvalidKey so the wire reveals no detail):
//
//  1. parse the compact JWS + read its claims enough to find `iss`.
//  2. iss-allowlist: `iss` MUST name a configured trusted transmitter.
//  3. signature: verify against THAT transmitter's JWKS via
//     VerifyCompactJWS (alg-allowlist BEFORE signature; no alg=none/HS*).
//  4. typ: the JOSE header `typ` MUST be secevent+jwt.
//  5. aud-binding: `aud` MUST contain this server's audience.
//  6. temporal: a SET MUST carry iat and/or exp (neither ⇒ reject), within
//     the configured skew.
//  7. jti replay: MarkSeen — a seen jti rejects (fail-closed).
//  8. events: keep only KNOWN actionable URIs (honoring the transmitter's
//     AllowedEvents). No actionable event ⇒ ack + no-op.
//  9. subject mapping: map sub_id → local user. Unmapped ⇒ ack + no-op.
//  10. action: revoke the mapped subject's sessions + refresh tokens.
func (r *Receiver) Receive(ctx context.Context, setBody string) (ReceiverResult, error) {
	// (1) Parse enough of the SET to learn its issuer, WITHOUT trusting any
	// of it yet (the signature is checked in step 3). VerifyCompactJWS also
	// reparses the header internally for the alg/kid gate; we read the
	// payload `iss` here only to SELECT which trust bundle to verify
	// against. A malformed body is the one shape error distinct from a
	// trust failure.
	header, payload, ok := splitCompactJWS(setBody)
	if !ok {
		return r.reject(ErrReceiverInvalidRequest), nil
	}
	var pre struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &pre); err != nil || pre.Iss == "" {
		// No issuer ⇒ cannot select a trust bundle ⇒ untrusted.
		return r.reject(ErrReceiverInvalidKey), nil
	}

	// (2) iss-allowlist — the trust gate. An issuer not in the configured
	// set is rejected BEFORE any signature work: only configured,
	// authenticated transmitters may ever trigger a revocation.
	entry, trustedIss := r.trusted[pre.Iss]
	if !trustedIss {
		return r.reject(ErrReceiverInvalidKey), nil
	}

	keys, err := entry.jwks.GetJWKS(ctx)
	if err != nil || len(keys) == 0 {
		// The trust bundle is unavailable — treat as not-authenticatable
		// (fail-closed). A misconfigured/empty bundle must never accept.
		return r.reject(ErrReceiverInvalidKey), nil
	}

	// (3) signature + alg-allowlist (no alg=none, no symmetric) against
	// THIS transmitter's bundle. Reuses the SAME verifier the SPIFFE path
	// uses — alg-confusion-safe, kid-bound, on-curve EC checks.
	verifiedPayload, err := security.VerifyCompactJWS(setBody, keys, entry.allowedAlgs)
	if err != nil {
		return r.reject(ErrReceiverInvalidKey), nil
	}

	// (4) typ gate: the JOSE header MUST declare secevent+jwt, so a plain
	// access/id token signed by the same upstream key can never be replayed
	// here as a SET (the inverse of the issuers' at+jwt typ gate).
	if !headerTypIsSET(header) {
		return r.reject(ErrReceiverInvalidKey), nil
	}

	var c inboundSETClaims
	if err := json.Unmarshal(verifiedPayload, &c); err != nil {
		return r.reject(ErrReceiverInvalidKey), nil
	}
	// Defense-in-depth: the verified payload's iss MUST still equal the one
	// we selected the bundle by (a mismatch would mean the unverified
	// pre-parse disagreed with the signed body — reject).
	if c.Iss != pre.Iss {
		return r.reject(ErrReceiverInvalidKey), nil
	}

	// (5) STRICT aud-binding — refuse a SET not addressed to THIS receiver.
	if !c.Aud.Contains(r.audience) {
		return r.reject(ErrReceiverInvalidKey), nil
	}

	// (6) temporal freshness. A SET MUST carry at least one temporal claim
	// (iat or exp). With NEITHER, both window checks below would be skipped,
	// so the SET bypasses freshness entirely; worse, with no exp the jti
	// replay key lives only DefaultJTIReplayWindow (below), so the same
	// no-temporal SET replays INDEFINITELY past that window, re-triggering a
	// revocation each time. A push-delivery SET with no freshness claim is
	// non-conformant for replay-safety → reject (fail-closed). When present,
	// we bound exp (not already past) and iat (not too far in the future) by
	// the skew; the jti-replay key (below) is bounded by exp+skew when exp is
	// present, else the default window from now (and since a fresh iat ≈ now,
	// that is effectively iat+window for the iat-only case — never unbounded,
	// because a no-temporal SET is rejected above).
	now := r.now()
	skew := r.maxClockSkew
	if c.Exp == 0 && c.Iat == 0 {
		return r.reject(ErrReceiverInvalidKey), nil
	}
	if c.Exp != 0 && now.Add(-skew).After(time.Unix(c.Exp, 0)) {
		return r.reject(ErrReceiverInvalidKey), nil
	}
	if c.Iat != 0 && now.Add(skew).Before(time.Unix(c.Iat, 0)) {
		return r.reject(ErrReceiverInvalidKey), nil
	}

	// (7) jti replay — consume the jti so a replayed SET cannot re-trigger.
	// A SET MUST carry a jti (RFC 8417 §2.2); a missing jti is rejected
	// rather than silently accepted (accepting "" would let an attacker
	// strip the claim to bypass the replay guard). Fail-closed: a seen jti,
	// OR a store error, rejects (an external-driven revocation primitive
	// must not double-act, and must not act on store uncertainty).
	if c.Jti == "" {
		return r.reject(ErrReceiverInvalidKey), nil
	}
	replayExpiry := now.Add(security.DefaultJTIReplayWindow)
	if c.Exp != 0 {
		replayExpiry = time.Unix(c.Exp, 0).Add(skew)
	}
	first, mErr := r.jtiReplay.MarkSeen(ctx, jtiNamespaceKey(c.Iss, c.Jti), replayExpiry)
	if mErr != nil {
		if r.logger != nil {
			r.logger.Error("ssf: jti replay store error", "iss", c.Iss, "error", mErr.Error())
		}
		return r.reject(ErrReceiverInvalidKey), nil
	}
	if !first {
		// Replayed SET — already actioned within its window. Reject so it
		// does not double-act, but the rejection is indistinguishable from
		// any other trust failure on the wire.
		return r.reject(ErrReceiverInvalidKey), nil
	}

	// ---- The SET is now FULLY VALIDATED. From here we ACK (202) even if
	// there is nothing to do; only unknown subjects/events remain, which
	// are no-ops, not errors. ----

	// (8) actionable events — keep only KNOWN URIs the transmitter is
	// allowed to trigger. An unknown / disallowed event is ignored.
	var eventTypes []string
	for uri := range c.Events {
		if !knownReceiverEvent(uri) {
			continue
		}
		if entry.allowedEvents != nil {
			if _, ok := entry.allowedEvents[uri]; !ok {
				continue
			}
		}
		eventTypes = append(eventTypes, uri)
	}
	if len(eventTypes) == 0 {
		// Valid SET, but it carries no event this receiver acts on. Ack it.
		r.auditReceived(ctx, c.Iss, nil, "")
		if r.metric != nil {
			r.metric(ReceiverOutcomeNoop)
		}
		return ReceiverResult{Acked: true, Issuer: c.Iss}, nil
	}

	// (9) subject mapping — the precision crux. Resolve the SET subject to a
	// LOCAL user id. A subject with no known local mapping is a NO-OP (ack,
	// no revocation) — never a guessed/partial match.
	sub := c.subjectID()
	localSub, mapped, rErr := r.resolver.ResolveLocalSubject(ctx, entry.subjectMode, entry.provider, sub)
	if rErr != nil {
		// A transient resolver failure: fail-closed (no action) and do NOT
		// ack, so the transmitter may retry rather than silently dropping a
		// real revocation. Surfaced as an internal error → 500.
		if r.logger != nil {
			r.logger.Error("ssf: subject resolve error", "iss", c.Iss, "error", rErr.Error())
		}
		return ReceiverResult{}, rErr
	}
	if !mapped {
		// Unmapped subject ⇒ no wrongful revocation. Ack + no-op.
		r.auditReceived(ctx, c.Iss, eventTypes, "")
		if r.metric != nil {
			r.metric(ReceiverOutcomeNoop)
		}
		return ReceiverResult{Acked: true, Issuer: c.Iss, EventTypes: eventTypes}, nil
	}

	// (10) action — revoke ALL of the mapped subject's local access. Every
	// actionable event here (session-revoked / account-disabled /
	// token-claims-change / token-revoked) is conservatively handled by the
	// SAME full-subject revocation: killing the subject's sessions + refresh
	// tokens is the safe superset of each. Token-claims-change is the
	// weakest signal but still revokes (the previously-trusted tokens should
	// no longer be honored).
	res, revErr := r.revoker.RevokeAllForSubject(ctx, localSub)
	if revErr != nil {
		// The SET was valid + mapped; the revoke is the safe direction, so a
		// store error here is surfaced (the transmitter retries) rather than
		// acked-as-done. We still audit the attempt.
		r.auditRevocation(ctx, c.Iss, eventTypes, localSub, res, false)
		if r.logger != nil {
			r.logger.Error("ssf: revocation failed after valid SET", "iss", c.Iss, "subject", localSub, "error", revErr.Error())
		}
		return ReceiverResult{}, revErr
	}

	r.auditRevocation(ctx, c.Iss, eventTypes, localSub, res, true)
	if r.metric != nil {
		r.metric(ReceiverOutcomeRevoked)
	}
	return ReceiverResult{
		Acked:        true,
		Acted:        true,
		Issuer:       c.Iss,
		EventTypes:   eventTypes,
		LocalSubject: localSub,
		Revocation:   res,
	}, nil
}

// reject builds a rejected result + bumps the rejected metric. Centralizing
// it keeps every validation-failure path emitting the SAME coarse code +
// metric (no oracle, consistent observability).
func (r *Receiver) reject(code string) ReceiverResult {
	if r.metric != nil {
		r.metric(ReceiverOutcomeRejected)
	}
	return ReceiverResult{Acked: false, RejectCode: code}
}

// auditReceived records the ssf_event_received event for a valid SET that
// did nothing actionable (unknown event or unmapped subject). SAFE fields
// only (iss + event types + local subject) — NEVER the raw SET.
func (r *Receiver) auditReceived(ctx context.Context, iss string, eventTypes []string, localSubject string) {
	if r.recorder == nil {
		return
	}
	e := &audit.Event{
		Type:    EventSSFEventReceived,
		Outcome: audit.OutcomeSuccess,
		ActorID: localSubject,
	}
	audit.SetMeta(e, metaSSFIssuer, iss)
	audit.SetMeta(e, metaSSFEvents, strings.Join(eventTypes, " "))
	r.recorder.Record(ctx, e)
}

// auditRevocation records the ssf_revocation event when a validated SET
// drove a local revocation (success or a failed attempt).
func (r *Receiver) auditRevocation(ctx context.Context, iss string, eventTypes []string, localSubject string, res RevocationResult, ok bool) {
	if r.recorder == nil {
		return
	}
	e := &audit.Event{
		Type:    EventSSFRevocation,
		Outcome: audit.OutcomeSuccess,
		ActorID: localSubject,
	}
	if !ok {
		e.Outcome = audit.OutcomeFailure
	}
	audit.SetMeta(e, metaSSFIssuer, iss)
	audit.SetMeta(e, metaSSFEvents, strings.Join(eventTypes, " "))
	r.recorder.Record(ctx, e)
}

// Audit metadata keys the receiver writes (via SetMeta, never raw SET).
const (
	metaSSFIssuer = "ssf_issuer"
	metaSSFEvents = "ssf_events"
)

// subjectID returns the SET's subject identifier, preferring sub_id and
// falling back to a top-level `sub` string (carried by transmitters that
// don't use the RFC 9493 sub_id object).
func (c *inboundSETClaims) subjectID() setSubjectID {
	if c.SubID != nil {
		return *c.SubID
	}
	if c.Sub != "" {
		return setSubjectID{Format: subjectFormatOpaque, ID: c.Sub}
	}
	return setSubjectID{}
}

// jtiNamespaceKey namespaces the replay key by issuer so two transmitters
// that happen to mint colliding jti values can't cause one's SET to
// suppress the other's (the jti uniqueness guarantee is per-issuer).
func jtiNamespaceKey(iss, jti string) string {
	return "ssf:" + iss + ":" + jti
}
