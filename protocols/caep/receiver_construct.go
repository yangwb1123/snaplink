package caep

import (
	"errors"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
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

// Receiver consumes inbound SETs from configured trusted transmitters and
// revokes local access for the mapped subject.
type Receiver struct {
	// trusted maps an upstream `iss` → its normalized trust entry. The set
	// of keys IS the allowlist.
	trusted map[string]trustedEntry
	// audience is THIS server's identifier the SET `aud` MUST contain.
	audience     string
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
	now      func() time.Time   // injectable clock for tests; nil ⇒ time.Now
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

	trusted, err := buildTrustedEntries(transmitters)
	if err != nil {
		return nil, err
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
	if err := r.applyDefaults(userProvider); err != nil {
		return nil, err
	}
	return r, nil
}

// buildTrustedEntries normalizes the trusted-transmitter allowlist into the
// internal issuer-keyed map. The validation ORDER (empty-iss → nil-JWKS →
// duplicate-iss → iss_sub-without-provider) is load-bearing and preserved.
func buildTrustedEntries(transmitters []TrustedTransmitter) (map[string]trustedEntry, error) {
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
		var evSet map[string]struct{}
		if len(tt.AllowedEvents) > 0 {
			evSet = toStringSet(tt.AllowedEvents)
		}
		trusted[iss] = trustedEntry{
			jwks:          tt.JWKS,
			subjectMode:   tt.SubjectMode,
			provider:      tt.Provider,
			allowedAlgs:   toStringSet(algs),
			allowedEvents: evSet,
		}
	}
	return trusted, nil
}

// toStringSet builds a presence set from a slice. Callers preserving the
// nil-vs-empty distinction (e.g. allowedEvents) must guard the empty case.
func toStringSet(vals []string) map[string]struct{} {
	set := make(map[string]struct{}, len(vals))
	for _, v := range vals {
		set[v] = struct{}{}
	}
	return set
}

// applyDefaults fills the resolver and clock seams left unset by opts. A nil
// resolver requires a UserProvider; the default userProviderResolver is wired
// only when no custom SubjectResolver was supplied.
func (r *Receiver) applyDefaults(userProvider core.UserProvider) error {
	if r.resolver == nil {
		if userProvider == nil {
			return errors.New("caep: receiver requires a UserProvider (or a custom SubjectResolver)")
		}
		r.resolver = &userProviderResolver{users: userProvider}
	}
	if r.now == nil {
		r.now = time.Now
	}
	return nil
}
