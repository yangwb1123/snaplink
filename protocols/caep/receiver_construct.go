package caep

import (
	"errors"
	"strings"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

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
