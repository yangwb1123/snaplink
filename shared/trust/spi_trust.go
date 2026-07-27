// Package trust defines the trust-scoring SPI (Zero Trust Framework Phase 1,
// "Direction 3" of the token-governance/credential-rotation/ZT/DR analysis)
// plus the reference scorers and a weighted composite
// aggregator. It covers ONLY the scoring foundation — Score returns an
// advisory signal, never an allow/deny decision. The two later phases are
// separate, independently-wired packages that consume this signal: the
// conditional-access policy engine lives in domains/conditionalaccess
// (opt-in via sso.WithConditionalAccess), and continuous/session-decay
// verification is this package's own decay.go curve plus
// platform/lifecycle/continuousverify (opt-in via sso.WithSessionTrustDecay).
//
// Layering note: this SPI is core-shaped and would naturally sit in
// shared/core, mirroring the existing SPI + reference-scorer pattern already
// followed by shared/spi.RiskScorer. It lives in its own shared/trust leaf
// instead because shared/core AND shared/spi are both AT their frozen
// per-directory file-count ceiling (see directory_fanout_test.go's
// dirFileCountExemptions / the shared/spi cap) — adding a file to either
// would fail that committed, shrink-only gate. A new shared/ leaf keeps the
// same dependency-free kernel placement without touching the ratchet.
//
// Every import here still points down (nothing reaches into domains/anomaly
// or platform/geo): scorers that need that kind of data (IP failure counts,
// login history) declare a narrow local interface instead (see
// ip_reputation_scorer.go, behavior_scorer.go) that the real domains-layer
// stores can satisfy structurally without an upward import, or that the
// Memory* implementation here satisfies directly for tests/dev.
package trust

import (
	"context"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// TrustSignals carries the request-time context available to a TrustScorer
// at login/token time. Every field is optional (zero value = "unknown to the
// caller") — scorers MUST degrade gracefully rather than treat a zero value
// as a negative signal; see the floor semantics on [ScorerWeight].
type TrustSignals struct {
	// RemoteIP is the caller's address, resolved by the same trusted-proxy
	// model as geo/ratelimit/mesh headers (AGENTS.md "X-Forwarded-* Trust").
	// Empty when unavailable (e.g. an internal token-exchange hop).
	RemoteIP string

	// Geo is the enrichment already computed for RemoteIP on this request,
	// when a geo.Provider is wired. Zero value (all fields empty) means "no
	// geo hint" — NOT "unknown location = risky"; geo is UX-only and
	// fail-open (AGENTS.md "Fail Modes"), and a TrustScorer must honor that:
	// a missing value degrades to the scorer's configured floor, it never
	// manufactures a penalty from absence. Typed as [core.GeoInfo] (the same
	// type shared/spi.RiskRequest.Geo uses) so this SPI doesn't duplicate the
	// shape.
	Geo core.GeoInfo

	// UserID / ClientID identify the subject and OAuth client the score is
	// being computed for. Both may be empty (client_credentials has no
	// UserID; a pre-authentication check may have no ClientID yet).
	UserID   string
	ClientID string

	// Time is the instant the signals were captured, injected rather than
	// scorers calling time.Now() so composite scoring — and its tests — stay
	// deterministic.
	Time time.Time

	// AMR / ACR mirror the RFC 8176 / RFC 9068 values already computed for
	// this authentication event (AGENTS.md "RFC 9068 Claims").
	AMR []string
	ACR string

	// DeviceHints carries whatever device/client-posture signal the caller
	// already has on hand (User-Agent family, a DPoP/mTLS key thumbprint, a
	// device id header) — free-form because the SDK has no device inventory
	// of its own; see DevicePostureScorer.
	DeviceHints map[string]string
}

// TrustScore is the output of a TrustScorer: a normalized confidence signal
// plus a short, audit-readable trail of what drove it. It is ADVISORY, not
// an access-control decision — turning a score into allow/deny/step-up is
// the conditional-access policy engine (domains/conditionalaccess), which
// consumes this score via AccessContext.TrustScore.
type TrustScore struct {
	// Value is in [0.0, 1.0]: 0 = no trust signal / maximally suspicious, 1
	// = fully trusted.
	Value float64

	// Reasons is an ordered, short-code trail (e.g. "geo_risk:known_country",
	// "ip_reputation:degraded", "behavior:cold_start") for audit logging —
	// short codes only, never free-text or PII.
	Reasons []string
}

// ClampScore constrains v to [0.0, 1.0]. Scorer implementations run their
// raw computation through this before returning, so a buggy scorer can't
// push a composite average out of range.
func ClampScore(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}

// TrustScorer computes a TrustScore from the signals available at
// login/token time. Implementations MUST be safe for concurrent use (called
// on the request hot path) and MUST fail open: a scorer that can't reach its
// data source returns an error and lets [ScorerWeight.FloorOnError] carry
// it — it must never block authentication itself (AGENTS.md "Fail Modes";
// geo/risk-scorer are the existing fail-open precedents this follows).
type TrustScorer interface {
	// Score returns a TrustScore for signals, or an error when the scorer's
	// data source is unavailable (a composite degrades this scorer's
	// contribution to its configured floor rather than failing the whole
	// score — see WeightedComposite).
	Score(ctx context.Context, signals TrustSignals) (TrustScore, error)

	// Name is the scorer's stable identifier — used as a metric label and a
	// Reasons/error-degradation prefix, so a composite of N scorers can
	// attribute a low score (or a degradation) to one of them without
	// string-matching Reasons.
	Name() string
}

// ScorerWeight is the composite/weighted aggregator contract: it pairs a
// named TrustScorer with its relative contribution weight and the score
// substituted when that scorer errors. Weights are relative, not required
// to sum to 1 — [WeightedComposite] normalizes by the sum of weights of
// scorers that actually returned a score.
type ScorerWeight struct {
	Scorer TrustScorer
	Weight float64

	// FloorOnError is this scorer's contribution when Score returns an
	// error — fail-open by construction: a misconfigured or unreachable
	// data source degrades its OWN slice of the composite, it never tanks
	// the whole trust score to 0 or aborts authentication. Operators point
	// this at a conservative-but-not-zero value (e.g. 0.3-0.5) for scorers
	// backed by an external store.
	FloorOnError float64
}
