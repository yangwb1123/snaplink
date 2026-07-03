package trust

import (
	"strconv"
	"strings"
)

// DefaultTrustScoreClaim is the claim name used when
// SerializationConfig.ClaimName is empty.
const DefaultTrustScoreClaim = "trust_score"

// SerializationConfig gates whether a computed TrustScore is surfaced
// beyond the in-process scoring call — into session metadata or a token
// claim. Both flags default to false (Go zero value): scoring with a
// zero-value SerializationConfig is metrics/audit-observable only and
// changes NOTHING on the wire, matching config.TrustConfig's default-off
// contract (AGENTS.md "Serialization: ... default OFF so no wire change
// unless enabled").
type SerializationConfig struct {
	// StampSessionMetadata opts into adding the score to session-scoped
	// metadata (e.g. the login audit event's Metadata map via
	// platform/audit.SetMeta) so downstream analysis can see what a
	// session's trust score was at creation time.
	StampSessionMetadata bool

	// IncludeTokenClaim opts into adding the score as a private claim on
	// the token minted for this login (see ClaimName). Downstream policy
	// enforcement points (Phase 4 of the source analysis doc — not
	// implemented here) would read it to gate access; today it is purely
	// informational.
	IncludeTokenClaim bool

	// ClaimName is the claim key used when IncludeTokenClaim is set. Empty
	// falls back to DefaultTrustScoreClaim.
	ClaimName string
}

// SessionMetadata renders score as a small string-keyed map suitable for
// platform/audit.SetMeta (or any other session-metadata sink), or nil when
// cfg.StampSessionMetadata is off. Callers MUST treat a nil return as "add
// nothing" rather than an empty-but-present map, so a disabled config stays
// byte-identical to a build that never computed a score at all.
func SessionMetadata(cfg SerializationConfig, score TrustScore) map[string]string {
	if !cfg.StampSessionMetadata {
		return nil
	}
	return map[string]string{
		"trust_score":   formatScore(score.Value),
		"trust_reasons": strings.Join(score.Reasons, ","),
	}
}

// TokenClaim renders score as the claim value to add under name, with
// ok=true when cfg.IncludeTokenClaim is set. ok=false means "add nothing" —
// the caller must not add an empty claim, which would itself be a wire
// change for a disabled config.
func TokenClaim(cfg SerializationConfig, score TrustScore) (name, value string, ok bool) {
	if !cfg.IncludeTokenClaim {
		return "", "", false
	}
	name = cfg.ClaimName
	if name == "" {
		name = DefaultTrustScoreClaim
	}
	return name, formatScore(score.Value), true
}

func formatScore(v float64) string {
	return strconv.FormatFloat(ClampScore(v), 'f', 2, 64)
}
