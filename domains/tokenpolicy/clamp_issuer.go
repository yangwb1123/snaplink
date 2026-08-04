package tokenpolicy

import (
	"context"

	"github.com/yangwb1123/snaplink/shared/core"
)

// ClampingIssuer decorates a [core.TokenIssuer] so every access token it
// mints has its lifetime clamped DOWNWARD by the max_ttl dimension. It is
// the UNIFORM seam that applies max_ttl to every grant flow (and the
// /auth/login direct mint) without editing each grant handler, because all
// issuance funnels through the server's IssuerForClient resolution.
//
// It ONLY clamps TTL — a silent, deterministic modification of the caller's
// (freshly built, per-issue) Subject. The DENY dimensions (scope combos,
// refresh depth, active sessions) are enforced by the caller's pre-issuance
// gate, which alone has the request context to write the oracle-safe 400.
//
// A policy-store error FAILS OPEN (issue with the unclamped TTL): a
// governance-store outage must never break token issuance (AGENTS.md §3).
type ClampingIssuer struct {
	inner core.TokenIssuer
	store Store
}

// Interface guard: the decorator IS a TokenIssuer.
var _ core.TokenIssuer = (*ClampingIssuer)(nil)

// NewClampingIssuer wraps inner so its access-token TTLs are policy-clamped.
// Returns inner UNCHANGED when store or inner is nil, so a caller can wrap
// unconditionally and pay zero cost (byte-identical) when no policy is wired.
func NewClampingIssuer(inner core.TokenIssuer, store Store) core.TokenIssuer {
	if store == nil || inner == nil {
		return inner
	}
	return &ClampingIssuer{inner: inner, store: store}
}

// Issue evaluates the max_ttl dimension against the subject's client + the
// requested scopes and clamps subject.TTL downward before delegating to the
// wrapped issuer. Evaluate guarantees EffectiveTTL is never above a positive
// RequestedTTL, so this never RAISES a client-configured lifetime.
//
// MINT-SITE CONTRACT: a site that mints via IssuerForClient MUST stamp
// Subject.TenantID (from the client being served) or tenant-scoped max_ttl
// rules silently never clamp that flow. A missing stamp is fail-open (TTL
// unclamped) — the per-site clamp tests pin every known site; review any new
// Subject literal against that census.
func (c *ClampingIssuer) Issue(ctx context.Context, subject *core.Subject, scopes []string) (*core.Token, error) {
	if subject != nil {
		if policies, err := c.store.Policies(ctx); err == nil {
			dec := Evaluate(PolicyInput{
				ClientID:     subject.ClientID,
				TenantID:     subject.TenantID,
				Scopes:       scopes,
				Kind:         KindAccess,
				RequestedTTL: subject.TTL,
			}, policies)
			if dec.EffectiveTTL > 0 {
				subject.TTL = dec.EffectiveTTL
			}
		}
	}
	return c.inner.Issue(ctx, subject, scopes)
}

// Validate delegates unchanged — policy only shapes issuance.
func (c *ClampingIssuer) Validate(ctx context.Context, token string) (*core.TokenClaims, error) {
	return c.inner.Validate(ctx, token)
}

// Revoke delegates unchanged.
func (c *ClampingIssuer) Revoke(ctx context.Context, token string) error {
	return c.inner.Revoke(ctx, token)
}
