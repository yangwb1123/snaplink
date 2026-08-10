package rs

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Claims is the validated view of an access token the RS acts on. Fields
// cover the RFC 9068 §2.2 claim set plus the RFC 9449 cnf.jkt binding; Raw
// holds the complete claim document for anything beyond them.
type Claims struct {
	Issuer    string
	Subject   string
	Audience  []string
	ClientID  string
	Scope     string
	JTI       string
	ExpiresAt int64
	NotBefore int64
	IssuedAt  int64

	// ServingRegion is the SnapLink extension `serving_region` claim: the
	// regional deployment that minted this token (echoed by introspection).
	// Empty when the AS didn't mint/echo it. Config.AllowedServingRegions
	// gates on it; HasServingRegion reports presence.
	ServingRegion string

	// TenantID is the SnapLink extension `tenant_id` claim: the mint-time
	// tenant binding of the client the token was issued to (echoed by
	// introspection). Empty when the AS didn't bind the client, in which
	// case no claim was minted. HasTenantID reports presence; there is no
	// Config gate — the tenant expectation is per-binding adapter config,
	// not a shared RS static set.
	TenantID string

	// RenewAfter is the unix time an introspected token needs renewal, per
	// the AS's opt-in token-policy governance (WithTokenPolicy's
	// RequireRenewAfter) — an early warning ahead of the AS eventually
	// reporting the token inactive. Zero when introspection didn't include
	// it (no policy configured, or ValidateTokenWithJWT was used instead —
	// this field is introspection-only, never present on a raw JWT).
	RenewAfter int64

	// CnfJKT is the RFC 9449 §6.1 confirmation thumbprint. Non-empty means
	// the token is sender-constrained: it MUST be accompanied by a DPoP
	// proof whose key hashes to this value.
	CnfJKT string

	// Raw is the full claim set as decoded JSON, for claims this struct
	// does not project.
	Raw map[string]any
}

// Scopes splits the space-delimited scope claim (RFC 8693 §4.2 syntax).
func (c *Claims) Scopes() []string {
	if c == nil || c.Scope == "" {
		return nil
	}
	return strings.Fields(c.Scope)
}

// HasAudience reports whether aud contains the given value.
func (c *Claims) HasAudience(aud string) bool {
	if c == nil {
		return false
	}
	for _, a := range c.Audience {
		if a == aud {
			return true
		}
	}
	return false
}

// HasServingRegion reports whether the token carries a non-empty
// serving_region claim.
func (c *Claims) HasServingRegion() bool {
	return c != nil && c.ServingRegion != ""
}

// HasTenantID reports whether the token carries a non-empty tenant_id
// claim. Tenant IDs are non-empty by construction (binding identity
// validation), so presence == non-empty — same discipline as the
// serving-region precedent.
func (c *Claims) HasTenantID() bool {
	return c != nil && c.TenantID != ""
}

// HasServingRegionIn reports whether the token's serving_region is in
// regions. Exact match — region IDs are opaque, case-sensitive. A token
// without the claim is never in the set (fail-closed callers use this with
// a configured allowlist).
func (c *Claims) HasServingRegionIn(regions []string) bool {
	if !c.HasServingRegion() {
		return false
	}
	for _, r := range regions {
		if r == c.ServingRegion {
			return true
		}
	}
	return false
}

// wireClaims mirrors the claim names on the wire; aud stays `any` because
// OIDC allows both a compact string and an array.
type wireClaims struct {
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
	Aud      any    `json:"aud"`
	Exp      int64  `json:"exp"`
	Nbf      int64  `json:"nbf"`
	Iat      int64  `json:"iat"`
	JTI      string `json:"jti"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	// ServingRegion is the SnapLink extension claim (mint-region evidence).
	ServingRegion string `json:"serving_region"`
	// TenantID is the SnapLink extension claim (mint-time client binding).
	// No omitempty: decode treats absence as the zero value.
	TenantID string `json:"tenant_id"`
	Cnf      struct {
		JKT string `json:"jkt"`
	} `json:"cnf"`
}

// parseClaims decodes a verified JWT payload into Claims. Called AFTER
// signature verification only — nothing here may be treated as trusted
// earlier.
func parseClaims(payload []byte) (*Claims, error) {
	var w wireClaims
	if err := json.Unmarshal(payload, &w); err != nil {
		return nil, fmt.Errorf("%w: claims parse: %v", ErrTokenMalformed, err)
	}
	var raw map[string]any
	// Second pass keeps the full document; it cannot fail once the typed
	// pass succeeded.
	_ = json.Unmarshal(payload, &raw)
	return &Claims{
		Issuer:        w.Iss,
		Subject:       w.Sub,
		Audience:      audienceValues(w.Aud),
		ClientID:      w.ClientID,
		Scope:         w.Scope,
		JTI:           w.JTI,
		ExpiresAt:     w.Exp,
		NotBefore:     w.Nbf,
		IssuedAt:      w.Iat,
		CnfJKT:        w.Cnf.JKT,
		ServingRegion: w.ServingRegion,
		TenantID:      w.TenantID,
		Raw:           raw,
	}, nil
}

// audienceValues normalizes the aud claim: the spec allows a single string
// or an array of strings.
func audienceValues(v any) []string {
	switch x := v.(type) {
	case string:
		if x == "" {
			return nil
		}
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// validateClaims applies the time + identity gates with the configured skew.
// exp is REQUIRED (RFC 9068 §2.2); nbf/iat are checked only when present.
func validateClaims(c *Claims, cfg Config, now time.Time) error {
	if c.Issuer != cfg.Issuer {
		return fmt.Errorf("%w: iss %q", ErrIssuerMismatch, c.Issuer)
	}
	if c.ExpiresAt == 0 {
		return fmt.Errorf("%w: missing exp", ErrTokenMalformed)
	}
	nowSec := now.Unix()
	skewSec := int64(cfg.skew().Seconds())
	if nowSec >= c.ExpiresAt+skewSec {
		return ErrTokenExpired
	}
	if c.NotBefore != 0 && nowSec+skewSec < c.NotBefore {
		return fmt.Errorf("%w: nbf in the future", ErrTokenNotYetValid)
	}
	if c.IssuedAt != 0 && c.IssuedAt > nowSec+skewSec {
		return fmt.Errorf("%w: iat in the future", ErrTokenNotYetValid)
	}
	if cfg.ExpectedAud != "" && !c.HasAudience(cfg.ExpectedAud) {
		return ErrAudienceMismatch
	}
	// Region governance gate (opt-in, fail-closed): a region-pinned
	// deployment cannot accept a token with no verifiable mint region, so
	// the missing claim is a mismatch, not a pass. Runs LAST — after the
	// identity/time gates — so a garbage/expired token still reports its
	// higher-priority sentinel and the gate never becomes a probe oracle.
	if len(cfg.AllowedServingRegions) > 0 && !c.HasServingRegionIn(cfg.AllowedServingRegions) {
		return fmt.Errorf("%w: serving_region %q", ErrServingRegionMismatch, c.ServingRegion)
	}
	return nil
}
