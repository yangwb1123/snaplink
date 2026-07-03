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
		Issuer:    w.Iss,
		Subject:   w.Sub,
		Audience:  audienceValues(w.Aud),
		ClientID:  w.ClientID,
		Scope:     w.Scope,
		JTI:       w.JTI,
		ExpiresAt: w.Exp,
		NotBefore: w.Nbf,
		IssuedAt:  w.Iat,
		CnfJKT:    w.Cnf.JKT,
		Raw:       raw,
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
	return nil
}
