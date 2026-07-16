package rs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// introspectBodyLimit bounds the response read: a well-formed RFC 7662
// answer is a few hundred bytes; anything near this limit is hostile or
// misrouted.
const introspectBodyLimit = 1 << 20

// defaultIntrospectTimeout bounds an introspection round-trip when the
// caller supplies no HTTPClient — the RS must not hang a request on a stuck
// AS.
const defaultIntrospectTimeout = 5 * time.Second

// ValidateTokenWithIntrospect validates via the AS's RFC 7662 introspection
// endpoint: revocation is visible immediately, at the cost of an AS
// round-trip per call. The response is deliberately NEVER cached — the AS
// marks it Cache-Control: no-store, and caching an `active` verdict would
// reintroduce exactly the revocation blindness this mode exists to remove.
//
// {"active": false} maps to ErrTokenInactive; transport/status/parse
// failures map to ErrIntrospection so callers can pick their fail mode for
// AS outages separately from genuine rejections.
func ValidateTokenWithIntrospect(ctx context.Context, token string, cfg Config) (*Claims, error) {
	if cfg.Issuer == "" || cfg.IntrospectURL == "" {
		return nil, fmt.Errorf("%w: Issuer and IntrospectURL required for introspection", ErrConfig)
	}
	if token == "" {
		return nil, fmt.Errorf("%w: empty token", ErrTokenMalformed)
	}
	w, err := introspectCall(ctx, token, cfg)
	if err != nil {
		return nil, err
	}
	if !w.Active {
		return nil, ErrTokenInactive
	}
	claims := &Claims{
		Issuer:     w.Iss,
		Subject:    w.Sub,
		Audience:   audienceValues(w.Aud),
		ClientID:   w.ClientID,
		Scope:      w.Scope,
		JTI:        w.JTI,
		ExpiresAt:  w.Exp,
		NotBefore:  w.Nbf,
		IssuedAt:   w.Iat,
		RenewAfter: w.RenewAfter,
		CnfJKT:     w.Cnf.JKT,
		Raw:        w.raw,
	}
	if err := validateIntrospectedClaims(claims, cfg); err != nil {
		return nil, err
	}
	return claims, nil
}

// wireIntrospection is wireClaims plus the RFC 7662 active flag and the
// opt-in token-policy renew_after early warning (introspection-only, never
// present on a raw JWT — kept off wireClaims for that reason).
type wireIntrospection struct {
	Active     bool  `json:"active"`
	RenewAfter int64 `json:"renew_after"`
	wireClaims
	raw map[string]any
}

// introspectCall performs the RFC 7662 POST: form-encoded body, RS client
// credentials via HTTP Basic, JSON response.
func introspectCall(ctx context.Context, token string, cfg Config) (*wireIntrospection, error) {
	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.IntrospectURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIntrospection, err)
	}
	req.Header.Set(headerContentType, contentTypeForm)
	req.Header.Set(headerAccept, contentTypeJSON)
	if cfg.IntrospectCreds != nil {
		req.SetBasicAuth(cfg.IntrospectCreds.ID, cfg.IntrospectCreds.Secret)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultIntrospectTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIntrospection, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrIntrospection, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, introspectBodyLimit))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIntrospection, err)
	}
	var w wireIntrospection
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("%w: response parse: %v", ErrIntrospection, err)
	}
	_ = json.Unmarshal(body, &w.raw)
	return &w, nil
}

// validateIntrospectedClaims re-applies the identity/time gates the RS is
// configured with. The AS already refused inactive tokens; these checks
// guard against a token minted by a DIFFERENT issuer being introspected at
// the wrong AS, an aud the RS does not serve, and an active=true answer with
// a stale exp. RFC 7662 makes iss/aud/exp OPTIONAL in the response, so each
// is enforced only when present — except aud, which fails closed when the RS
// demands one and the AS did not state it.
func validateIntrospectedClaims(c *Claims, cfg Config) error {
	if c.Issuer != "" && c.Issuer != cfg.Issuer {
		return fmt.Errorf("%w: iss %q", ErrIssuerMismatch, c.Issuer)
	}
	if cfg.ExpectedAud != "" && !c.HasAudience(cfg.ExpectedAud) {
		return ErrAudienceMismatch
	}
	if c.ExpiresAt != 0 && time.Now().Unix() >= c.ExpiresAt+int64(cfg.skew().Seconds()) {
		return ErrTokenExpired
	}
	return nil
}
