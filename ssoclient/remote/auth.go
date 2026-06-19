// Package remote implements ssoclient.{Auth,Authz,Audit}Client by calling
// the SSO server over the network — gRPC for hot paths (authz, audit) and
// HTTP for token validation (JWKS fetch + local signature verify).
//
// The remote AuthClient does NOT call /userinfo to validate tokens — it
// verifies signatures locally with cached JWKS, so the SSO server isn't on
// the per-request path. It accepts the full asymmetric alg set the server can
// emit (EdDSA / ES256-512 / RS256-512 / PS256-512) via the shared,
// alg-confusion-safe security.VerifyCompactJWS primitive.
package remote

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/ssoclient"
)

// AuthClient validates JWTs locally via JWKS and revokes via the SSO server's
// HTTP /logout endpoint. JWKSCache lifecycle is owned by the caller (so
// multiple clients can share one cache).
type AuthClient struct {
	jwks      *JWKSCache
	httpc     *http.Client
	logoutURL string // optional; if empty, Logout is a no-op for tokens
}

type AuthOption func(*AuthClient)

// WithAuthHTTPClient customizes the *http.Client used for Logout.
func WithAuthHTTPClient(c *http.Client) AuthOption {
	return func(a *AuthClient) {
		if c != nil {
			a.httpc = c
		}
	}
}

// WithLogoutURL enables remote token revocation via POST <logoutURL>.
// Without it, Logout silently skips the server round-trip.
func WithLogoutURL(url string) AuthOption {
	return func(a *AuthClient) { a.logoutURL = url }
}

func NewAuthClient(jwks *JWKSCache, opts ...AuthOption) *AuthClient {
	c := &AuthClient{
		jwks:  jwks,
		httpc: &http.Client{Timeout: 5 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// jwtHeader is the minimal header struct we need for routing by kid.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// jwtPayload mirrors the Ed25519JWTIssuer's payload layout in the SDK.
type jwtPayload struct {
	Iss   string            `json:"iss"`
	Sub   string            `json:"sub"`
	Aud   any               `json:"aud"` // may be string or []string
	Exp   int64             `json:"exp"`
	Nbf   int64             `json:"nbf"`
	Iat   int64             `json:"iat"`
	Scope string            `json:"scope"`
	Extra map[string]string `json:"ext"`
}

func (c *AuthClient) ValidateToken(ctx context.Context, token string) (*ssoclient.Subject, error) {
	if token == "" {
		return nil, errors.New("ssoclient/remote: token required")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("ssoclient/remote: malformed token")
	}

	kid, err := parseTokenKID(parts[0])
	if err != nil {
		return nil, err
	}

	jwk, err := c.jwks.getJWK(ctx, kid)
	if err != nil {
		return nil, err
	}

	// Verify against ONLY the kid-selected key (a single-element bundle), so a
	// token cannot be validated against a different published key than its
	// header names.
	pldRaw, err := security.VerifyCompactJWS(token, []core.JWK{jwk}, security.AsymmetricJWSAlgs())
	if err != nil {
		return nil, fmt.Errorf("ssoclient/remote: %w", err)
	}

	var p jwtPayload
	if err := json.Unmarshal(pldRaw, &p); err != nil {
		return nil, fmt.Errorf("ssoclient/remote: payload parse: %w", err)
	}

	if err := validateTokenTime(p); err != nil {
		return nil, err
	}

	return subjectFromPayload(p), nil
}

// parseTokenKID decodes only the header `kid` to select the cached JWK — the
// alg gate, signature verification, and kty/crv↔alg consistency are all
// delegated to security.VerifyCompactJWS (which rejects alg=none and every
// symmetric HS* alg before any signature work, so an attacker cannot downgrade
// an asymmetric token to "unsigned" nor force the RS/HS public-key-as-HMAC
// confusion).
func parseTokenKID(headerSegment string) (string, error) {
	hdrRaw, err := base64.RawURLEncoding.DecodeString(headerSegment)
	if err != nil {
		return "", fmt.Errorf("ssoclient/remote: header decode: %w", err)
	}
	var h jwtHeader
	if err := json.Unmarshal(hdrRaw, &h); err != nil {
		return "", fmt.Errorf("ssoclient/remote: header parse: %w", err)
	}
	return h.Kid, nil
}

// validateTokenTime enforces exp/nbf using the same clock and inclusive/
// exclusive boundaries as the original inline checks.
func validateTokenTime(p jwtPayload) error {
	now := time.Now().Unix()
	if p.Exp != 0 && now >= p.Exp {
		return errors.New("ssoclient/remote: token expired")
	}
	if p.Nbf != 0 && now < p.Nbf {
		return errors.New("ssoclient/remote: token not yet valid")
	}
	return nil
}

// subjectFromPayload maps verified claims to the public Subject shape.
func subjectFromPayload(p jwtPayload) *ssoclient.Subject {
	subj := &ssoclient.Subject{
		ID:        p.Sub,
		ExpiresAt: p.Exp,
		Attrs:     p.Extra,
	}
	subj.Audience = normalizeAudience(p.Aud)
	if p.Scope != "" {
		subj.Scopes = strings.Split(p.Scope, " ")
	}
	return subj
}

// Logout posts to the configured URL when set. Without a URL, only the
// JWT expiry guarantees revocation — fine for short-lived tokens but
// callers must understand the trade-off.
func (c *AuthClient) Logout(ctx context.Context, req *ssoclient.LogoutRequest) error {
	if c.logoutURL == "" || req == nil {
		return nil
	}
	body, _ := json.Marshal(map[string]string{
		"session_id": req.SessionID,
	})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.logoutURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if req.AccessToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+req.AccessToken)
	}
	resp, err := c.httpc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("ssoclient/remote: logout: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("ssoclient/remote: logout status %d", resp.StatusCode)
	}
	return nil
}

// normalizeAudience handles the "aud" claim variability: spec allows either
// a single string or an array of strings.
func normalizeAudience(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
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
