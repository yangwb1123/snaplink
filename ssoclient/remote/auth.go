// Package remote implements ssoclient.{Auth,Authz,Audit}Client by calling
// the SSO server over the network — gRPC for hot paths (authz, audit) and
// HTTP for token validation (JWKS fetch + local Ed25519 verify).
//
// The remote AuthClient does NOT call /userinfo to validate tokens — it
// verifies signatures locally with cached JWKS, so the SSO server isn't on
// the per-request path.
package remote

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

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

	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("ssoclient/remote: header decode: %w", err)
	}
	var h jwtHeader
	if err := json.Unmarshal(hdrRaw, &h); err != nil {
		return nil, fmt.Errorf("ssoclient/remote: header parse: %w", err)
	}
	if h.Alg != "EdDSA" {
		return nil, fmt.Errorf("ssoclient/remote: unsupported alg %q", h.Alg)
	}

	pub, err := c.jwks.Get(ctx, h.Kid)
	if err != nil {
		return nil, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("ssoclient/remote: signature decode: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return nil, errors.New("ssoclient/remote: signature invalid")
	}

	pldRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("ssoclient/remote: payload decode: %w", err)
	}
	var p jwtPayload
	if err := json.Unmarshal(pldRaw, &p); err != nil {
		return nil, fmt.Errorf("ssoclient/remote: payload parse: %w", err)
	}

	now := time.Now().Unix()
	if p.Exp != 0 && now >= p.Exp {
		return nil, errors.New("ssoclient/remote: token expired")
	}
	if p.Nbf != 0 && now < p.Nbf {
		return nil, errors.New("ssoclient/remote: token not yet valid")
	}

	subj := &ssoclient.Subject{
		ID:        p.Sub,
		ExpiresAt: p.Exp,
		Attrs:     p.Extra,
	}
	subj.Audience = normalizeAudience(p.Aud)
	if p.Scope != "" {
		subj.Scopes = strings.Split(p.Scope, " ")
	}
	return subj, nil
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
	defer resp.Body.Close()
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
