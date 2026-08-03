// Package local implements ssoclient.{Auth,Authz,Audit}Client by directly
// invoking snaplink/sso SDK types in-process. Use it when the App embeds
// the SDK (monolithic mode) so business code stays decoupled from the
// "library vs network" deployment choice.
package local

import (
	"context"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient"
	"github.com/yangwb1123/snaplink/shared/core"
)

// AuthClient wraps an sso.TokenIssuer (and optionally a SessionManager for
// session-level logout). Construct with NewAuthClient and pass it where an
// ssoclient.AuthClient is expected.
type AuthClient struct {
	issuer      sso.TokenIssuer
	sessionMgr  sso.SessionManager // optional; used by Logout for session_id
	expectedAud string             // optional; WithExpectedAud — gate skipped when empty
}

// Option mutates an AuthClient at construction. Currently only the session
// manager hook exists; new ones append here without touching the interface.
type Option func(*AuthClient)

// WithSessionManager enables session-id revocation in Logout. Without it, a
// SessionID-only Logout fails closed with ssoclient.ErrLogoutNotConfigured.
func WithSessionManager(sm sso.SessionManager) Option {
	return func(c *AuthClient) { c.sessionMgr = sm }
}

// WithExpectedAud requires the token's `aud` claim to contain the given
// value; a token without `aud` fails closed when the expectation is set.
// Empty expectation (the default) skips the gate. The local trust anchor is
// the in-process issuer — the signing key IS the issuer binding — so there
// is no issuer pin here, only the audience pin, which no key can express.
// Semantics mirror rs.Config.ExpectedAud (rs/claims.go).
func WithExpectedAud(aud string) Option {
	return func(c *AuthClient) { c.expectedAud = aud }
}

func NewAuthClient(issuer sso.TokenIssuer, opts ...Option) *AuthClient {
	c := &AuthClient{issuer: issuer}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *AuthClient) ValidateToken(ctx context.Context, accessToken string) (*ssoclient.Subject, error) {
	if accessToken == "" {
		return nil, errors.New("ssoclient/local: token required")
	}
	claims, err := c.issuer.Validate(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	if !core.IsAccessTokenClaims(claims) {
		return nil, errors.New("ssoclient/local: token is not an access token")
	}
	// Audience gate runs only on signature-verified claims; opt-in, with the
	// same containment semantics as rs.Config.ExpectedAud (rs/claims.go).
	if c.expectedAud != "" && !hasAudience(claims.Audience, c.expectedAud) {
		return nil, ssoclient.ErrAudienceMismatch
	}
	subj := &ssoclient.Subject{
		ID:       claims.Subject,
		Issuer:   claims.Issuer,
		Audience: append([]string{}, claims.Audience...),
		Scopes:   append([]string{}, claims.Scopes...),
		Attrs:    claims.Extra,
	}
	if !claims.ExpiresAt.IsZero() {
		subj.ExpiresAt = claims.ExpiresAt.Unix()
	}
	return subj, nil
}

// hasAudience reports whether aud contains the expected value. Duplicated
// from rs/claims.go:HasAudience (the facade packages cannot import rs);
// parity is enforced by tests, not shared code.
func hasAudience(aud []string, want string) bool {
	for _, a := range aud {
		if a == want {
			return true
		}
	}
	return false
}

func (c *AuthClient) Logout(ctx context.Context, req *ssoclient.LogoutRequest) error {
	if req == nil || (req.SessionID == "" && req.AccessToken == "") {
		return errors.New("ssoclient/local: session_id or access_token required")
	}
	// Pre-flight capability check, mirroring remote.Logout: a set field
	// without its capability is a configuration error reported BEFORE any
	// leg runs — never a silent no-op, never a half-logout.
	if req.SessionID != "" && c.sessionMgr == nil {
		return fmt.Errorf("%w: session revocation requires WithSessionManager", ssoclient.ErrLogoutNotConfigured)
	}
	var errs []error
	if req.AccessToken != "" {
		if err := c.issuer.Revoke(ctx, req.AccessToken); err != nil {
			errs = append(errs, err)
		}
	}
	if req.SessionID != "" {
		if err := c.sessionMgr.Destroy(ctx, req.SessionID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
