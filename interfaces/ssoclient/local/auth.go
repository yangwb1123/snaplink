// Package local implements ssoclient.{Auth,Authz,Audit}Client by directly
// invoking snaplink/sso SDK types in-process. Use it when the App embeds
// the SDK (monolithic mode) so business code stays decoupled from the
// "library vs network" deployment choice.
package local

import (
	"context"
	"errors"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/interfaces/ssoclient"
)

// AuthClient wraps an sso.TokenIssuer (and optionally a SessionManager for
// session-level logout). Construct with NewAuthClient and pass it where an
// ssoclient.AuthClient is expected.
type AuthClient struct {
	issuer     sso.TokenIssuer
	sessionMgr sso.SessionManager // optional; used by Logout for session_id
}

// Option mutates an AuthClient at construction. Currently only the session
// manager hook exists; new ones append here without touching the interface.
type Option func(*AuthClient)

// WithSessionManager enables session-id revocation in Logout. Without it,
// Logout will only revoke bearer tokens and silently ignore session_id.
func WithSessionManager(sm sso.SessionManager) Option {
	return func(c *AuthClient) { c.sessionMgr = sm }
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
	subj := &ssoclient.Subject{
		ID:       claims.Subject,
		Audience: append([]string{}, claims.Audience...),
		Scopes:   append([]string{}, claims.Scopes...),
		Attrs:    claims.Extra,
	}
	if !claims.ExpiresAt.IsZero() {
		subj.ExpiresAt = claims.ExpiresAt.Unix()
	}
	return subj, nil
}

func (c *AuthClient) Logout(ctx context.Context, req *ssoclient.LogoutRequest) error {
	if req == nil || (req.SessionID == "" && req.AccessToken == "") {
		return errors.New("ssoclient/local: session_id or access_token required")
	}
	var errs []error
	if req.AccessToken != "" {
		if err := c.issuer.Revoke(ctx, req.AccessToken); err != nil {
			errs = append(errs, err)
		}
	}
	if req.SessionID != "" && c.sessionMgr != nil {
		if err := c.sessionMgr.Destroy(ctx, req.SessionID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
