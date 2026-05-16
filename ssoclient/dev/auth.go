package dev

import (
	"context"
	"maps"

	"github.com/snaplink/sso/ssoclient"
)

// AuthClient is a stub ssoclient.AuthClient. ValidateToken returns
// the configured Subject regardless of the token bytes; Logout is a
// no-op.
//
// The default Subject is a generic "dev-user" with audience matching
// the empty string — fine for most "I just want my UI to render"
// flows. Use WithSubject for fuller fidelity (e.g. multiple audiences
// or custom Attrs to drive feature-flag code paths).
type AuthClient struct {
	subject *ssoclient.Subject
}

type authConfig struct {
	commonOption
	subject *ssoclient.Subject
}

// NewAuthClient constructs the stub. Emits the package's one-time
// stderr warning on first non-silent build.
func NewAuthClient(opts ...Option) *AuthClient {
	cfg := &authConfig{
		subject: defaultSubject(),
	}
	for _, opt := range opts {
		opt(cfg)
	}
	if !cfg.silent {
		warn("AuthClient")
	}
	return &AuthClient{subject: cfg.subject}
}

// WithSubject pins the Subject returned by every ValidateToken call.
// Takes precedence over WithUserID. Pass nil to use the default.
func WithSubject(s *ssoclient.Subject) Option {
	return func(c *authConfig) {
		if s != nil {
			c.subject = s
		}
	}
}

// WithUserID is a convenience for the most common override: change
// the Subject.ID without rebuilding the whole struct.
func WithUserID(id string) Option {
	return func(c *authConfig) {
		if c.subject == nil {
			c.subject = defaultSubject()
		}
		c.subject.ID = id
	}
}

// WithAttr writes a single key into Subject.Attrs (lazily allocates).
// Useful for exercising business code that branches on a JWT claim
// without composing a full Subject.
func WithAttr(key, value string) Option {
	return func(c *authConfig) {
		if c.subject == nil {
			c.subject = defaultSubject()
		}
		if c.subject.Attrs == nil {
			c.subject.Attrs = map[string]string{}
		}
		c.subject.Attrs[key] = value
	}
}

// ValidateToken returns the configured Subject. The bytes of accessToken
// are ignored — that's the point.
func (c *AuthClient) ValidateToken(_ context.Context, _ string) (*ssoclient.Subject, error) {
	// Defensive copy so callers mutating Attrs don't bleed into the
	// next ValidateToken caller. Cheap; happens at most once per
	// inbound request.
	cp := *c.subject
	if c.subject.Attrs != nil {
		cp.Attrs = make(map[string]string, len(c.subject.Attrs))
		maps.Copy(cp.Attrs, c.subject.Attrs)
	}
	return &cp, nil
}

// Logout is a no-op. Always returns nil.
func (c *AuthClient) Logout(_ context.Context, _ *ssoclient.LogoutRequest) error {
	return nil
}

func defaultSubject() *ssoclient.Subject {
	return &ssoclient.Subject{
		ID:       "dev-user",
		Audience: []string{"dev"},
		Scopes:   []string{"openid", "profile", "email"},
		Attrs: map[string]string{
			"email": "dev@local",
			"name":  "Dev User",
		},
	}
}

// Compile-time interface assertion.
var _ ssoclient.AuthClient = (*AuthClient)(nil)
