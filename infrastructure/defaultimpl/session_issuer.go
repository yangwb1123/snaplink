package defaultimpl

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
)

const (
	sessionTokenBytes      = 32
	defaultSessionTokenTTL = 24 * time.Hour
)

// SessionTokenIssuer is an opaque-token TokenIssuer: AccessToken is a random
// session ID, claims are stored server-side, and Validate is a hash-map lookup.
//
// Use it for relying parties that prefer revoke-by-delete semantics over
// stateless self-contained tokens, or as the strategy for browser apps that
// just need a long-lived bearer cookie.
type SessionTokenIssuer struct {
	tokens sync.Map // tokenID -> *sessionEntry
	ttl    time.Duration
}

type sessionEntry struct {
	claims    *sso.TokenClaims
	expiresAt time.Time
}

type SessionIssuerOption func(*SessionTokenIssuer)

func WithSessionTokenTTL(ttl time.Duration) SessionIssuerOption {
	return func(s *SessionTokenIssuer) { s.ttl = ttl }
}

func NewSessionTokenIssuer(opts ...SessionIssuerOption) *SessionTokenIssuer {
	s := &SessionTokenIssuer{ttl: defaultSessionTokenTTL}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *SessionTokenIssuer) Issue(_ context.Context, subject *sso.Subject, scopes []string) (*sso.Token, error) {
	if subject == nil || subject.ID == "" {
		return nil, errors.New("session_issuer: subject required")
	}
	buf := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("session_issuer: generate token: %w", err)
	}
	tokenID := base64.RawURLEncoding.EncodeToString(buf)
	now := time.Now()
	expiresAt := now.Add(s.ttl)

	s.tokens.Store(tokenID, &sessionEntry{
		claims: &sso.TokenClaims{
			Subject:   subject.ID,
			Scopes:    scopes,
			ExpiresAt: expiresAt,
			NotBefore: now,
			IssuedAt:  now,
			Extra:     subject.Claims,
		},
		expiresAt: expiresAt,
	})

	return &sso.Token{
		AccessToken: tokenID,
		TokenType:   sso.TokenTypeBearer,
		ExpiresIn:   int(s.ttl.Seconds()),
		Scope:       strings.Join(scopes, " "),
		CreatedAt:   now,
	}, nil
}

func (s *SessionTokenIssuer) Validate(_ context.Context, token string) (*sso.TokenClaims, error) {
	v, ok := s.tokens.Load(token)
	if !ok {
		return nil, errors.New("session_issuer: invalid token")
	}
	entry := v.(*sessionEntry)
	if time.Now().After(entry.expiresAt) {
		s.tokens.Delete(token)
		return nil, errors.New("session_issuer: token expired")
	}
	return entry.claims, nil
}

// Revoke is tolerant of unknown tokens — callers may sweep across multiple
// issuers and we want only the issuer that owns the token to actually delete.
func (s *SessionTokenIssuer) Revoke(_ context.Context, token string) error {
	if _, ok := s.tokens.LoadAndDelete(token); !ok {
		return errors.New("session_issuer: token not found")
	}
	return nil
}
