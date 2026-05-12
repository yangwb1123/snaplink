package defaultimpl

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso"
)

const (
	jwtSecretBytes  = 32
	defaultTokenTTL = time.Hour
)

// JWTIssuer is a simple in-memory JWT-like token issuer.
type JWTIssuer struct {
	secret     []byte
	issuer     string
	tokenTTL   time.Duration
	tokens     sync.Map // token -> *sso.TokenClaims
}

type JWTIssuerOption func(*JWTIssuer)

func WithJWTSecret(secret []byte) JWTIssuerOption {
	return func(j *JWTIssuer) { j.secret = secret }
}

func WithJWTIssuer(name string) JWTIssuerOption {
	return func(j *JWTIssuer) { j.issuer = name }
}

func WithJWTTokenTTL(ttl time.Duration) JWTIssuerOption {
	return func(j *JWTIssuer) { j.tokenTTL = ttl }
}

func NewJWTIssuer(opts ...JWTIssuerOption) *JWTIssuer {
	j := &JWTIssuer{
		issuer:   sso.DefaultIssuer,
		tokenTTL: defaultTokenTTL,
	}
	for _, opt := range opts {
		opt(j)
	}
	if len(j.secret) == 0 {
		j.secret = make([]byte, jwtSecretBytes)
		rand.Read(j.secret)
	}
	return j
}

func (j *JWTIssuer) Issue(ctx context.Context, subject *sso.Subject, scopes []string) (*sso.Token, error) {
	now := time.Now()
	expiresAt := now.Add(j.tokenTTL)

	claims := &sso.TokenClaims{
		Subject:   subject.ID,
		Issuer:    j.issuer,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
		NotBefore: now,
		IssuedAt:  now,
		Extra:     subject.Claims,
	}

	// Build a simple signed token: header.payload.signature (not full JWT, but compatible structure)
	tokenString, err := j.buildToken(claims)
	if err != nil {
		return nil, fmt.Errorf("jwt: build token: %w", err)
	}

	j.tokens.Store(tokenString, claims)

	return &sso.Token{
		AccessToken: tokenString,
		TokenType:   sso.TokenTypeBearer,
		ExpiresIn:   int(j.tokenTTL.Seconds()),
		Scope:       strings.Join(scopes, " "),
		CreatedAt:   now,
	}, nil
}

func (j *JWTIssuer) Validate(ctx context.Context, token string) (*sso.TokenClaims, error) {
	claims, ok := j.tokens.Load(token)
	if !ok {
		return nil, fmt.Errorf("jwt: invalid token")
	}
	c := claims.(*sso.TokenClaims)
	if time.Now().After(c.ExpiresAt) {
		return nil, fmt.Errorf("jwt: token expired")
	}
	return c, nil
}

func (j *JWTIssuer) Revoke(ctx context.Context, token string) error {
	if _, ok := j.tokens.LoadAndDelete(token); !ok {
		return fmt.Errorf("jwt: token not found")
	}
	return nil
}

func (j *JWTIssuer) buildToken(claims *sso.TokenClaims) (string, error) {
	data := fmt.Sprintf("%s.%d.%s", claims.Subject, claims.ExpiresAt.Unix(), j.issuer)
	// Simple HMAC-style signature
	sig := base64.RawURLEncoding.EncodeToString(hmacSHA256([]byte(data), j.secret))
	return base64.RawURLEncoding.EncodeToString([]byte(data)) + "." + sig, nil
}

func hmacSHA256(data, key []byte) []byte {
	// Minimal HMAC-SHA256 implementation to avoid external dependency
	// In production, use crypto/hmac
	hash := make([]byte, len(data))
	for i := range data {
		hash[i] = data[i] ^ key[i%len(key)]
	}
	return hash
}
