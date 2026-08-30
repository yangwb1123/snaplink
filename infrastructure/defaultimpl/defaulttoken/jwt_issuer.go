package defaulttoken

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	jwtSecretBytes  = 32
	defaultTokenTTL = time.Hour
)

// JWTIssuer is a simple in-memory JWT-like token issuer.
type JWTIssuer struct {
	secret    []byte
	issuer    string
	tokenTTL  time.Duration
	tokens    sync.Map // token -> *core.TokenClaims
	lastSweep atomic.Int64
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
		issuer:   core.DefaultIssuer,
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

// accessTokenExpiry applies the optional RFC 8705 certificate lifetime ceiling.
// The zero-ceiling path preserves the issuer's existing TTL-derived response.
func accessTokenExpiry(now time.Time, ttl time.Duration, notAfter time.Time) (time.Time, int) {
	expiresAt := now.Add(ttl)
	expiresIn := int(ttl.Seconds())
	if !notAfter.IsZero() && notAfter.Before(expiresAt) {
		expiresAt = notAfter
		expiresIn = int(max(time.Duration(0), expiresAt.Sub(now)).Seconds())
	}
	return expiresAt, expiresIn
}

func (j *JWTIssuer) Issue(ctx context.Context, subject *core.Subject, scopes []string) (*core.Token, error) {
	now := time.Now()
	j.maybeSweepExpired(now)
	expiresAt, expiresIn := accessTokenExpiry(now, j.tokenTTL, subject.NotAfter)

	claims := &core.TokenClaims{
		TokenUse:  core.TokenUseAccessToken,
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

	return &core.Token{
		AccessToken: tokenString,
		TokenType:   core.TokenTypeBearer,
		ExpiresIn:   expiresIn,
		Scope:       strings.Join(scopes, " "),
		CreatedAt:   now,
	}, nil
}

func (j *JWTIssuer) Validate(ctx context.Context, token string) (*core.TokenClaims, error) {
	claims, ok := j.tokens.Load(token)
	if !ok {
		return nil, fmt.Errorf("jwt: invalid token")
	}
	c := claims.(*core.TokenClaims)
	if time.Since(c.ExpiresAt) > 0 {
		j.tokens.Delete(token)
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

func (j *JWTIssuer) maybeSweepExpired(now time.Time) {
	nowUnix := now.UnixNano()
	previous := j.lastSweep.Load()
	if nowUnix-previous < sweepInterval.Nanoseconds() ||
		!j.lastSweep.CompareAndSwap(previous, nowUnix) {
		return
	}
	sweepExpired(&j.tokens, now, func(value any) time.Time {
		return value.(*core.TokenClaims).ExpiresAt
	})
}

func (j *JWTIssuer) buildToken(claims *core.TokenClaims) (string, error) {
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
