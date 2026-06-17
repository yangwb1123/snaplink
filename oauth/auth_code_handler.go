package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// PKCEMethodPlain is the PKCE challenge method "plain" (RFC 7636 §4.3).
const PKCEMethodPlain = "plain"

// PKCEMethodS256 is the PKCE challenge method "S256" (RFC 7636 §4.3).
const PKCEMethodS256 = "S256"

// IsSecureRedirectURI reports whether the URI satisfies the OAuth 2.1
// §4.1.3 redirect_uri security profile: scheme=https required for
// public hosts; http://localhost (or http://127.0.0.1 / [::1]) on any
// port stays permitted so development workflows don't need a local
// TLS terminator. URIs that fail to parse return false (closed
// default), which collapses to invalid_redirect_uri on the caller.
func IsSecureRedirectURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil || u == nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return false
}

// IsValidPKCEMethod reports whether the named PKCE challenge method is
// one we support. Empty defaults to "plain" per RFC 7636 §4.3 (the
// caller stamps the default after this check); "S256" is the strongly
// recommended method for production.
func IsValidPKCEMethod(method string) bool {
	return method == "" || method == PKCEMethodPlain || method == PKCEMethodS256
}

// IsPKCEMethodAllowedForClient reports whether the (already-validated)
// PKCE challenge method is permitted under the client's per-client
// allowlist. Empty allowlist = unrestricted (legacy behavior, accept
// anything IsValidPKCEMethod accepted). Empty method input means the
// default was applied — must be allowlisted too.
func IsPKCEMethodAllowedForClient(method string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == method {
			return true
		}
	}
	return false
}

// VerifyPKCE returns true when the supplied verifier derives to the
// stored challenge under the named method. Constant-time comparison
// closes off timing-oracle attacks on the challenge value.
//
// An empty challenge means no PKCE binding was set at issue; callers
// MUST NOT invoke this helper in that case (the exchange skips PKCE
// entirely when info.CodeChallenge is empty — backwards compatible
// with confidential clients).
func VerifyPKCE(method, challenge, verifier string) bool {
	switch method {
	case PKCEMethodS256:
		sum := sha256.Sum256([]byte(verifier))
		derived := base64.RawURLEncoding.EncodeToString(sum[:])
		return subtle.ConstantTimeCompare([]byte(derived), []byte(challenge)) == 1
	case PKCEMethodPlain, "":
		return subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) == 1
	default:
		return false
	}
}

// GenerateAuthCodeBytes mints a cryptographically random base64url code.
// Used for authorization codes, refresh tokens, and other opaque tokens.
func GenerateAuthCodeBytes() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// IsScopeSubset reports whether every scope in want is also in have.
// Used by the refresh_token grant to enforce RFC 6749 §6's "MUST NOT
// expand scope" rule — a refresh request may downscope or keep the
// original grant but never widen it.
func IsScopeSubset(want, have []string) bool {
	if len(want) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(have))
	for _, s := range have {
		set[s] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; !ok {
			return false
		}
	}
	return true
}

// IssueAuthCodeParams contains the parameters for issuing an auth code.
type IssueAuthCodeParams struct {
	AuthCodeTTL          time.Duration
	AuthCodeStore        AuthCodeStore
	UserID               string
	ClientID             string
	RedirectURI          string
	Scopes               []string
	Nonce                string
	Provider             string
	AuthMethods          []string
	ACR                  string
	Attributes           map[string]string
	CodeChallenge        string
	CodeChallengeMethod  string
	Resources            []string
	AuthorizationDetails json.RawMessage
	SID                  string
}

// IssueAuthCode generates and stores an authorization code.
// Returns the code string or an error.
func IssueAuthCode(ctx context.Context, p IssueAuthCodeParams) (string, error) {
	code, err := GenerateAuthCodeBytes()
	if err != nil {
		return "", fmt.Errorf("generate auth code: %w", err)
	}
	ttl := p.AuthCodeTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute // DefaultAuthCodeTTL fallback
	}
	entry := &AuthCode{
		UserID:               p.UserID,
		ClientID:             p.ClientID,
		RedirectURI:          p.RedirectURI,
		Scopes:               append([]string(nil), p.Scopes...),
		Nonce:                p.Nonce,
		Provider:             p.Provider,
		AuthTime:             time.Now(),
		AuthMethods:          p.AuthMethods,
		ACR:                  p.ACR,
		Attributes:           p.Attributes,
		CodeChallenge:        p.CodeChallenge,
		CodeChallengeMethod:  p.CodeChallengeMethod,
		Resources:            append([]string(nil), p.Resources...),
		AuthorizationDetails: CloneRawJSON(p.AuthorizationDetails),
		SID:                  p.SID,
		ExpiresAt:            time.Now().Add(ttl),
	}
	if err := p.AuthCodeStore.Issue(ctx, code, entry); err != nil {
		return "", fmt.Errorf("store auth code: %w", err)
	}
	return code, nil
}

// IssueRefreshTokenParams contains the parameters for issuing a refresh token.
type IssueRefreshTokenParams struct {
	RefreshTokenTTL  time.Duration
	RefreshTokenStore interface {
		Issue(ctx context.Context, token string, info *RefreshToken) error
	}
	UserID             string
	ClientID           string
	Provider           string
	Scopes             []string
	Attributes         map[string]string
	FamilyID           string
	Resources          []string
	AuthorizationDetails json.RawMessage
	SID                string
	ClientTTLOverride  time.Duration
}

// IssueRefreshToken generates and stores a refresh token.
// Returns the token string or an error.
func IssueRefreshToken(ctx context.Context, p IssueRefreshTokenParams) (string, error) {
	token, err := GenerateAuthCodeBytes()
	if err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	// TTL resolution precedence: per-client override > server-wide
	// configuration > default.
	ttl := p.ClientTTLOverride
	if ttl <= 0 {
		ttl = p.RefreshTokenTTL
	}
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour // DefaultRefreshTokenTTL fallback
	}
	if p.FamilyID == "" {
		fid, err := GenerateAuthCodeBytes()
		if err != nil {
			return "", fmt.Errorf("generate refresh family id: %w", err)
		}
		p.FamilyID = fid
	}
	now := time.Now()
	entry := &RefreshToken{
		UserID:               p.UserID,
		ClientID:             p.ClientID,
		Provider:             p.Provider,
		Scopes:               append([]string(nil), p.Scopes...),
		Attributes:           p.Attributes,
		IssuedAt:             now,
		ExpiresAt:            now.Add(ttl),
		FamilyID:             p.FamilyID,
		Resources:            append([]string(nil), p.Resources...),
		AuthorizationDetails: CloneRawJSON(p.AuthorizationDetails),
		SID:                  p.SID,
	}
	if err := p.RefreshTokenStore.Issue(ctx, token, entry); err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}
	return token, nil
}
