package oauthwire

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

	"github.com/snaplink/sso/protocols/oauth/oauthspi"
	"github.com/snaplink/sso/protocols/oauth/oauthvalidate"
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
	AuthCodeStore        oauthspi.AuthCodeStore
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
	// ConfirmationJKT binds the issued code to the DPoP key the client
	// presented at /auth/login (RFC 9449 §10). Empty = unbound — the
	// exchange skips the jkt gate entirely.
	ConfirmationJKT string
	// RequestedClaims is the OIDC Core §5.5 `claims` parameter (raw
	// JSON) persisted on the code so the /token exchange honors it —
	// see oauthspi.AuthCode.RequestedClaims. Empty = no-op.
	RequestedClaims json.RawMessage
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
	entry := &oauthspi.AuthCode{
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
		AuthorizationDetails: oauthvalidate.CloneRawJSON(p.AuthorizationDetails),
		SID:                  p.SID,
		ConfirmationJKT:      p.ConfirmationJKT,
		RequestedClaims:      oauthvalidate.CloneRawJSON(p.RequestedClaims),
		ExpiresAt:            time.Now().Add(ttl),
	}
	if err := p.AuthCodeStore.Issue(ctx, code, entry); err != nil {
		return "", fmt.Errorf("store auth code: %w", err)
	}
	return code, nil
}

// IssueRefreshTokenParams contains the parameters for issuing a refresh token.
type IssueRefreshTokenParams struct {
	RefreshTokenTTL   time.Duration
	RefreshTokenStore interface {
		Issue(ctx context.Context, token string, info *oauthspi.RefreshToken) error
	}
	UserID               string
	ClientID             string
	Provider             string
	Scopes               []string
	Attributes           map[string]string
	FamilyID             string
	Resources            []string
	AuthorizationDetails json.RawMessage
	SID                  string
	// AMR / ACR / AuthTime are the original authentication-event claims (RFC
	// 9068 §2.2) persisted so rotation can re-stamp them unchanged. Empty =
	// pre-feature behavior (Provider fallback / claim omitted).
	AMR               []string
	ACR               string
	AuthTime          time.Time
	ClientTTLOverride time.Duration
	// ConfirmationJKT binds this refresh token to the DPoP key the client
	// used at issue time (RFC 9449 §5). Empty = unbound.
	ConfirmationJKT string
	// Generation is the new token's rotation depth (0 at first issue,
	// parent+1 at rotation) — the token-policy max_refresh_depth input.
	Generation int
	// FamilyCreatedAt propagates the family's original issuance moment across
	// a ROTATION (FamilyID already set). Ignored on a first issue (FamilyID
	// empty) — IssueRefreshToken stamps "now" itself in that branch, since
	// there is no earlier record to propagate from. Zero on a rotation call
	// means the caller's record predates this field; the absolute-max-
	// lifetime cap then simply never fires for that family (additive-
	// migration default, see oauthspi.RefreshToken.FamilyCreatedAt).
	FamilyCreatedAt time.Time
}

// IssueRefreshToken generates and stores a refresh token.
// Returns the token string or an error.
func IssueRefreshToken(ctx context.Context, p IssueRefreshTokenParams) (string, error) {
	token, err := GenerateAuthCodeBytes()
	if err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	ttl := resolveRefreshTTL(p)
	freshFamily := p.FamilyID == ""
	if freshFamily {
		fid, err := GenerateAuthCodeBytes()
		if err != nil {
			return "", fmt.Errorf("generate refresh family id: %w", err)
		}
		p.FamilyID = fid
	}
	entry := buildRefreshTokenEntry(p, ttl, freshFamily)
	if err := p.RefreshTokenStore.Issue(ctx, token, entry); err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}
	return token, nil
}

// resolveRefreshTTL applies the TTL resolution precedence: per-client
// override > server-wide configuration > default. Extracted from
// IssueRefreshToken for the function-length budget.
func resolveRefreshTTL(p IssueRefreshTokenParams) time.Duration {
	if p.ClientTTLOverride > 0 {
		return p.ClientTTLOverride
	}
	if p.RefreshTokenTTL > 0 {
		return p.RefreshTokenTTL
	}
	return 30 * 24 * time.Hour // DefaultRefreshTokenTTL fallback
}

// buildRefreshTokenEntry assembles the persisted RefreshToken record.
// freshFamily is true when p.FamilyID was empty at call time (IssueRefreshToken
// has already minted a fresh one by the time this runs) — the absolute-max-
// lifetime clock (FamilyCreatedAt) then starts NOW, since there is no earlier
// record to propagate from; a rotation instead propagates whatever the
// caller supplied. Extracted from IssueRefreshToken for the function-length
// budget.
func buildRefreshTokenEntry(p IssueRefreshTokenParams, ttl time.Duration, freshFamily bool) *oauthspi.RefreshToken {
	now := time.Now()
	familyCreatedAt := p.FamilyCreatedAt
	if freshFamily {
		familyCreatedAt = now
	}
	return &oauthspi.RefreshToken{
		UserID:               p.UserID,
		ClientID:             p.ClientID,
		Provider:             p.Provider,
		Scopes:               append([]string(nil), p.Scopes...),
		Attributes:           p.Attributes,
		IssuedAt:             now,
		ExpiresAt:            now.Add(ttl),
		FamilyID:             p.FamilyID,
		Resources:            append([]string(nil), p.Resources...),
		AuthorizationDetails: oauthvalidate.CloneRawJSON(p.AuthorizationDetails),
		SID:                  p.SID,
		Amr:                  append([]string(nil), p.AMR...),
		Acr:                  p.ACR,
		AuthTime:             p.AuthTime,
		ConfirmationJKT:      p.ConfirmationJKT,
		Generation:           p.Generation,
		FamilyCreatedAt:      familyCreatedAt,
	}
}
