// Package remote implements ssoclient.{Auth,Authz,Audit}Client by calling
// the SSO server over the network — gRPC for hot paths (authz, audit) and
// HTTP for token validation (JWKS fetch + local signature verify).
//
// The remote AuthClient does NOT call /userinfo to validate tokens — it
// verifies signatures locally with cached JWKS, so the SSO server isn't on
// the per-request path. It accepts the full asymmetric alg set the server can
// emit (EdDSA / ES256-512 / RS256-512 / PS256-512) via the shared,
// alg-confusion-safe security.VerifyCompactJWS primitive.
//
// Issuer pinning is REQUIRED: ValidateToken fails closed with
// ssoclient.ErrIssuerRequired until WithIssuer is wired — the facade must
// not be weaker than the rs layer it wraps (rs.Config.Issuer is required
// and matched exactly). Audience enforcement is opt-in via WithExpectedAud.
// Logout speaks two server contracts: the session-logout JSON API
// (POST /logout via WithLogoutURL) and RFC 7009 token revocation
// (POST /token/revoke via WithRevokeURL) — see AuthClient.Logout.
package remote

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
)

// AuthClient validates JWTs locally via JWKS and revokes via the SSO server's
// HTTP /logout and /token/revoke endpoints. JWKSCache lifecycle is owned by
// the caller (so multiple clients can share one cache).
type AuthClient struct {
	jwks         *JWKSCache
	httpc        *http.Client
	issuer       string // required; WithIssuer — fail-closed when empty
	expectedAud  string // optional; WithExpectedAud — gate skipped when empty
	logoutURL    string // optional; session-logout JSON API (POST /logout)
	revokeURL    string // optional; RFC 7009 token revocation (POST /token/revoke)
	revokeID     string // client credentials for the revoke endpoint
	revokeSecret string
}

type AuthOption func(*AuthClient)

// WithAuthHTTPClient customizes the *http.Client used for Logout and
// revocation.
func WithAuthHTTPClient(c *http.Client) AuthOption {
	return func(a *AuthClient) {
		if c != nil {
			a.httpc = c
		}
	}
}

// WithIssuer pins the expected `iss` claim, matched exactly (rs semantics,
// rs/claims.go). Required: ValidateToken fails closed with
// ssoclient.ErrIssuerRequired until set, mirroring rs.Config.Issuer
// ("REQUIRED", rs/rs.go). The local implementation has no issuer pin because
// its trust anchor is the in-process sso.TokenIssuer instance — the signing
// key IS the issuer binding.
func WithIssuer(issuer string) AuthOption {
	return func(a *AuthClient) { a.issuer = issuer }
}

// WithExpectedAud requires the token's `aud` claim (string or array form) to
// contain the given value; a token without `aud` fails closed when the
// expectation is set. Empty expectation (the default) skips the gate. The
// value is a claim expectation, not a client-registry lookup: pin whatever
// the App's mint path actually stamps — RFC 8707 resource indicators on the
// server's token path, or sso.Subject.Resources for defaultimpl mints.
// Semantics mirror rs.Config.ExpectedAud (rs/claims.go).
func WithExpectedAud(aud string) AuthOption {
	return func(a *AuthClient) { a.expectedAud = aud }
}

// WithLogoutURL targets the SSO server's session-logout JSON API
// (POST /logout, server_logout.go), which destroys the named session and
// revokes any bearer it carries. This is NOT token revocation: Logout
// requests carrying an AccessToken are routed to WithRevokeURL instead. The
// OIDC RP-Initiated Logout flow (GET /end_session) is a user-agent redirect
// flow and must not be pointed at here.
func WithLogoutURL(url string) AuthOption {
	return func(a *AuthClient) { a.logoutURL = url }
}

// WithRevokeURL targets the SSO server's RFC 7009 token revocation endpoint
// (POST /token/revoke). Logout requests carrying an AccessToken are revoked
// here as form-encoded token + token_type_hint=access_token with HTTP Basic
// client credentials (server precedence: Basic wins over body creds —
// handle_revoke.go). The server answers 200 on valid credentials regardless
// of token existence, so a 2xx response IS the revocation confirmation; any
// non-2xx is an error. Client credentials are mandatory parameters: the
// server 401s without valid creds, and the facade refuses to construct a
// configured-but-broken path.
func WithRevokeURL(url, clientID, clientSecret string) AuthOption {
	return func(a *AuthClient) {
		a.revokeURL = url
		a.revokeID = clientID
		a.revokeSecret = clientSecret
	}
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
	// Config gate BEFORE any token work, like rs's ErrConfig gate: a client
	// without an issuer pin must not silently validate against nothing.
	if c.issuer == "" {
		return nil, fmt.Errorf("%w: WithIssuer required", ssoclient.ErrIssuerRequired)
	}
	p, err := c.verifiedPayload(ctx, token)
	if err != nil {
		return nil, err
	}
	if p.Iss != c.issuer {
		return nil, fmt.Errorf("%w: iss %q", ssoclient.ErrIssuerMismatch, p.Iss)
	}
	if err := validateTokenTime(p); err != nil {
		return nil, err
	}
	if c.expectedAud != "" && !hasAudience(normalizeAudience(p.Aud), c.expectedAud) {
		return nil, ssoclient.ErrAudienceMismatch
	}
	return subjectFromPayload(p), nil
}

func (c *AuthClient) verifiedPayload(ctx context.Context, token string) (jwtPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwtPayload{}, errors.New("ssoclient/remote: malformed token")
	}
	kid, err := parseAccessTokenKID(parts[0])
	if err != nil {
		return jwtPayload{}, err
	}
	jwk, err := c.jwks.getJWK(ctx, kid)
	if err != nil {
		return jwtPayload{}, err
	}
	// Verify against ONLY the kid-selected key (a single-element bundle), so a
	// token cannot be validated against a different published key than its
	// header names.
	pldRaw, err := security.VerifyCompactJWS(token, []core.JWK{jwk}, security.AsymmetricJWSAlgs())
	if err != nil {
		return jwtPayload{}, fmt.Errorf("ssoclient/remote: %w", err)
	}
	var p jwtPayload
	if err := json.Unmarshal(pldRaw, &p); err != nil {
		return jwtPayload{}, fmt.Errorf("ssoclient/remote: payload parse: %w", err)
	}
	return p, nil
}

// parseAccessTokenKID authenticates the token's intended representation before
// selecting a key. Algorithm and key-type gates remain in VerifyCompactJWS.
func parseAccessTokenKID(headerSegment string) (string, error) {
	hdrRaw, err := base64.RawURLEncoding.DecodeString(headerSegment)
	if err != nil {
		return "", fmt.Errorf("ssoclient/remote: header decode: %w", err)
	}
	var h jwtHeader
	if err := json.Unmarshal(hdrRaw, &h); err != nil {
		return "", fmt.Errorf("ssoclient/remote: header parse: %w", err)
	}
	if !strings.EqualFold(h.Typ, "at+jwt") && !strings.EqualFold(h.Typ, "application/at+jwt") {
		return "", errors.New("ssoclient/remote: token is not an access token")
	}
	return h.Kid, nil
}

// validateTokenTime enforces the RFC 9068 §2.2 time gates using the same
// clock and inclusive/exclusive boundaries as the original inline checks.
// exp is REQUIRED (RFC 9068 §2.2) — a token without an expiry bound would
// otherwise validate until the signing key retires, which would make the
// facade weaker than the rs layer it wraps (rs rejects a missing exp as
// malformed, rs/claims.go).
func validateTokenTime(p jwtPayload) error {
	if p.Exp == 0 {
		return errors.New("ssoclient/remote: token missing exp")
	}
	now := time.Now().Unix()
	if now >= p.Exp {
		return errors.New("ssoclient/remote: token expired")
	}
	if p.Nbf != 0 && now < p.Nbf {
		return errors.New("ssoclient/remote: token not yet valid")
	}
	return nil
}

// subjectFromPayload maps verified claims to the public Subject shape. Runs
// only AFTER every claim gate passed, so Issuer/Audience here are the
// verified values.
func subjectFromPayload(p jwtPayload) *ssoclient.Subject {
	subj := &ssoclient.Subject{
		ID:        p.Sub,
		Issuer:    p.Iss,
		ExpiresAt: p.Exp,
		Attrs:     p.Extra,
	}
	subj.Audience = normalizeAudience(p.Aud)
	if p.Scope != "" {
		subj.Scopes = strings.Split(p.Scope, " ")
	}
	return subj
}

// hasAudience reports whether aud contains the expected value. Duplicated
// from rs/claims.go:HasAudience — remote cannot import rs (rs imports remote
// for JWKSCache); parity is enforced by tests, not shared code.
func hasAudience(aud []string, want string) bool {
	for _, a := range aud {
		if a == want {
			return true
		}
	}
	return false
}

// Logout revokes the supplied session and/or token, routing each field to
// the endpoint whose server contract it matches:
//
//   - SessionID   → POST <logoutURL>  (session-logout JSON API: body
//     {"session_id": ...}, plus a Bearer when the request also carries an
//     AccessToken, so the full-logout side effects — back-channel fan-out,
//     session-hub logout, audit — still fire for both-fields logouts)
//   - AccessToken → POST <revokeURL>  (RFC 7009 form fields + HTTP Basic)
//
// The contract is loud: an error is returned if any revocation could not be
// performed (missing endpoint, bad request, or transport failure); nil means
// every requested revocation request was sent and answered. Endpoint
// availability is checked BEFORE any request is sent, so a configuration
// error never produces a half-logout performed by the other leg.
func (c *AuthClient) Logout(ctx context.Context, req *ssoclient.LogoutRequest) error {
	if req == nil || (req.SessionID == "" && req.AccessToken == "") {
		return errors.New("ssoclient/remote: session_id or access_token required")
	}
	if req.AccessToken != "" && c.revokeURL == "" {
		return fmt.Errorf("%w: access-token revocation requires WithRevokeURL", ssoclient.ErrLogoutNotConfigured)
	}
	if req.SessionID != "" && c.logoutURL == "" {
		return fmt.Errorf("%w: session logout requires WithLogoutURL", ssoclient.ErrLogoutNotConfigured)
	}
	if req.SessionID != "" {
		if err := c.postLogout(ctx, req); err != nil {
			return err
		}
	}
	if req.AccessToken != "" {
		if err := c.postRevoke(ctx, req.AccessToken); err != nil {
			return err
		}
	}
	return nil
}

// postLogout destroys the named session via the server's session-logout JSON
// API (POST /logout). The wire shape matches exactly what handleLogout
// binds: a JSON body with session_id plus an optional bearer.
func (c *AuthClient) postLogout(ctx context.Context, req *ssoclient.LogoutRequest) error {
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

// postRevoke revokes an access token via RFC 7009: form-encoded token +
// token_type_hint with HTTP Basic client credentials. The server answers 200
// on valid credentials regardless of token existence, so 2xx is the
// revocation confirmation and any non-2xx is an error.
func (c *AuthClient) postRevoke(ctx context.Context, token string) error {
	form := url.Values{}
	form.Set("token", token)
	form.Set("token_type_hint", "access_token")
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.revokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	// The server's BindParams dispatches on Content-Type: form encoding is
	// REQUIRED for the fields to be read — a JSON or missing header would
	// 400 invalid_request.
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.SetBasicAuth(c.revokeID, c.revokeSecret)
	resp, err := c.httpc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("ssoclient/remote: revoke: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		if resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("ssoclient/remote: revoke status %d: check WithRevokeURL client credentials", resp.StatusCode)
		}
		return fmt.Errorf("ssoclient/remote: revoke status %d", resp.StatusCode)
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
