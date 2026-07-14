package authenticators

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
)

// OIDCFederationAuthenticator delegates authentication to an
// upstream OAuth 2.0 / OIDC provider (Google, Microsoft, GitHub,
// Auth0, Keycloak, etc.). Implements the standard OAuth 2.0
// authorization-code flow:
//
//  1. LoginURL builds the upstream `authorization_endpoint?...&state=...`
//     URL — the SDK redirects the user-agent there.
//  2. The upstream IdP authenticates the user + redirects back to the
//     AS's /callback endpoint with `code` + `state`.
//  3. Callback POSTs the code to the upstream `token_endpoint` (client_secret
//     in HTTP Basic per RFC 6749 §2.3.1) + fetches userinfo from
//     `userinfo_endpoint`.
//
// The returned AuthResult carries:
//   - ExternalID  — the upstream `sub` claim. Stable per-user identifier.
//   - UserID      — by default same as ExternalID; operators can plug
//     a [UserLinker] (see [WithUserLinker]) to map upstream sub onto an
//     internal account id.
//   - Attributes  — every other claim returned by userinfo (email,
//     name, picture, etc.) projected as string values.
//
// Spec compliance scope:
//   - OAuth 2.0 §4.1 authorization-code flow (full).
//   - OIDC Core scope handling — the configured Scopes list is sent
//     to the IdP verbatim; "openid" + "profile" + "email" is the
//     usual production minimum.
//   - PKCE on the upstream flow is OUT OF SCOPE for v1 — would
//     require per-request code_verifier storage keyed by state.
//     Operators wanting upstream PKCE today should plug a custom
//     Authenticator with their own state store.
//   - ID-token validation is OUT OF SCOPE — Userinfo fetch is the
//     v1 source of truth. Operators that need ID-token claims
//     (essential `acr`, `amr`, etc.) should add a follow-up signer
//     verification.
type OIDCFederationAuthenticator struct {
	cfg       OIDCFederationConfig
	client    *http.Client
	linker    UserLinker
	acrMapper ACRMapper
}

// UserLinker maps an external (provider, subject) pair — provider is the
// authenticator's configured Name, subject is the resolved external `sub` (or
// SubjectFieldOverride claim) — onto the local account a federated login
// should resolve to. Optional: a nil UserLinker (the default, and the
// zero-value OIDCFederationAuthenticator's behavior) leaves AuthResult.UserID
// as the raw external subject, BYTE-IDENTICAL to this authenticator's
// original behavior before UserLinker existed.
//
// This is the hook the package doc above has long promised ("operators can
// plug a UserLinker") without it existing as code. domains/identitylink's
// NewAuthenticatorLinker is the ready-made implementation, backed by an
// identitylink.Store + identitylink.MergePolicy — see that package's doc
// comment for the full account-linking/merge design this seam plugs into.
//
// An error from ResolveUserID fails Callback outright: the caller MUST NOT
// let the failure's shape differ from any other Callback error (oracle-leak
// hardening, AGENTS.md §3 — e.g. identitylink.Resolve's ErrAccountConflict
// must not be distinguishable from a network error talking to the upstream
// IdP). Callback returns it unwrapped, exactly like every other Callback
// error path.
type UserLinker interface {
	ResolveUserID(ctx context.Context, provider, subject string) (userID string, err error)
}

// ACRMapper normalizes a federated identity provider's authentication-context
// signal — an OIDC upstream `acr` claim today; a SAML AuthnContextClassRef URI
// once infrastructure/saml exposes one from an incoming assertion — onto this
// SDK's OWN acr vocabulary: the free-form string AuthResult.AchievedACR
// carries, which the AS stamps as the id_token `acr` claim and checks against
// acr_values (and which a conditional-access policy can gate on, the same way
// it already gates on Conditions.RiskScore). Without a mapper, a federated
// login's upstream ACR is either dropped or passed through raw and unusable by
// policy — see [WithACRMapper]. domains/authenticators/acrmap.PatternACRMapper
// is the reference implementation (exact -> regex -> prefix -> default
// cascade, config-loadable).
//
// MapACR MUST be pure (no I/O) and MUST NEVER return an error: an empty
// upstreamACR (no claim reported by the upstream IdP) or an upstream value
// matching no configured rule both resolve to "" — "no claim", i.e.
// AuthResult.AchievedACR stays unset, exactly as if no mapper were wired. A
// federated login's success MUST NOT depend on the upstream IdP's ACR
// reporting.
type ACRMapper interface {
	MapACR(upstreamACR string) string
}

// OIDCFederationOption configures an OIDCFederationAuthenticator at
// construction. Additive: existing NewOIDCFederationAuthenticator(cfg) call
// sites (no opts) are unaffected by a new option being introduced.
type OIDCFederationOption func(*OIDCFederationAuthenticator)

// WithUserLinker wires an optional UserLinker (see its doc). Passing a nil
// linker — or simply not passing this option — keeps Callback's original
// behavior: AuthResult.UserID defaults to the raw external subject.
func WithUserLinker(l UserLinker) OIDCFederationOption {
	return func(o *OIDCFederationAuthenticator) { o.linker = l }
}

// WithACRMapper wires an optional ACRMapper (see its doc). Passing a nil
// mapper — or simply not passing this option — keeps Callback's original
// behavior: AuthResult.AchievedACR is never set from federation, BYTE-
// IDENTICAL to this authenticator's behavior before ACRMapper existed.
func WithACRMapper(m ACRMapper) OIDCFederationOption {
	return func(o *OIDCFederationAuthenticator) { o.acrMapper = m }
}

// OIDCFederationConfig is the operator-supplied IdP description.
// Fields map 1:1 to OIDC Discovery 1.0 metadata when bootstrapping
// from .well-known/openid-configuration.
type OIDCFederationConfig struct {
	// Name is the authenticator name + the value clients pass in
	// `provider=<name>` to choose this IdP at /auth/login.
	Name string

	// AuthorizationEndpoint is the upstream URL the user-agent is
	// redirected to for login + consent.
	AuthorizationEndpoint string

	// TokenEndpoint is the upstream URL the AS POSTs the
	// authorization code to.
	TokenEndpoint string

	// UserinfoEndpoint is the upstream URL the AS GETs claims from
	// using the bearer token returned by TokenEndpoint. Empty
	// disables the userinfo fetch — the AuthResult then carries
	// only the `sub`/scope-derived bits the token response itself
	// returned.
	UserinfoEndpoint string

	// ClientID + ClientSecret are the AS's registered credentials
	// at the upstream IdP. Passed via HTTP Basic on the token
	// endpoint (RFC 6749 §2.3.1).
	ClientID     string
	ClientSecret string

	// RedirectURI is where the upstream IdP sends the user-agent
	// after authentication. MUST be one of the AS's registered
	// redirect URIs with the upstream IdP.
	RedirectURI string

	// Scopes requested at the upstream IdP. OIDC mandates "openid"
	// for any provider that returns an id_token; "profile" + "email"
	// are the usual production minimum.
	Scopes []string

	// SubjectFieldOverride maps a userinfo claim name onto the AS's
	// ExternalID. Defaults to "sub" (OIDC Core). Set to "email" for
	// pre-OIDC OAuth providers (GitHub `email`, etc.) that return
	// no `sub`.
	SubjectFieldOverride string

	// Timeout caps the upstream HTTP call duration (token endpoint +
	// userinfo endpoint each). Default 10s.
	Timeout time.Duration
}

// NewOIDCFederationAuthenticator validates cfg + returns the
// authenticator. Required fields:
//   - Name
//   - AuthorizationEndpoint
//   - TokenEndpoint
//   - ClientID + ClientSecret
//   - RedirectURI
func NewOIDCFederationAuthenticator(cfg OIDCFederationConfig, opts ...OIDCFederationOption) (*OIDCFederationAuthenticator, error) {
	if cfg.Name == "" {
		return nil, errors.New("oidc-federation: name required")
	}
	if cfg.AuthorizationEndpoint == "" || cfg.TokenEndpoint == "" {
		return nil, errors.New("oidc-federation: authorization_endpoint + token_endpoint required")
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("oidc-federation: client_id + client_secret required")
	}
	if cfg.RedirectURI == "" {
		return nil, errors.New("oidc-federation: redirect_uri required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	o := &OIDCFederationAuthenticator{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
	for _, opt := range opts {
		opt(o)
	}
	return o, nil
}

func (o *OIDCFederationAuthenticator) Name() string { return o.cfg.Name }

// LoginURL builds the upstream `authorization_endpoint?...` URL.
// state is passed through verbatim — the AS's outer layer is
// responsible for state CSRF defense + correlating the callback
// back to the original /auth/login request.
func (o *OIDCFederationAuthenticator) LoginURL(state string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", o.cfg.ClientID)
	q.Set("redirect_uri", o.cfg.RedirectURI)
	q.Set("state", state)
	if len(o.cfg.Scopes) > 0 {
		q.Set("scope", strings.Join(o.cfg.Scopes, " "))
	}
	sep := "?"
	if strings.Contains(o.cfg.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return o.cfg.AuthorizationEndpoint + sep + q.Encode()
}

// Authenticate is not supported — federation flows complete via
// Callback after the upstream IdP redirect. Returns a typed error so
// callers can distinguish "wrong authenticator" from "bad credentials".
func (o *OIDCFederationAuthenticator) Authenticate(_ context.Context, _ *sso.AuthRequest) (*sso.AuthResult, error) {
	return nil, ErrOIDCFederationDirectAuthUnsupported
}

// Callback exchanges the authorization code for tokens + (if
// configured) fetches userinfo, mapping the result onto AuthResult.
func (o *OIDCFederationAuthenticator) Callback(ctx context.Context, state *sso.CallbackState) (*sso.AuthResult, error) {
	if state == nil || state.Code == "" {
		return nil, errors.New("oidc-federation: empty callback state")
	}
	token, err := o.exchangeCode(ctx, state.Code)
	if err != nil {
		return nil, err
	}
	if token.AccessToken == "" {
		return nil, errors.New("oidc-federation: token response missing access_token")
	}
	claims := map[string]any{}
	if o.cfg.UserinfoEndpoint != "" {
		claims, err = o.fetchUserinfo(ctx, token.AccessToken)
		if err != nil {
			return nil, err
		}
	}
	subField := o.cfg.SubjectFieldOverride
	if subField == "" {
		subField = "sub"
	}
	sub, _ := claims[subField].(string)
	if sub == "" {
		return nil, fmt.Errorf("oidc-federation: userinfo missing %q claim", subField)
	}
	userID, err := o.resolveUserID(ctx, sub)
	if err != nil {
		return nil, err
	}
	return &sso.AuthResult{
		// UserID is the (possibly linker-resolved) local account; ExternalID
		// is ALWAYS the raw external subject, never rewritten — see
		// resolveUserID.
		UserID:     userID,
		ExternalID: sub,
		Provider:   o.cfg.Name,
		Attributes: stringClaims(claims),
		// Upstream IdP doesn't tell us which AMR was used. RFC 8176
		// reserves `fed` for "federated authentication," but it's
		// not in common use; emit it alongside the generic `pwd`
		// fallback so RPs branching on AMR get a federation signal.
		AuthMethods: []string{AuthMethodFed},
		AchievedACR: o.achievedACR(claims),
	}, nil
}

// achievedACR resolves AuthResult.AchievedACR from the upstream userinfo
// claims: "" when no ACRMapper is wired (byte-identical to pre-ACRMapper
// behavior) or when userinfo carried no string `acr` entry. ID-token claims
// are OUT OF SCOPE for this authenticator today (see the package doc) — the
// userinfo response is the only claims source available, so an upstream that
// emits `acr` only in the ID token (the OIDC-typical placement) isn't seen
// here yet. MapACR itself never errors, so this can't fail Callback.
func (o *OIDCFederationAuthenticator) achievedACR(claims map[string]any) string {
	if o.acrMapper == nil {
		return ""
	}
	upstreamACR, _ := claims["acr"].(string)
	return o.acrMapper.MapACR(upstreamACR)
}

// stringClaims projects the string-valued entries of a userinfo response
// onto AuthResult.Attributes (non-string claims, e.g. nested objects or
// booleans, are dropped — Attributes is a flat string map).
func stringClaims(claims map[string]any) map[string]string {
	attrs := map[string]string{}
	for k, v := range claims {
		if s, ok := v.(string); ok {
			attrs[k] = s
		}
	}
	return attrs
}

// resolveUserID maps the raw external subject onto the local account
// AuthResult.UserID should carry. With no linker wired (the default) it is
// the identity function — BYTE-IDENTICAL to this authenticator's behavior
// before UserLinker existed. ExternalID (set by the caller, always sub) is
// deliberately never influenced by this — only UserID is.
func (o *OIDCFederationAuthenticator) resolveUserID(ctx context.Context, sub string) (string, error) {
	if o.linker == nil {
		return sub, nil
	}
	// Fail closed, unwrapped — a wired linker's rejection (e.g.
	// identitylink.ErrAccountConflict) MUST be indistinguishable from any
	// other Callback failure to the caller (oracle-leak hardening, AGENTS.md
	// §3).
	return o.linker.ResolveUserID(ctx, o.cfg.Name, sub)
}

type oidcTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token,omitempty"`
	ExpiresIn   int64  `json:"expires_in,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

func (o *OIDCFederationAuthenticator) exchangeCode(ctx context.Context, code string) (*oidcTokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", o.cfg.RedirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oidc-federation: build token req: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 §2.3.1 — HTTP Basic is the MUST-support method for
	// client authentication at the token endpoint.
	req.SetBasicAuth(o.cfg.ClientID, o.cfg.ClientSecret)

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc-federation: token req: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("oidc-federation: read token body: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("oidc-federation: token endpoint %d: %s", resp.StatusCode, string(body))
	}
	var out oidcTokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("oidc-federation: parse token body: %w", err)
	}
	return &out, nil
}

func (o *OIDCFederationAuthenticator) fetchUserinfo(ctx context.Context, accessToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.cfg.UserinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc-federation: build userinfo req: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc-federation: userinfo req: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("oidc-federation: read userinfo: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("oidc-federation: userinfo %d: %s", resp.StatusCode, string(body))
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("oidc-federation: parse userinfo: %w", err)
	}
	return out, nil
}

// ErrOIDCFederationDirectAuthUnsupported is returned by Authenticate.
// Federation completes via the redirect → Callback path; there's no
// way for a client to log in to an upstream IdP by POSTing credentials
// to /auth/login.
var ErrOIDCFederationDirectAuthUnsupported = errors.New("oidc-federation: direct authentication not supported — use redirect + Callback flow")

var _ sso.Authenticator = (*OIDCFederationAuthenticator)(nil)
