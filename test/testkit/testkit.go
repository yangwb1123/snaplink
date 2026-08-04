// Package testkit spins up a real, in-process SSO server for downstream
// integration tests — the importable counterpart to the SDK's internal e2e
// harness (which is trapped in a _test.go file and so can't be imported).
//
// A resource-server / RP test can mint a REAL token (via Login, or directly
// through the exposed Issuer) and validate it over the live JWKS endpoint —
// exercising the exact signature + JWKS round-trip that the ssoclient/dev
// bypass stubs deliberately skip (and that, per the EdDSA-only-client history,
// is where misconfiguration bites). Defaults wire one client + one user with a
// password authenticator; Options add more.
//
// Typical use:
//
//	h := testkit.NewServer()
//	defer h.Close()
//	res, _ := h.Login(ctx, testkit.DefaultUsername, testkit.DefaultPassword, "openid")
//	// validate res.AccessToken in your resource server using
//	// ssoclient/remote against h.JWKSURL().
package testkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// Defaults seeded when no Option overrides them.
const (
	DefaultIssuer       = "testkit-sso"
	DefaultClientID     = "testkit-client"
	DefaultClientSecret = "testkit-secret"
	DefaultUsername     = "testkit-user"
	DefaultPassword     = "testkit-pass"
	// DefaultRedirectURI is seeded on the harness client so
	// authorization_code flows work without extra wiring. Override with
	// WithRedirectURI.
	DefaultRedirectURI = "http://localhost:9999/callback"
)

// Harness is a running in-process SSO server. Call Close when done.
type Harness struct {
	// URL is the base URL of the running HTTP server.
	URL string
	// Issuer is the Ed25519 signing issuer — mint or validate tokens directly
	// without going through the HTTP flow when a test needs to.
	Issuer *defaultimpl.Ed25519JWTIssuer

	clientID     string
	clientSecret string
	server       *httptest.Server
}

type config struct {
	issuerName      string
	clientID        string
	clientSecret    string
	scopes          []string
	users           map[string]string // username -> password
	usersAreDefault bool
	router          sso.Router // nil => server default (NewStdRouter)
	redirectURIs    []string
}

// Option customizes NewServer.
type Option func(*config)

// WithIssuerName overrides the issuer/`iss` value (default DefaultIssuer).
func WithIssuerName(name string) Option {
	return func(c *config) { c.issuerName = name }
}

// WithClient overrides the seeded confidential client and its allowed scopes
// (default DefaultClientID/DefaultClientSecret, scope "openid").
func WithClient(id, secret string, scopes ...string) Option {
	return func(c *config) {
		c.clientID, c.clientSecret = id, secret
		if len(scopes) > 0 {
			c.scopes = append([]string(nil), scopes...)
		}
	}
}

// WithRouter mounts the SSO server onto the supplied router instead of the
// default StdRouter — the production embedding shape (sso.WithRouter). A nil
// router (or unset option) uses the server default, byte-identical to today.
func WithRouter(r sso.Router) Option {
	return func(c *config) { c.router = r }
}

// WithRedirectURI replaces the seeded client redirect URI list (default
// DefaultRedirectURI).
func WithRedirectURI(uri string) Option {
	return func(c *config) { c.redirectURIs = []string{uri} }
}

// WithUser adds a login user (username/password). Called multiple times to
// seed several. The default user is dropped once any WithUser is supplied.
func WithUser(username, password string) Option {
	return func(c *config) {
		if c.usersAreDefault {
			c.users = map[string]string{}
			c.usersAreDefault = false
		}
		c.users[username] = password
	}
}

// usersAreDefault is tracked on config so the first WithUser replaces the seed
// default rather than adding to it.
func (c *config) markDefaults() { c.usersAreDefault = true }

// NewServer builds and starts the harness. It never fails for well-formed
// options, so it returns just *Harness for ergonomic test setup.
func NewServer(opts ...Option) *Harness {
	cfg := resolveConfig(opts...)

	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer(cfg.issuerName),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	users := seedUsers(cfg)
	clients := seedClient(cfg)
	pw := newPasswordAuthenticator(cfg)

	srvOpts := []sso.Option{
		sso.WithIssuer(cfg.issuerName),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		// Wired by default so the harness can run authorization_code and
		// refresh-rotation flows out of the box (the router-backend matrix
		// is the first consumer). A seeded refresh store makes /auth/login
		// additionally return refresh_token — additive for existing users.
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
	}
	if cfg.router != nil {
		srvOpts = append(srvOpts, sso.WithRouter(cfg.router))
	}
	srv := sso.NewServer(srvOpts...)

	ts := httptest.NewServer(srv.Handler())
	return &Harness{
		URL:          ts.URL,
		Issuer:       issuer,
		clientID:     cfg.clientID,
		clientSecret: cfg.clientSecret,
		server:       ts,
	}
}

// resolveConfig seeds the defaults then applies caller options. markDefaults
// must run before options so the first WithUser replaces the seed user.
func resolveConfig(opts ...Option) config {
	cfg := config{
		issuerName:   DefaultIssuer,
		clientID:     DefaultClientID,
		clientSecret: DefaultClientSecret,
		scopes:       []string{"openid"},
		users:        map[string]string{DefaultUsername: DefaultPassword},
		redirectURIs: []string{DefaultRedirectURI},
	}
	cfg.markDefaults()
	for _, o := range opts {
		o(&cfg)
	}
	return cfg
}

// seedUsers registers every configured user with a fresh memory provider.
func seedUsers(cfg config) *defaultimpl.MemoryUserProvider {
	users := defaultimpl.NewMemoryUserProvider()
	for u := range cfg.users {
		_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: u})
	}
	return users
}

// seedClient registers the single confidential client used by the harness.
func seedClient(cfg config) *defaultimpl.MemoryClientStore {
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    cfg.clientID,
		Secret:                cfg.clientSecret,
		RedirectURIs:          append([]string(nil), cfg.redirectURIs...),
		AllowedScopes:         cfg.scopes,
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
	})
	return clients
}

// newPasswordAuthenticator builds the password verifier over a snapshot of the
// credentials, so the closure validates by value, not by a later-mutated map.
func newPasswordAuthenticator(cfg config) *authenticators.PasswordAuthenticator {
	creds := make(map[string]string, len(cfg.users))
	for u, p := range cfg.users {
		creds[u] = p
	}
	return authenticators.NewPasswordAuthenticator(
		authenticators.PasswordVerifierFunc(func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if want, ok := creds[u]; ok && p != "" && want == p {
				return &sso.AuthResult{UserID: u}, nil
			}
			return nil, errors.New("testkit: bad credentials")
		}),
	)
}

// Close shuts down the HTTP server. Idempotent.
func (h *Harness) Close() {
	if h != nil && h.server != nil {
		h.server.Close()
		h.server = nil
	}
}

// JWKSURL is the JWKS endpoint a downstream resource server points its
// ssoclient/remote JWKS cache at.
func (h *Harness) JWKSURL() string { return h.URL + "/.well-known/jwks.json" }

// DiscoveryURL is the OIDC discovery document endpoint.
func (h *Harness) DiscoveryURL() string {
	return h.URL + "/.well-known/openid-configuration"
}

// Handler is the full server handler behind URL — the probe mux + SSO
// middleware chain wrapping whatever router was injected. Recorder-level
// comparisons (httptest.NewRecorder) see the same bytes the wire serves,
// minus transport framing such as the Date header.
func (h *Harness) Handler() http.Handler {
	return h.server.Config.Handler
}

// LoginResult holds the tokens returned by a successful Login.
type LoginResult struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// Login drives POST /auth/login with the password authenticator and returns
// the minted tokens. scopes defaults to ["openid"] when omitted.
func (h *Harness) Login(ctx context.Context, username, password string, scopes ...string) (*LoginResult, error) {
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	reqBody, err := json.Marshal(map[string]any{
		"provider":   authenticators.MethodPassword,
		"client_id":  h.clientID,
		"credential": map[string]string{"username": username, "password": password},
		"scope":      scopes,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL+"/auth/login", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("testkit: login failed: %d %s", resp.StatusCode, raw)
	}
	var out LoginResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("testkit: decode login response: %w", err)
	}
	if out.AccessToken == "" {
		return nil, fmt.Errorf("testkit: login returned no access_token: %s", raw)
	}
	return &out, nil
}
