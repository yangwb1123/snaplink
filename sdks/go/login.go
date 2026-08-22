// Package snaplink provides the framework-neutral Go SDK login primitives.
package snaplink

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const defaultTransactionTTL = 10 * time.Minute

// LoginOptions describes a public OAuth client. Client secrets are
// intentionally absent: hosted login is Authorization Code + S256 PKCE.
type LoginOptions struct {
	BaseURL                         string
	ClientID                        string
	LoginPageURL                    string
	RedirectURI                     string
	ReturnTo                        string
	Scope                           []string
	Resource                        []string
	Prompt                          string
	LoginHint                       string
	AcrValues                       string
	UILocales                       string
	MaxAge                          *int
	CallbackURL                     string
	AllowInsecureHTTPForDevelopment bool
	TransactionTTL                  time.Duration
}

// TokenResponse is the successful authorization-code exchange response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	TokenType    string `json:"token_type"`
}

// LoginResult is either a redirect action or a completed token exchange.
type LoginResult struct {
	RedirectURL string
	Tokens      *TokenResponse
	ReturnTo    string
}

// StateStore persists one short-lived state/verifier transaction.
type StateStore interface {
	Take(key string) ([]byte, bool, error)
	Save(key string, value []byte) error
}

// MemoryStateStore is suitable for development and single-process examples.
type MemoryStateStore struct {
	mu     sync.Mutex
	values map[string][]byte
}

func (s *MemoryStateStore) Take(key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.values[key]
	delete(s.values, key)
	return append([]byte(nil), value...), ok, nil
}

func (s *MemoryStateStore) Save(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.values == nil {
		s.values = make(map[string][]byte)
	}
	s.values[key] = append([]byte(nil), value...)
	return nil
}

// Error is returned for OAuth callback and token-endpoint failures.
type Error struct {
	Status      int
	Code        string
	Description string
}

func (e *Error) Error() string {
	if e.Description != "" {
		return e.Description
	}
	if e.Code != "" {
		return e.Code
	}
	return fmt.Sprintf("snaplink request failed with status %d", e.Status)
}

// Client holds the public-client session for one application process.
type Client struct {
	store      StateStore
	httpClient *http.Client
	baseURL    string
	clientID   string
	tokens     *TokenResponse
}

// NewClient constructs a hosted-login client. A nil store uses memory.
func NewClient(store StateStore, httpClient *http.Client) *Client {
	if store == nil {
		store = &MemoryStateStore{}
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{store: store, httpClient: httpClient}
}

// Login starts hosted login or completes a callback supplied in CallbackURL.
// The caller returns RedirectURL as a 302 when it is non-empty. On callback,
// Tokens is populated and ReturnTo identifies the original application URL.
func (c *Client) Login(ctx context.Context, options LoginOptions) (LoginResult, error) {
	config, err := normalizeOptions(options)
	if err != nil {
		return LoginResult{}, err
	}
	c.ensure()
	if c.baseURL != config.baseURL || c.clientID != config.clientID {
		c.tokens = nil
		c.baseURL, c.clientID = config.baseURL, config.clientID
	}
	if callback, ok, err := callbackValues(options.CallbackURL, config.redirectURI, options.AllowInsecureHTTPForDevelopment); err != nil {
		return LoginResult{}, err
	} else if ok {
		return c.finish(ctx, config, callback)
	}
	if c.tokens != nil && c.baseURL == config.baseURL && c.clientID == config.clientID {
		return LoginResult{Tokens: c.tokens, ReturnTo: config.returnTo}, nil
	}
	return c.start(config)
}

// AccessToken returns the current in-memory bearer, if login completed.
func (c *Client) AccessToken() string {
	if c.tokens == nil {
		return ""
	}
	return c.tokens.AccessToken
}

// Clear removes the in-memory session. Server logout remains an API concern.
func (c *Client) Clear() { c.tokens = nil }

type loginConfig struct {
	baseURL     string
	clientID    string
	loginPage   string
	redirectURI string
	returnTo    string
	scope       []string
	resource    []string
	options     LoginOptions
	ttl         time.Duration
}

type loginTransaction struct {
	BaseURL      string    `json:"base_url"`
	ClientID     string    `json:"client_id"`
	CodeVerifier string    `json:"code_verifier"`
	CreatedAt    time.Time `json:"created_at"`
	RedirectURI  string    `json:"redirect_uri"`
	ReturnTo     string    `json:"return_to"`
	State        string    `json:"state"`
}

type callback struct {
	code             string
	state            string
	issuer           string
	err              string
	errorDescription string
}

func (c *Client) ensure() {
	if c.store == nil {
		c.store = &MemoryStateStore{}
	}
	if c.httpClient == nil {
		c.httpClient = http.DefaultClient
	}
}

func (c *Client) start(config loginConfig) (LoginResult, error) {
	verifier, challenge, err := pkce()
	if err != nil {
		return LoginResult{}, err
	}
	state, err := randomURL(32)
	if err != nil {
		return LoginResult{}, err
	}
	tx := loginTransaction{
		BaseURL: config.baseURL, ClientID: config.clientID, CodeVerifier: verifier,
		CreatedAt: time.Now().UTC(), RedirectURI: config.redirectURI,
		ReturnTo: config.returnTo, State: state,
	}
	encoded, err := json.Marshal(tx)
	if err != nil {
		return LoginResult{}, err
	}
	if err := c.store.Save(storeKey(config.clientID), encoded); err != nil {
		return LoginResult{}, err
	}
	redirect, err := buildLoginURL(config, state, challenge)
	if err != nil {
		_, _, _ = c.store.Take(storeKey(config.clientID))
		return LoginResult{}, err
	}
	return LoginResult{RedirectURL: redirect, ReturnTo: config.returnTo}, nil
}

func (c *Client) finish(ctx context.Context, config loginConfig, response callback) (LoginResult, error) {
	key := storeKey(config.clientID)
	raw, ok, err := c.store.Take(key)
	if err != nil {
		return LoginResult{}, err
	}
	if !ok {
		return LoginResult{}, &Error{Status: 0, Code: "invalid_request", Description: "hosted-login transaction is missing or expired"}
	}
	var tx loginTransaction
	if err := json.Unmarshal(raw, &tx); err != nil || time.Since(tx.CreatedAt) > config.ttl {
		return LoginResult{}, &Error{Status: 0, Code: "invalid_request", Description: "hosted-login transaction is missing or expired"}
	}
	if response.state == "" || response.state != tx.State {
		return LoginResult{}, &Error{Status: 0, Code: "invalid_request", Description: "hosted-login state did not match"}
	}
	if canonicalURL(response.issuer) != canonicalURL(tx.BaseURL) {
		return LoginResult{}, &Error{Status: 0, Code: "invalid_request", Description: "authorization issuer did not match Snaplink"}
	}
	if response.err != "" {
		return LoginResult{}, &Error{Status: 0, Code: response.err, Description: response.errorDescription}
	}
	if response.code == "" {
		return LoginResult{}, &Error{Status: 0, Code: "invalid_request", Description: "authorization response did not contain a code"}
	}
	tokens, err := c.exchange(ctx, tx, response.code)
	if err != nil {
		return LoginResult{}, err
	}
	c.tokens, c.baseURL, c.clientID = &tokens, config.baseURL, config.clientID
	return LoginResult{Tokens: &tokens, ReturnTo: tx.ReturnTo}, nil
}

func (c *Client) exchange(ctx context.Context, tx loginTransaction, code string) (TokenResponse, error) {
	form := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {tx.ClientID},
		"code": {code}, "code_verifier": {tx.CodeVerifier},
		"redirect_uri": {tx.RedirectURI},
	}
	return c.postToken(ctx, form)
}

func (c *Client) postToken(ctx context.Context, form url.Values) (TokenResponse, error) {
	endpoint := strings.TrimRight(c.baseURL, "/") + "/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return TokenResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return TokenResponse{}, decodeError(resp)
	}
	var tokens TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return TokenResponse{}, err
	}
	return tokens, nil
}

func decodeError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	var value struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &value)
	return &Error{Status: resp.StatusCode, Code: value.Error, Description: value.Description}
}

func normalizeOptions(options LoginOptions) (loginConfig, error) {
	base, err := normalizeHTTP(options.BaseURL, "base_url", options.AllowInsecureHTTPForDevelopment, false)
	if err != nil {
		return loginConfig{}, err
	}
	if strings.TrimSpace(options.ClientID) == "" {
		return loginConfig{}, &Error{Status: 0, Code: "invalid_request", Description: "client_id is required"}
	}
	redirect, err := normalizeHTTP(options.RedirectURI, "redirect_uri", options.AllowInsecureHTTPForDevelopment, true)
	if err != nil {
		return loginConfig{}, err
	}
	returnTo := options.ReturnTo
	if returnTo == "" {
		returnTo = redirect
	}
	returnURL, err := normalizeHTTP(returnTo, "return_to", options.AllowInsecureHTTPForDevelopment, true)
	if err != nil {
		return loginConfig{}, err
	}
	if !sameOrigin(returnURL, redirect) {
		return loginConfig{}, &Error{Status: 0, Code: "invalid_request", Description: "return_to must use the redirect URI origin"}
	}
	loginPage := options.LoginPageURL
	if loginPage == "" {
		loginPage = strings.TrimRight(base, "/") + "/login/"
	}
	if _, err := normalizeHTTP(loginPage, "login_page_url", options.AllowInsecureHTTPForDevelopment, true); err != nil {
		return loginConfig{}, err
	}
	ttl := options.TransactionTTL
	if ttl <= 0 {
		ttl = defaultTransactionTTL
	}
	scope := options.Scope
	if len(scope) == 0 {
		scope = []string{"openid", "profile", "email"}
	}
	if err := validateValues(scope, "scope"); err != nil {
		return loginConfig{}, err
	}
	return loginConfig{baseURL: base, clientID: options.ClientID, loginPage: loginPage,
		redirectURI: redirect, returnTo: returnURL, scope: scope, resource: options.Resource,
		options: options, ttl: ttl}, nil
}

func buildLoginURL(config loginConfig, state, challenge string) (string, error) {
	u, err := url.Parse(config.loginPage)
	if err != nil {
		return "", err
	}
	query := u.Query()
	for _, key := range []string{"client_id", "redirect_uri", "response_type", "response_mode", "scope", "state", "code_challenge", "code_challenge_method", "resource", "prompt", "max_age", "login_hint", "acr_values", "ui_locales"} {
		query.Del(key)
	}
	query.Set("client_id", config.clientID)
	query.Set("redirect_uri", config.redirectURI)
	query.Set("response_type", "code")
	query.Set("response_mode", "query")
	query.Set("scope", strings.Join(config.scope, " "))
	query.Set("state", state)
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	for _, resource := range config.resource {
		if resource == "" {
			return "", &Error{Status: 0, Code: "invalid_request", Description: "resource values must be non-empty"}
		}
		query.Add("resource", resource)
	}
	setOptional(query, "prompt", config.options.Prompt)
	setOptional(query, "login_hint", config.options.LoginHint)
	setOptional(query, "acr_values", config.options.AcrValues)
	setOptional(query, "ui_locales", config.options.UILocales)
	if config.options.MaxAge != nil {
		if *config.options.MaxAge < 0 {
			return "", &Error{Status: 0, Code: "invalid_request", Description: "max_age must be non-negative"}
		}
		query.Set("max_age", fmt.Sprint(*config.options.MaxAge))
	}
	u.RawQuery, u.Fragment = query.Encode(), ""
	return u.String(), nil
}

func setOptional(query url.Values, key, value string) {
	if value != "" {
		query.Set(key, value)
	}
}

func callbackValues(raw, redirectURI string, allowInsecure bool) (callback, bool, error) {
	if raw == "" {
		return callback{}, false, nil
	}
	normalized, err := normalizeHTTP(raw, "callback_url", allowInsecure, true)
	if err != nil {
		return callback{}, false, err
	}
	if canonicalURL(normalized) != canonicalURL(redirectURI) {
		return callback{}, false, &Error{Status: 0, Code: "invalid_request", Description: "callback_url does not match redirect_uri"}
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return callback{}, false, err
	}
	values := u.Query()
	return callback{code: values.Get("code"), state: values.Get("state"), issuer: values.Get("iss"),
		err: values.Get("error"), errorDescription: values.Get("error_description")}, true, nil
}

func normalizeHTTP(raw, name string, allowInsecure, allowQuery bool) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", &Error{Status: 0, Code: "invalid_request", Description: name + " is required"}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return "", &Error{Status: 0, Code: "invalid_request", Description: name + " must be an absolute HTTP(S) URL"}
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (allowInsecure || loopback(u.Hostname()))) {
		return "", &Error{Status: 0, Code: "invalid_request", Description: name + " must use HTTPS or loopback HTTP"}
	}
	if (!allowQuery && u.RawQuery != "") || u.Fragment != "" {
		return "", &Error{Status: 0, Code: "invalid_request", Description: name + " contains a forbidden query or fragment"}
	}
	return u.String(), nil
}

func sameOrigin(a, b string) bool {
	left, _ := url.Parse(a)
	right, _ := url.Parse(b)
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

func canonicalURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.RawQuery, u.Fragment = "", ""
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String()
}

func validateValues(values []string, name string) error {
	for _, value := range values {
		if value == "" || strings.IndexFunc(value, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' }) >= 0 {
			return &Error{Status: 0, Code: "invalid_request", Description: name + " values must be non-empty and whitespace-free"}
		}
	}
	return nil
}

func pkce() (string, string, error) {
	verifier, err := randomURL(64)
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func randomURL(size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func storeKey(clientID string) string { return "snaplink.login.v1:" + url.QueryEscape(clientID) }

func loopback(host string) bool {
	host = strings.Trim(host, "[]")
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
