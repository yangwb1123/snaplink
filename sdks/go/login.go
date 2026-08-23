// Package snaplink provides the framework-neutral Go SDK login primitives.
package snaplink

import (
	"context"
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
	Setup                           *SetupOptions
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
	pending    *pendingSetup
	context    *AccountContext
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
		c.pending = nil
		c.context = nil
		c.baseURL, c.clientID = config.baseURL, config.clientID
	}
	if callback, ok, err := callbackValues(options.CallbackURL, config.redirectURI, options.AllowInsecureHTTPForDevelopment); err != nil {
		return LoginResult{}, err
	} else if ok {
		return c.finish(ctx, config, callback)
	}
	if options.Setup != nil {
		setup := *options.Setup
		setup.BaseURL, setup.ClientID = config.baseURL, config.clientID
		setup.AllowInsecureHTTPForDevelopment = options.AllowInsecureHTTPForDevelopment
		if _, err := c.Setup(ctx, setup); err != nil {
			return LoginResult{}, err
		}
	}
	if c.tokens != nil && c.baseURL == config.baseURL && c.clientID == config.clientID {
		if err := c.claimPending(ctx, config); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{Tokens: c.tokens, ReturnTo: config.returnTo}, nil
	}
	return c.start(config, c.pending)
}

// AccessToken returns the current in-memory bearer, if login completed.
func (c *Client) AccessToken() string {
	if c.tokens == nil {
		return ""
	}
	return c.tokens.AccessToken
}

// Clear removes the in-memory session. Server logout remains an API concern.
func (c *Client) Clear() {
	c.tokens = nil
	c.context = nil
}

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
	BaseURL          string    `json:"base_url"`
	ClientID         string    `json:"client_id"`
	CodeVerifier     string    `json:"code_verifier"`
	CreatedAt        time.Time `json:"created_at"`
	RedirectURI      string    `json:"redirect_uri"`
	ReturnTo         string    `json:"return_to"`
	State            string    `json:"state"`
	ActivationTicket string    `json:"activation_ticket,omitempty"`
	ProductID        string    `json:"product_id,omitempty"`
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

func (c *Client) start(config loginConfig, pending *pendingSetup) (LoginResult, error) {
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
	if pending != nil {
		tx.ActivationTicket, tx.ProductID = pending.Ticket, pending.ProductID
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
	if tx.ActivationTicket != "" {
		if err := c.claimActivation(ctx, config.baseURL, tx.ClientID, tx.ActivationTicket, tx.ProductID); err != nil {
			c.tokens = nil
			return LoginResult{}, err
		}
	}
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
