package remote

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient"
	"github.com/yangwb1123/snaplink/shared/core"
)

const maxTokenResponseBytes = 1 << 20

// TokenClient is the remote OAuth token-acquisition implementation.
type TokenClient struct {
	tokenURL         string
	authorizationURL string
	clientID         string
	basicID          string
	basicSecret      string
	formID           string
	formSecret       string
	redirectURI      string
	requirePKCE      bool
	httpc            *http.Client
}

type TokenOption func(*TokenClient)

func WithClientID(clientID string) TokenOption {
	return func(c *TokenClient) { c.clientID = clientID }
}

func WithAuthorizationEndpoint(endpoint string) TokenOption {
	return func(c *TokenClient) { c.authorizationURL = endpoint }
}

func WithClientCredentials(clientID, secret string) TokenOption {
	return func(c *TokenClient) { c.basicID, c.basicSecret = clientID, secret }
}

func WithFormClientCredentials(clientID, secret string) TokenOption {
	return func(c *TokenClient) { c.formID, c.formSecret = clientID, secret }
}

func WithRedirectURI(uri string) TokenOption {
	return func(c *TokenClient) { c.redirectURI = uri }
}

func WithPKCE(enabled bool) TokenOption {
	return func(c *TokenClient) { c.requirePKCE = enabled }
}

func WithHTTPClient(client *http.Client) TokenOption {
	return func(c *TokenClient) {
		if client != nil {
			c.httpc = client
		}
	}
}

func NewTokenClient(tokenURL string, options ...TokenOption) *TokenClient {
	client := &TokenClient{
		tokenURL: tokenURL, requirePKCE: true,
		httpc: &http.Client{Timeout: 10 * time.Second},
	}
	for _, option := range options {
		option(client)
	}
	return client
}

func (c *TokenClient) GeneratePKCE() (string, string, error) {
	raw := make([]byte, 48)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("ssoclient/remote: generate PKCE: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	challenge := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(challenge[:]), nil
}

func (c *TokenClient) AuthorizationCodeURL(state string, scopes ...string) (string, string, error) {
	if state == "" {
		return "", "", errors.New("ssoclient/remote: authorization state required")
	}
	target, err := url.Parse(c.authorizationURL)
	if err != nil || target.Scheme == "" || target.Host == "" || c.effectiveClientID() == "" {
		return "", "", errors.New("ssoclient/remote: authorization endpoint and client ID required")
	}
	verifier, challenge := "", ""
	if c.requirePKCE {
		verifier, challenge, err = c.GeneratePKCE()
		if err != nil {
			return "", "", err
		}
	}
	query := target.Query()
	query.Set("client_id", c.effectiveClientID())
	query.Set("response_type", "code")
	query.Set("redirect_uri", c.redirectURI)
	query.Set("scope", strings.Join(scopes, " "))
	query.Set("state", state)
	if challenge != "" {
		query.Set("code_challenge", challenge)
		query.Set("code_challenge_method", "S256")
	}
	target.RawQuery = query.Encode()
	return target.String(), verifier, nil
}

func (c *TokenClient) ExchangeCode(ctx context.Context, code, verifier string) (*ssoclient.TokenResponse, error) {
	if code == "" {
		return nil, errors.New("ssoclient/remote: authorization code required")
	}
	if c.requirePKCE && (len(verifier) < core.PKCEVerifierMinLen || len(verifier) > core.PKCEVerifierMaxLen) {
		return nil, errors.New("ssoclient/remote: valid PKCE verifier required")
	}
	form := url.Values{
		"grant_type":   {core.GrantAuthorizationCode},
		"code":         {code},
		"redirect_uri": {c.redirectURI},
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	return c.requestToken(ctx, form)
}

func (c *TokenClient) Refresh(ctx context.Context, refreshToken string) (*ssoclient.TokenResponse, error) {
	if refreshToken == "" {
		return nil, errors.New("ssoclient/remote: refresh token required")
	}
	return c.requestToken(ctx, url.Values{
		"grant_type": {core.GrantRefreshToken}, "refresh_token": {refreshToken},
	})
}

func (c *TokenClient) ClientCredentials(ctx context.Context, scopes ...string) (*ssoclient.TokenResponse, error) {
	form := url.Values{"grant_type": {core.GrantClientCredentials}}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	return c.requestToken(ctx, form)
}

func (c *TokenClient) requestToken(ctx context.Context, form url.Values) (*ssoclient.TokenResponse, error) {
	clientID := c.effectiveClientID()
	if c.tokenURL == "" || clientID == "" {
		return nil, errors.New("ssoclient/remote: token URL and client ID required")
	}
	form.Set("client_id", clientID)
	if c.basicID == "" && c.formSecret != "" {
		form.Set("client_secret", c.formSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Pragma", "no-cache")
	if c.basicID != "" {
		req.SetBasicAuth(c.basicID, c.basicSecret)
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ssoclient/remote: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, decodeTokenError(resp)
	}
	return decodeTokenResponse(resp.Body)
}

func (c *TokenClient) effectiveClientID() string {
	if c.basicID != "" {
		return c.basicID
	}
	if c.formID != "" {
		return c.formID
	}
	return c.clientID
}

type wireTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
}

func decodeTokenResponse(body io.Reader) (*ssoclient.TokenResponse, error) {
	var wire wireTokenResponse
	if err := json.NewDecoder(io.LimitReader(body, maxTokenResponseBytes)).Decode(&wire); err != nil {
		return nil, fmt.Errorf("ssoclient/remote: decode token response: %w", err)
	}
	if wire.AccessToken == "" {
		return nil, errors.New("ssoclient/remote: token response omitted access_token")
	}
	return &ssoclient.TokenResponse{
		AccessToken: wire.AccessToken, RefreshToken: wire.RefreshToken,
		ExpiresIn: wire.ExpiresIn, Scopes: strings.Fields(wire.Scope),
		TokenType: wire.TokenType, IDToken: wire.IDToken,
	}, nil
}

func decodeTokenError(resp *http.Response) error {
	var wire struct {
		Code        string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseBytes)).Decode(&wire)
	if wire.Code == "" {
		wire.Code = "server_error"
	}
	return &ssoclient.TokenError{
		Status: resp.StatusCode, Code: wire.Code, Description: wire.Description,
	}
}
