package auditgovernance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	defaultTokenTimeout = 5 * time.Second
	defaultRefreshSkew  = 30 * time.Second
	maxTokenBodyBytes   = 64 << 10
	maxCachedTokenTTL   = 24 * time.Hour
)

// OAuthTokenConfig configures RFC 6749 client_credentials authentication for
// the Audit Governance relay. SourcePrefix is checked locally; the remote
// governance service must independently bind the signed client_id to its
// pre-registered source and tenant policy.
type OAuthTokenConfig struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	SourcePrefix string
	// SourceSystem is a compatibility alias for SourcePrefix.
	// Deprecated: configure SourcePrefix for tenant-scoped source IDs.
	SourceSystem          string
	Scope                 string
	Resources             []string
	Timeout               time.Duration
	RefreshSkew           time.Duration
	AllowInsecureLoopback bool
}

// OAuthTokenSource obtains and safely caches one service token per configured
// OAuth client. Tenant IDs deliberately do not partition the cache because the
// current Snaplink access-token wire format does not carry tenant_id.
type OAuthTokenSource struct {
	endpoint     *url.URL
	clientID     string
	clientSecret string
	sourcePrefix string
	scope        string
	resources    []string
	refreshSkew  time.Duration
	client       *http.Client
	now          func() time.Time

	mu        sync.RWMutex
	token     string
	refreshAt time.Time
	fetches   singleflight.Group
}

// OAuthTokenOption customizes deterministic behavior without weakening the
// production validation performed by NewOAuthTokenSource.
type OAuthTokenOption func(*OAuthTokenSource)

// WithOAuthTokenClock injects a clock for tests.
func WithOAuthTokenClock(now func() time.Time) OAuthTokenOption {
	return func(source *OAuthTokenSource) {
		if now != nil {
			source.now = now
		}
	}
}

func NewOAuthTokenSource(
	config OAuthTokenConfig, client *http.Client, options ...OAuthTokenOption,
) (*OAuthTokenSource, error) {
	config = defaultOAuthTokenConfig(config)
	endpoint, err := secureEndpoint(config.TokenURL, config.AllowInsecureLoopback)
	if err != nil || !validOAuthTokenConfig(config) {
		return nil, ErrInvalidConfig
	}
	source := &OAuthTokenSource{
		endpoint: endpoint, clientID: config.ClientID, clientSecret: config.ClientSecret,
		sourcePrefix: config.SourcePrefix, scope: config.Scope,
		resources: append([]string(nil), config.Resources...), refreshSkew: config.RefreshSkew,
		client: noRedirectClient(client, config.Timeout), now: func() time.Time { return time.Now().UTC() },
	}
	for _, option := range options {
		option(source)
	}
	return source, nil
}

func defaultOAuthTokenConfig(config OAuthTokenConfig) OAuthTokenConfig {
	config.TokenURL = strings.TrimSpace(config.TokenURL)
	config.ClientID = strings.TrimSpace(config.ClientID)
	config.SourcePrefix = strings.TrimSpace(config.SourcePrefix)
	config.SourceSystem = strings.TrimSpace(config.SourceSystem)
	if config.SourcePrefix == "" {
		config.SourcePrefix = config.SourceSystem
	}
	config.Scope = strings.Join(strings.Fields(config.Scope), " ")
	config.Resources = append([]string(nil), config.Resources...)
	if config.Timeout <= 0 {
		config.Timeout = defaultTokenTimeout
	}
	if config.RefreshSkew <= 0 {
		config.RefreshSkew = defaultRefreshSkew
	}
	for index := range config.Resources {
		config.Resources[index] = strings.TrimSpace(config.Resources[index])
	}
	return config
}

func validOAuthTokenConfig(config OAuthTokenConfig) bool {
	if config.ClientID == "" || config.ClientSecret == "" || !validSourcePrefix(config.SourcePrefix) ||
		config.Scope == "" || config.Timeout <= 0 || config.RefreshSkew <= 0 {
		return false
	}
	for _, resource := range config.Resources {
		if resource == "" {
			return false
		}
	}
	return true
}

func secureEndpoint(raw string, allowInsecureLoopback bool) (*url.URL, error) {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, ErrInvalidConfig
	}
	if endpoint.Scheme != "https" && !allowedLoopbackHTTP(endpoint, allowInsecureLoopback) {
		return nil, ErrInvalidConfig
	}
	return endpoint, nil
}

func (s *OAuthTokenSource) AccessToken(ctx context.Context, binding SourceBinding) (string, error) {
	expected, err := TenantSourceID(s.sourcePrefix, binding.TenantID)
	if err != nil || binding.SourceSystem != expected {
		return "", ErrTokenUnavailable
	}
	if token, ok := s.cachedToken(); ok {
		return token, nil
	}
	result := s.fetches.DoChan("client", func() (any, error) {
		if token, ok := s.cachedToken(); ok {
			return token, nil
		}
		return s.fetchToken(ctx)
	})
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case outcome := <-result:
		if outcome.Err != nil {
			return "", outcome.Err
		}
		token, ok := outcome.Val.(string)
		if !ok || token == "" {
			return "", ErrTokenUnavailable
		}
		return token, nil
	}
}

func (s *OAuthTokenSource) cachedToken() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token, s.token != "" && s.now().Before(s.refreshAt)
}

func (s *OAuthTokenSource) fetchToken(ctx context.Context) (string, error) {
	request, err := s.tokenRequest(ctx)
	if err != nil {
		return "", ErrTokenUnavailable
	}
	response, err := s.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("%w: token transport", ErrTokenUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxTokenBodyBytes))
		return "", fmt.Errorf("%w: token endpoint HTTP %d", ErrTokenUnavailable, response.StatusCode)
	}
	wire, err := decodeTokenResponse(response)
	if err != nil {
		return "", err
	}
	s.cacheToken(wire)
	return wire.AccessToken, nil
}

func (s *OAuthTokenSource) tokenRequest(ctx context.Context) (*http.Request, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {s.scope}}
	for _, resource := range s.resources {
		form.Add("resource", resource)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.SetBasicAuth(s.clientID, s.clientSecret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	return request, nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

func decodeTokenResponse(response *http.Response) (tokenResponse, error) {
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return tokenResponse{}, ErrTokenUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxTokenBodyBytes+1))
	if err != nil || len(body) > maxTokenBodyBytes {
		return tokenResponse{}, ErrTokenUnavailable
	}
	var wire tokenResponse
	if json.Unmarshal(body, &wire) != nil || strings.TrimSpace(wire.AccessToken) == "" ||
		strings.ContainsAny(wire.AccessToken, "\r\n") || !strings.EqualFold(wire.TokenType, "Bearer") || wire.ExpiresIn <= 0 {
		return tokenResponse{}, ErrTokenUnavailable
	}
	return wire, nil
}

func (s *OAuthTokenSource) cacheToken(wire tokenResponse) {
	now := s.now()
	seconds := min(wire.ExpiresIn, int64(maxCachedTokenTTL/time.Second))
	lifetime := time.Duration(seconds) * time.Second
	skew := min(s.refreshSkew, lifetime/2)
	s.mu.Lock()
	s.token = wire.AccessToken
	s.refreshAt = now.Add(lifetime - skew)
	s.mu.Unlock()
}

var _ ClientCredentialsTokenSource = (*OAuthTokenSource)(nil)
