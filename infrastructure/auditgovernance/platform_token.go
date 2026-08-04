package auditgovernance

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	PlatformProvisioningScope = "audit:platform:cross_tenant audit:policy:read audit:policy:write"
	PlatformRetentionScope    = "audit:platform:cross_tenant audit:policy:write"
)

type PlatformTokenConfig struct {
	TokenURL              string
	ClientID              string
	ClientSecret          string
	Resource              string
	Scope                 string
	Timeout               time.Duration
	RefreshSkew           time.Duration
	AllowInsecureLoopback bool
}

type PlatformTokenProvider interface {
	PlatformToken(context.Context) (string, error)
}

// PlatformTokenSource owns a cache distinct from every event-relay client.
type PlatformTokenSource struct {
	endpoint     *url.URL
	clientID     string
	clientSecret string
	resource     string
	scope        string
	refreshSkew  time.Duration
	client       *http.Client
	now          func() time.Time

	mu        sync.RWMutex
	token     string
	refreshAt time.Time
	fetches   singleflight.Group
}

func NewPlatformTokenSource(config PlatformTokenConfig, client *http.Client) (*PlatformTokenSource, error) {
	config = defaultPlatformTokenConfig(config)
	endpoint, err := secureEndpoint(config.TokenURL, config.AllowInsecureLoopback)
	if err != nil || !validPlatformTokenConfig(config) {
		return nil, ErrInvalidConfig
	}
	return &PlatformTokenSource{
		endpoint: endpoint, clientID: config.ClientID, clientSecret: config.ClientSecret,
		resource: config.Resource, scope: config.Scope, refreshSkew: config.RefreshSkew,
		client: noRedirectClient(client, config.Timeout), now: func() time.Time { return time.Now().UTC() },
	}, nil
}

func defaultPlatformTokenConfig(config PlatformTokenConfig) PlatformTokenConfig {
	config.TokenURL = strings.TrimSpace(config.TokenURL)
	config.ClientID = strings.TrimSpace(config.ClientID)
	config.Resource = strings.TrimSpace(config.Resource)
	config.Scope = strings.Join(strings.Fields(config.Scope), " ")
	if config.Scope == "" {
		config.Scope = PlatformProvisioningScope
	}
	if config.Timeout <= 0 {
		config.Timeout = defaultTokenTimeout
	}
	if config.RefreshSkew <= 0 {
		config.RefreshSkew = defaultRefreshSkew
	}
	return config
}

func validPlatformTokenConfig(config PlatformTokenConfig) bool {
	return config.ClientID != "" && config.ClientSecret != "" &&
		!strings.ContainsAny(config.ClientSecret, "\r\n") && config.Resource != "" &&
		!strings.ContainsAny(config.Resource, "\r\n") && validPlatformScope(config.Scope) &&
		config.Timeout > 0 && config.RefreshSkew > 0
}

func validPlatformScope(scope string) bool {
	return scope == PlatformProvisioningScope || scope == PlatformRetentionScope
}

func (source *PlatformTokenSource) PlatformToken(ctx context.Context) (string, error) {
	if token, ok := source.cachedPlatformToken(); ok {
		return token, nil
	}
	result := source.fetches.DoChan("platform", func() (any, error) {
		if token, ok := source.cachedPlatformToken(); ok {
			return token, nil
		}
		return source.fetchPlatformToken(ctx)
	})
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case outcome := <-result:
		return platformTokenResult(outcome.Val, outcome.Err)
	}
}

func platformTokenResult(value any, err error) (string, error) {
	if err != nil {
		return "", err
	}
	token, ok := value.(string)
	if !ok || token == "" {
		return "", ErrTokenUnavailable
	}
	return token, nil
}

func (source *PlatformTokenSource) cachedPlatformToken() (string, bool) {
	source.mu.RLock()
	defer source.mu.RUnlock()
	return source.token, source.token != "" && source.now().Before(source.refreshAt)
}

func (source *PlatformTokenSource) fetchPlatformToken(ctx context.Context) (string, error) {
	request, err := source.platformTokenRequest(ctx)
	if err != nil {
		return "", ErrTokenUnavailable
	}
	response, err := source.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("%w: platform token transport", ErrTokenUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxTokenBodyBytes))
		return "", fmt.Errorf("%w: platform token HTTP %d", ErrTokenUnavailable, response.StatusCode)
	}
	wire, err := decodeTokenResponse(response)
	if err != nil {
		return "", err
	}
	source.cachePlatformToken(wire)
	return wire.AccessToken, nil
}

func (source *PlatformTokenSource) platformTokenRequest(ctx context.Context) (*http.Request, error) {
	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {source.scope},
		"resource":   {source.resource},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, source.endpoint.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.SetBasicAuth(source.clientID, source.clientSecret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	return request, nil
}

func (source *PlatformTokenSource) cachePlatformToken(wire tokenResponse) {
	now := source.now()
	seconds := min(wire.ExpiresIn, int64(maxCachedTokenTTL/time.Second))
	lifetime := time.Duration(seconds) * time.Second
	skew := min(source.refreshSkew, lifetime/2)
	source.mu.Lock()
	source.token = wire.AccessToken
	source.refreshAt = now.Add(lifetime - skew)
	source.mu.Unlock()
}

var _ PlatformTokenProvider = (*PlatformTokenSource)(nil)
