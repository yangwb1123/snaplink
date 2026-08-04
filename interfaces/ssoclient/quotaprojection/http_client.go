package quotaprojection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	defaultHTTPTimeout = 5 * time.Second
	maxResponseBytes   = 32 << 10
	maxSourceLength    = 256
)

type HTTPConfig struct {
	BaseURL string
	Timeout time.Duration
	// AllowInsecureLoopback permits explicit local development over HTTP.
	AllowInsecureLoopback bool
}

type HTTPClient struct {
	endpoint   *url.URL
	authorizer Authorizer
	client     *http.Client
}

func NewHTTPClient(config HTTPConfig, authorizer Authorizer, client *http.Client) (*HTTPClient, error) {
	config.BaseURL = strings.TrimSpace(config.BaseURL)
	if config.Timeout <= 0 {
		config.Timeout = defaultHTTPTimeout
	}
	endpoint, err := projectionEndpoint(config.BaseURL, config.AllowInsecureLoopback)
	if err != nil || authorizer == nil {
		return nil, ErrInvalidConfig
	}
	return &HTTPClient{
		endpoint: endpoint, authorizer: authorizer,
		client: projectionHTTPClient(client, config.Timeout),
	}, nil
}

func projectionEndpoint(raw string, allowInsecureLoopback bool) (*url.URL, error) {
	base, err := url.Parse(raw)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, ErrInvalidConfig
	}
	if base.Scheme != "https" && !projectionLoopbackHTTP(base, allowInsecureLoopback) {
		return nil, ErrInvalidConfig
	}
	return base.JoinPath(strings.TrimPrefix(core.PathTenantQuotaProjection, "/")), nil
}

func projectionLoopbackHTTP(endpoint *url.URL, allowed bool) bool {
	if !allowed || endpoint.Scheme != "http" {
		return false
	}
	if strings.EqualFold(endpoint.Hostname(), "localhost") {
		return true
	}
	ip := net.ParseIP(endpoint.Hostname())
	return ip != nil && ip.IsLoopback()
}

func projectionHTTPClient(client *http.Client, timeout time.Duration) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if copyClient.Timeout <= 0 {
		copyClient.Timeout = timeout
	}
	return &copyClient
}

type projectionRequest struct {
	TenantID     string                     `json:"tenant_id"`
	SourceSystem string                     `json:"source_system"`
	Projection   core.TenantQuotaProjection `json:"projection"`
}

func (c *HTTPClient) Publish(
	ctx context.Context, event *commerce.OutboxEvent, projection core.TenantQuotaProjection,
) (Receipt, error) {
	if err := validateDelivery(event, projection); err != nil {
		return Receipt{}, err
	}
	authorization, err := c.authorization(ctx, event.TenantID)
	if err != nil {
		return Receipt{}, err
	}
	body, err := json.Marshal(projectionRequest{
		TenantID: event.TenantID, SourceSystem: authorization.SourceSystem, Projection: projection,
	})
	if err != nil {
		return Receipt{}, ErrInvalidProjection
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, c.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return Receipt{}, ErrInvalidConfig
	}
	request.Header.Set("Authorization", "Bearer "+authorization.BearerToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return Receipt{}, err
	}
	return decodeProjectionReceipt(response, event.TenantID, projection.Revision)
}

func validateDelivery(event *commerce.OutboxEvent, projection core.TenantQuotaProjection) error {
	if event == nil || event.ID == "" || event.Type != commerce.EventEntitlementPublished ||
		event.AggregateVersion == 0 || event.AggregateVersion > projection.Revision {
		return ErrInvalidEvent
	}
	if core.ValidateQuotaTenantID(event.TenantID) != nil ||
		core.ValidateTenantQuotaProjection(&projection) != nil {
		return ErrInvalidProjection
	}
	return nil
}

func (c *HTTPClient) authorization(ctx context.Context, tenantID string) (Authorization, error) {
	authorization, err := c.authorizer.Authorize(ctx, tenantID)
	if err != nil {
		return Authorization{}, ErrTokenUnavailable
	}
	if authorization.TenantID != tenantID || !validSourceSystem(authorization.SourceSystem) ||
		strings.TrimSpace(authorization.BearerToken) == "" || strings.ContainsAny(authorization.BearerToken, "\r\n") {
		return Authorization{}, ErrTokenUnavailable
	}
	return authorization, nil
}

func validSourceSystem(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= maxSourceLength &&
		!strings.ContainsAny(value, "\r\n")
}

func decodeProjectionReceipt(
	response *http.Response, tenantID string, revision uint64,
) (Receipt, error) {
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		statusErr := &HTTPStatusError{StatusCode: response.StatusCode}
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			return Receipt{}, errors.Join(ErrAuthorizationRejected, statusErr)
		}
		return Receipt{}, statusErr
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return Receipt{}, ErrProtocolConflict
	}
	var receipt Receipt
	if err := decodeStrictJSON(response.Body, &receipt); err != nil {
		return Receipt{}, ErrInvalidReceipt
	}
	if receipt.TenantID != tenantID || receipt.Revision != revision {
		return Receipt{}, ErrInvalidReceipt
	}
	return receipt, nil
}

func decodeStrictJSON(reader io.Reader, target any) error {
	limited := io.LimitReader(reader, maxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil || len(body) == 0 || len(body) > maxResponseBytes {
		return ErrInvalidReceipt
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidReceipt
	}
	return nil
}

var _ Client = (*HTTPClient)(nil)
