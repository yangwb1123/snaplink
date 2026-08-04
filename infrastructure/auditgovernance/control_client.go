package auditgovernance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	controlTenantsPath      = "api/v1/tenants"
	controlSourcesPath      = "api/v1/sources"
	controlSchemasPath      = "api/v1/schemas"
	controlRetentionPath    = "api/v1/policies/retention"
	defaultControlBodyBytes = 256 << 10
	defaultControlTimeout   = 5 * time.Second
)

var ErrControlConflict = errors.New("audit governance: control create conflict")

type ControlStatusError struct{ StatusCode int }

func (err *ControlStatusError) Error() string {
	return fmt.Sprintf("audit governance control: HTTP %d", err.StatusCode)
}

type ControlConfig struct {
	BaseURL               string
	Timeout               time.Duration
	MaxBodyBytes          int64
	AllowInsecureLoopback bool
}

// RetentionPolicyRecord is the bounded commercial retention projection sent
// through the Audit Governance control plane. The immutable ledger is never
// deleted by this policy; ArchiveDays controls archive eligibility.
type RetentionPolicyRecord struct {
	TenantID       string `json:"tenant_id"`
	HotDays        int    `json:"hot_days"`
	WarmDays       int    `json:"warm_days"`
	ArchiveDays    int    `json:"archive_days"`
	RetentionClass string `json:"retention_class"`
}

type ControlPlane interface {
	ListTenants(context.Context) ([]TenantRecord, error)
	CreateTenant(context.Context, TenantRecord) (TenantRecord, error)
	ListSources(context.Context, string) ([]SourceRecord, error)
	CreateSource(context.Context, SourceRecord) (SourceRecord, error)
	ListSchemas(context.Context, string) ([]SchemaRecord, error)
	CreateSchema(context.Context, SchemaRecord) (SchemaRecord, error)
}

type ControlClient struct {
	base    *url.URL
	tokens  PlatformTokenProvider
	client  *http.Client
	timeout time.Duration
	maxBody int64
}

func NewControlClient(config ControlConfig, tokens PlatformTokenProvider, client *http.Client) (*ControlClient, error) {
	if config.Timeout <= 0 {
		config.Timeout = defaultControlTimeout
	}
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = defaultControlBodyBytes
	}
	base, err := secureEndpoint(strings.TrimSpace(config.BaseURL), config.AllowInsecureLoopback)
	if err != nil || base.RawQuery != "" || tokens == nil {
		return nil, ErrInvalidConfig
	}
	return &ControlClient{
		base: base, tokens: tokens, client: noRedirectClient(client, config.Timeout),
		timeout: config.Timeout, maxBody: config.MaxBodyBytes,
	}, nil
}

func (client *ControlClient) ListTenants(ctx context.Context) ([]TenantRecord, error) {
	var envelope struct {
		Items []TenantRecord `json:"items"`
	}
	err := client.request(ctx, http.MethodGet, client.base.JoinPath(controlTenantsPath), nil, http.StatusOK, &envelope)
	return envelope.Items, err
}

func (client *ControlClient) CreateTenant(ctx context.Context, tenant TenantRecord) (TenantRecord, error) {
	var created TenantRecord
	err := client.request(ctx, http.MethodPost, client.base.JoinPath(controlTenantsPath), tenant, http.StatusCreated, &created)
	return created, err
}

func (client *ControlClient) ListSources(ctx context.Context, tenantID string) ([]SourceRecord, error) {
	if !canonicalText(tenantID, maxTenantIDBytes, false) {
		return nil, ErrInvalidConfig
	}
	endpoint := client.base.JoinPath(controlSourcesPath)
	query := endpoint.Query()
	query.Set("tenant_id", tenantID)
	endpoint.RawQuery = query.Encode()
	var envelope struct {
		Items []SourceRecord `json:"items"`
	}
	err := client.request(ctx, http.MethodGet, endpoint, nil, http.StatusOK, &envelope)
	return envelope.Items, err
}

func (client *ControlClient) CreateSource(ctx context.Context, source SourceRecord) (SourceRecord, error) {
	var created SourceRecord
	err := client.request(ctx, http.MethodPost, client.base.JoinPath(controlSourcesPath), source, http.StatusCreated, &created)
	return created, err
}

func (client *ControlClient) ListSchemas(ctx context.Context, tenantID string) ([]SchemaRecord, error) {
	if !canonicalText(tenantID, maxTenantIDBytes, false) {
		return nil, ErrInvalidConfig
	}
	endpoint := client.base.JoinPath(controlSchemasPath)
	query := endpoint.Query()
	query.Set("tenant_id", tenantID)
	endpoint.RawQuery = query.Encode()
	var envelope struct {
		Items []SchemaRecord `json:"items"`
	}
	err := client.request(ctx, http.MethodGet, endpoint, nil, http.StatusOK, &envelope)
	return envelope.Items, err
}

func (client *ControlClient) CreateSchema(ctx context.Context, schema SchemaRecord) (SchemaRecord, error) {
	var created SchemaRecord
	err := client.request(ctx, http.MethodPost, client.base.JoinPath(controlSchemasPath), schema, http.StatusCreated, &created)
	return created, err
}

func (client *ControlClient) SetRetentionPolicy(
	ctx context.Context, policy RetentionPolicyRecord,
) (RetentionPolicyRecord, error) {
	if !validRetentionPolicy(policy) {
		return RetentionPolicyRecord{}, ErrInvalidConfig
	}
	var applied RetentionPolicyRecord
	err := client.request(ctx, http.MethodPut, client.base.JoinPath(controlRetentionPath), policy, http.StatusOK, &applied)
	if err == nil && applied != policy {
		err = ErrInvalidReceipt
	}
	return applied, err
}

func validRetentionPolicy(policy RetentionPolicyRecord) bool {
	return canonicalText(policy.TenantID, maxTenantIDBytes, false) &&
		canonicalText(policy.RetentionClass, maxDisplayNameBytes, false) &&
		policy.HotDays >= 0 && policy.HotDays <= policy.WarmDays &&
		policy.WarmDays <= policy.ArchiveDays && policy.ArchiveDays > 0
}

func (client *ControlClient) request(
	ctx context.Context, method string, endpoint *url.URL, input any, expected int, output any,
) error {
	requestCtx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	request, err := client.newControlRequest(requestCtx, method, endpoint, input)
	if err != nil {
		return err
	}
	response, err := client.client.Do(request)
	if err != nil {
		return fmt.Errorf("audit governance control: transport unavailable")
	}
	return client.decodeControlResponse(response, expected, output)
}

func (client *ControlClient) newControlRequest(
	ctx context.Context, method string, endpoint *url.URL, input any,
) (*http.Request, error) {
	token, err := client.tokens.PlatformToken(ctx)
	if err != nil || token == "" || strings.ContainsAny(token, "\r\n") {
		return nil, ErrTokenUnavailable
	}
	body, err := encodeControlBody(input)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request, nil
}

func encodeControlBody(input any) (io.Reader, error) {
	if input == nil {
		return nil, nil
	}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(body), nil
}

func (client *ControlClient) decodeControlResponse(response *http.Response, expected int, output any) error {
	defer response.Body.Close()
	if response.StatusCode != expected {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, client.maxBody))
		if response.StatusCode == http.StatusConflict {
			return ErrControlConflict
		}
		return &ControlStatusError{StatusCode: response.StatusCode}
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return ErrInvalidReceipt
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, client.maxBody+1))
	if err != nil || int64(len(body)) > client.maxBody || json.Unmarshal(body, output) != nil {
		return ErrInvalidReceipt
	}
	return nil
}

var _ ControlPlane = (*ControlClient)(nil)
