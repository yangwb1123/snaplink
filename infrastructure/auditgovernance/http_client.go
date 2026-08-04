package auditgovernance

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

const (
	defaultHTTPTimeout = 5 * time.Second
	maxReceiptBytes    = 64 << 10
	governancePath     = "api/v1/events"
)

// HTTPConfig fixes the tenant-scoped source namespace and schema projection.
type HTTPConfig struct {
	BaseURL      string
	SourcePrefix string
	// SourceSystem is a compatibility alias for SourcePrefix.
	// Deprecated: configure SourcePrefix for tenant-scoped source IDs.
	SourceSystem       string
	ActorID            string
	SchemaVersion      int
	DataClassification string
	RetentionClass     string
	Timeout            time.Duration
	// AllowInsecureLoopback permits explicit local development over HTTP.
	// Non-loopback HTTP endpoints are never accepted.
	AllowInsecureLoopback bool
}

// HTTPClient is a redirect-safe Audit Governance ingestion client.
type HTTPClient struct {
	endpoint           *url.URL
	sourcePrefix       string
	actorID            string
	schemaVersion      int
	dataClassification string
	retentionClass     string
	tokens             ClientCredentialsTokenSource
	client             *http.Client
}

func NewHTTPClient(
	config HTTPConfig, tokens ClientCredentialsTokenSource, client *http.Client,
) (*HTTPClient, error) {
	config = defaultHTTPConfig(config)
	endpoint, err := governanceEndpoint(config.BaseURL, config.AllowInsecureLoopback)
	if err != nil || tokens == nil || !validHTTPConfig(config) {
		return nil, ErrInvalidConfig
	}
	return &HTTPClient{
		endpoint: endpoint, sourcePrefix: config.SourcePrefix, actorID: config.ActorID,
		schemaVersion: config.SchemaVersion, dataClassification: config.DataClassification,
		retentionClass: config.RetentionClass, tokens: tokens,
		client: noRedirectClient(client, config.Timeout),
	}, nil
}

func defaultHTTPConfig(config HTTPConfig) HTTPConfig {
	config.BaseURL = strings.TrimSpace(config.BaseURL)
	config.SourcePrefix = strings.TrimSpace(config.SourcePrefix)
	config.SourceSystem = strings.TrimSpace(config.SourceSystem)
	if config.SourcePrefix == "" {
		config.SourcePrefix = config.SourceSystem
	}
	config.ActorID = strings.TrimSpace(config.ActorID)
	config.DataClassification = strings.TrimSpace(config.DataClassification)
	config.RetentionClass = strings.TrimSpace(config.RetentionClass)
	if config.ActorID == "" {
		config.ActorID = "snaplink-commerce"
	}
	if config.SchemaVersion == 0 {
		config.SchemaVersion = 1
	}
	if config.DataClassification == "" {
		config.DataClassification = "financial"
	}
	if config.RetentionClass == "" {
		config.RetentionClass = "billing_7y"
	}
	if config.Timeout <= 0 {
		config.Timeout = defaultHTTPTimeout
	}
	return config
}

func validHTTPConfig(config HTTPConfig) bool {
	return validSourcePrefix(config.SourcePrefix) && config.ActorID != "" && config.SchemaVersion > 0 &&
		config.DataClassification != "" && config.RetentionClass != "" && config.Timeout > 0
}

func governanceEndpoint(raw string, allowInsecureLoopback bool) (*url.URL, error) {
	base, err := url.Parse(raw)
	if err != nil || base.Host == "" {
		return nil, ErrInvalidConfig
	}
	if base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, ErrInvalidConfig
	}
	if base.Scheme != "https" && !allowedLoopbackHTTP(base, allowInsecureLoopback) {
		return nil, ErrInvalidConfig
	}
	endpoint := base.JoinPath(governancePath)
	query := endpoint.Query()
	query.Set("wait_for", "ledgered")
	endpoint.RawQuery = query.Encode()
	return endpoint, nil
}

func allowedLoopbackHTTP(endpoint *url.URL, allowed bool) bool {
	if !allowed || endpoint.Scheme != "http" {
		return false
	}
	if strings.EqualFold(endpoint.Hostname(), "localhost") {
		return true
	}
	ip := net.ParseIP(endpoint.Hostname())
	return ip != nil && ip.IsLoopback()
}

func noRedirectClient(client *http.Client, timeout time.Duration) *http.Client {
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

func (c *HTTPClient) Publish(ctx context.Context, event *commerce.OutboxEvent) (Receipt, error) {
	if err := validateCommerceEvent(event); err != nil {
		return Receipt{}, err
	}
	sourceSystem, err := TenantSourceID(c.sourcePrefix, event.TenantID)
	if err != nil {
		return Receipt{}, ErrInvalidEvent
	}
	token, err := c.accessToken(ctx, event.TenantID, sourceSystem)
	if err != nil {
		return Receipt{}, err
	}
	body, err := json.Marshal(c.governanceEvent(event, sourceSystem))
	if err != nil {
		return Receipt{}, ErrInvalidEvent
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return Receipt{}, ErrInvalidConfig
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return Receipt{}, err
	}
	return decodeReceipt(response, event)
}

func (c *HTTPClient) accessToken(ctx context.Context, tenantID, sourceSystem string) (string, error) {
	binding := SourceBinding{TenantID: tenantID, SourceSystem: sourceSystem}
	token, err := c.tokens.AccessToken(ctx, binding)
	if err != nil || strings.TrimSpace(token) == "" || strings.ContainsAny(token, "\r\n") {
		return "", ErrTokenUnavailable
	}
	return token, nil
}

type governanceEvent struct {
	EventID            string             `json:"event_id"`
	SourceSystem       string             `json:"source_system"`
	EventType          string             `json:"event_type"`
	SchemaID           string             `json:"schema_id"`
	SchemaVersion      int                `json:"schema_version"`
	OccurredAt         time.Time          `json:"occurred_at"`
	Actor              governanceActor    `json:"actor"`
	Targets            []governanceTarget `json:"targets"`
	AggregateType      string             `json:"aggregate_type"`
	AggregateID        string             `json:"aggregate_id"`
	AggregateVersion   int64              `json:"aggregate_version"`
	Action             string             `json:"action"`
	Outcome            string             `json:"outcome"`
	Payload            map[string]any     `json:"payload"`
	DataClassification string             `json:"data_classification"`
	RetentionClass     string             `json:"retention_class"`
	IdempotencyKey     string             `json:"idempotency_key"`
}

type governanceActor struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type governanceTarget struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (c *HTTPClient) governanceEvent(event *commerce.OutboxEvent, sourceSystem string) governanceEvent {
	facts := make(map[string]string, len(event.Payload))
	for key, value := range event.Payload {
		facts[key] = value
	}
	return governanceEvent{
		EventID: event.ID, SourceSystem: sourceSystem, EventType: string(event.Type),
		SchemaID: string(event.Type), SchemaVersion: c.schemaVersion, OccurredAt: event.OccurredAt.UTC(),
		Actor:         governanceActor{ID: c.actorID, Type: "service"},
		Targets:       []governanceTarget{{Type: event.AggregateType, ID: event.AggregateID}},
		AggregateType: event.AggregateType, AggregateID: event.AggregateID,
		AggregateVersion: int64(event.AggregateVersion), Action: eventAction(event.Type), Outcome: "success",
		Payload:            map[string]any{"facts": facts, "payload_digest": event.PayloadDigest},
		DataClassification: c.dataClassification, RetentionClass: c.retentionClass,
		IdempotencyKey: event.IdempotencyKey,
	}
}

func eventAction(eventType commerce.EventType) string {
	value := string(eventType)
	if index := strings.LastIndexByte(value, '.'); index >= 0 && index+1 < len(value) {
		return value[index+1:]
	}
	return value
}

func validateCommerceEvent(event *commerce.OutboxEvent) error {
	if event == nil || event.ID == "" || event.TenantID == "" || event.Type == "" {
		return ErrInvalidEvent
	}
	if event.AggregateType == "" || event.AggregateID == "" || event.AggregateVersion == 0 {
		return ErrInvalidEvent
	}
	if event.AggregateVersion > math.MaxInt64 || event.IdempotencyKey == "" || event.OccurredAt.IsZero() {
		return ErrInvalidEvent
	}
	if event.PayloadDigest == "" || hasSensitivePayloadKey(event.Payload) {
		return ErrInvalidEvent
	}
	return nil
}

func hasSensitivePayloadKey(payload map[string]string) bool {
	for key := range payload {
		normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
		if normalized == "tenant_id" || normalized == "source_system" {
			return true
		}
		for _, forbidden := range []string{
			"password", "token", "private_key", "device_credential", "card_number",
			"secret", "credential", "authorization",
		} {
			if strings.Contains(normalized, forbidden) {
				return true
			}
		}
		if normalized == "pan" || normalized == "cvv" ||
			strings.HasSuffix(normalized, "_pan") || strings.HasSuffix(normalized, "_cvv") {
			return true
		}
	}
	return false
}

type receiptEnvelope struct {
	Receipt wireReceipt `json:"receipt"`
}

type wireReceipt struct {
	EventID    string    `json:"event_id"`
	TenantID   string    `json:"tenant_id"`
	Status     string    `json:"status"`
	AcceptedAt time.Time `json:"accepted_at"`
	Duplicate  bool      `json:"duplicate"`
	Conflict   bool      `json:"conflict"`
}

func decodeReceipt(response *http.Response, event *commerce.OutboxEvent) (Receipt, error) {
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxReceiptBytes))
		return Receipt{}, &HTTPStatusError{StatusCode: response.StatusCode}
	}
	if response.StatusCode != http.StatusAccepted {
		return Receipt{}, ErrProtocolConflict
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return Receipt{}, ErrInvalidReceipt
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxReceiptBytes+1))
	if err != nil || len(encoded) > maxReceiptBytes {
		return Receipt{}, ErrInvalidReceipt
	}
	var envelope receiptEnvelope
	if json.Unmarshal(encoded, &envelope) != nil || !validReceipt(envelope.Receipt, event) {
		return Receipt{}, ErrInvalidReceipt
	}
	return Receipt{
		EventID: envelope.Receipt.EventID, TenantID: envelope.Receipt.TenantID,
		Status: envelope.Receipt.Status, AcceptedAt: envelope.Receipt.AcceptedAt,
		Duplicate: envelope.Receipt.Duplicate,
	}, nil
}

func validReceipt(receipt wireReceipt, event *commerce.OutboxEvent) bool {
	if receipt.EventID != event.ID || receipt.TenantID != event.TenantID || receipt.AcceptedAt.IsZero() {
		return false
	}
	if receipt.Conflict {
		return false
	}
	switch receipt.Status {
	case "ledgered", "indexed", "archived":
		return true
	default:
		return false
	}
}

var _ Client = (*HTTPClient)(nil)
