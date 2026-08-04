package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"strings"
	"time"

	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/infrastructure/auditgovernance"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/quotaprojection"
	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	defaultQuotaSourcePrefix = "snaplink-billing-quota"
	defaultQuotaBatchSize    = 100
	maxQuotaBatchSize        = 500
	defaultRetentionTimeout  = 5 * time.Second
	maxRetentionDays         = 36_500
)

type quotaRelayConfig struct {
	BaseURL, TokenURL, ClientID, ClientSecret string
	SourcePrefix, Scope, Resource, RelayOwner string
	HTTPTimeout, Lease, InitialBackoff        time.Duration
	MaxBackoff, PollInterval, MaxLag          time.Duration
	ErrorPause                                time.Duration
	BatchSize                                 int
}

type retentionProjectionConfig struct {
	BaseURL, TokenURL, ClientID, ClientSecret, Resource string
	HTTPTimeout                                         time.Duration
}

func (config quotaRelayConfig) enabled() bool { return config.BaseURL != "" }

func quotaRelayDefaults(getenv func(string) string) (quotaRelayConfig, error) {
	durations, err := quotaRelayDurationDefaults(getenv)
	if err != nil {
		return quotaRelayConfig{}, err
	}
	batchSize, err := envInt(getenv, "SNAPLINK_BILLING_QUOTA_BATCH_SIZE", defaultQuotaBatchSize)
	if err != nil {
		return quotaRelayConfig{}, err
	}
	return quotaRelayConfig{
		BaseURL: getenv("SNAPLINK_BILLING_QUOTA_BASE_URL"), TokenURL: getenv("SNAPLINK_BILLING_QUOTA_TOKEN_URL"),
		ClientID: getenv("SNAPLINK_BILLING_QUOTA_CLIENT_ID"), ClientSecret: getenv("SNAPLINK_BILLING_QUOTA_CLIENT_SECRET"),
		SourcePrefix: getenv("SNAPLINK_BILLING_QUOTA_SOURCE_PREFIX"), Scope: getenv("SNAPLINK_BILLING_QUOTA_SCOPE"),
		Resource: getenv("SNAPLINK_BILLING_QUOTA_RESOURCE"), RelayOwner: getenv("SNAPLINK_BILLING_QUOTA_RELAY_OWNER"),
		HTTPTimeout: durations.httpTimeout, Lease: durations.lease, InitialBackoff: durations.initialBackoff,
		MaxBackoff: durations.maxBackoff, PollInterval: durations.pollInterval, MaxLag: durations.maxLag,
		ErrorPause: durations.errorPause, BatchSize: batchSize,
	}, nil
}

type quotaRelayDurations struct {
	httpTimeout, lease, initialBackoff, maxBackoff time.Duration
	pollInterval, maxLag, errorPause               time.Duration
}

func quotaRelayDurationDefaults(getenv func(string) string) (quotaRelayDurations, error) {
	result := quotaRelayDurations{}
	values := []struct {
		key      string
		fallback time.Duration
		target   *time.Duration
	}{
		{"SNAPLINK_BILLING_QUOTA_HTTP_TIMEOUT", 5 * time.Second, &result.httpTimeout},
		{"SNAPLINK_BILLING_QUOTA_LEASE", 30 * time.Second, &result.lease},
		{"SNAPLINK_BILLING_QUOTA_INITIAL_BACKOFF", time.Second, &result.initialBackoff},
		{"SNAPLINK_BILLING_QUOTA_MAX_BACKOFF", time.Minute, &result.maxBackoff},
		{"SNAPLINK_BILLING_QUOTA_POLL_INTERVAL", 500 * time.Millisecond, &result.pollInterval},
		{"SNAPLINK_BILLING_QUOTA_MAX_LAG", 5 * time.Minute, &result.maxLag},
		{"SNAPLINK_BILLING_QUOTA_ERROR_PAUSE", 5 * time.Second, &result.errorPause},
	}
	for _, value := range values {
		parsed, err := envDuration(getenv, value.key, value.fallback)
		if err != nil {
			return quotaRelayDurations{}, err
		}
		*value.target = parsed
	}
	return result, nil
}

func addQuotaRelayFlags(flags *flag.FlagSet, config *quotaRelayConfig) {
	flags.StringVar(&config.BaseURL, "quota-base-url", config.BaseURL, "SSO base URL; empty disables quota projection")
	flags.StringVar(&config.TokenURL, "quota-token-url", config.TokenURL, "OAuth token URL (defaults to issuer /token)")
	flags.StringVar(&config.ClientID, "quota-client-id", config.ClientID, "pre-registered quota relay OAuth client ID")
	flags.StringVar(&config.SourcePrefix, "quota-source-prefix", config.SourcePrefix, "tenant-scoped quota source prefix")
	flags.StringVar(&config.Scope, "quota-scope", config.Scope, "quota relay OAuth scope")
	flags.StringVar(&config.Resource, "quota-resource", config.Resource, "exact SSO quota projection audience")
	flags.StringVar(&config.RelayOwner, "quota-relay-owner", config.RelayOwner, "unique quota outbox lease owner")
	flags.DurationVar(&config.HTTPTimeout, "quota-http-timeout", config.HTTPTimeout, "quota relay HTTP timeout")
	flags.DurationVar(&config.Lease, "quota-lease", config.Lease, "quota outbox claim lease")
	flags.IntVar(&config.BatchSize, "quota-batch-size", config.BatchSize, "quota outbox claim batch size")
	flags.DurationVar(&config.InitialBackoff, "quota-initial-backoff", config.InitialBackoff, "initial quota retry delay")
	flags.DurationVar(&config.MaxBackoff, "quota-max-backoff", config.MaxBackoff, "maximum quota retry delay")
	flags.DurationVar(&config.PollInterval, "quota-poll-interval", config.PollInterval, "idle quota poll interval")
	flags.DurationVar(&config.MaxLag, "quota-max-lag", config.MaxLag, "maximum quota delivery lag for readiness")
	flags.DurationVar(&config.ErrorPause, "quota-error-pause", config.ErrorPause, "quota worker error pause")
}

func (config *quotaRelayConfig) finalize(issuer string) {
	config.BaseURL = strings.TrimSpace(config.BaseURL)
	config.TokenURL = strings.TrimSpace(config.TokenURL)
	config.ClientID = strings.TrimSpace(config.ClientID)
	config.SourcePrefix = strings.TrimSpace(config.SourcePrefix)
	config.Scope = strings.Join(strings.Fields(config.Scope), " ")
	config.Resource = strings.TrimSpace(config.Resource)
	config.RelayOwner = strings.TrimSpace(config.RelayOwner)
	if !config.enabled() {
		return
	}
	if config.TokenURL == "" {
		config.TokenURL = strings.TrimRight(issuer, "/") + core.PathToken
	}
	if config.SourcePrefix == "" {
		config.SourcePrefix = defaultQuotaSourcePrefix
	}
	if config.Scope == "" {
		config.Scope = core.ScopeTenantQuotaProjectionWrite
	}
	if config.RelayOwner == "" {
		config.RelayOwner = defaultRelayOwner() + "-quota"
	}
}

func (config quotaRelayConfig) validate(allowInsecureLoopback bool) error {
	if !config.enabled() {
		return config.validateDisabled()
	}
	if config.TokenURL == "" || config.ClientID == "" || config.ClientSecret == "" ||
		config.Resource == "" || config.RelayOwner == "" {
		return errors.New("enabled quota relay requires token URL, client credentials, resource, and owner")
	}
	if config.Scope != core.ScopeTenantQuotaProjectionWrite {
		return errors.New("quota relay scope must be exactly tenant-quota:projection:write")
	}
	if _, err := auditgovernance.TenantSourceID(config.SourcePrefix, "validation-tenant"); err != nil {
		return errors.New("invalid quota source prefix")
	}
	return config.validateRuntime(allowInsecureLoopback)
}

func (config quotaRelayConfig) validateDisabled() error {
	if config.TokenURL != "" || config.ClientID != "" || config.ClientSecret != "" ||
		config.SourcePrefix != "" || config.Scope != "" || config.Resource != "" || config.RelayOwner != "" ||
		config.nonDefaultRuntimeConfigured() {
		return errors.New("quota base URL is required when quota relay settings are configured")
	}
	return nil
}

func (config quotaRelayConfig) nonDefaultRuntimeConfigured() bool {
	return config.BatchSize != 0 && config.BatchSize != defaultQuotaBatchSize ||
		config.nonDefaultDeliveryTiming() || config.nonDefaultWorkerTiming()
}

func (config quotaRelayConfig) nonDefaultDeliveryTiming() bool {
	return config.HTTPTimeout != 0 && config.HTTPTimeout != 5*time.Second ||
		config.Lease != 0 && config.Lease != 30*time.Second ||
		config.InitialBackoff != 0 && config.InitialBackoff != time.Second ||
		config.MaxBackoff != 0 && config.MaxBackoff != time.Minute
}

func (config quotaRelayConfig) nonDefaultWorkerTiming() bool {
	return config.PollInterval != 0 && config.PollInterval != 500*time.Millisecond ||
		config.MaxLag != 0 && config.MaxLag != 5*time.Minute ||
		config.ErrorPause != 0 && config.ErrorPause != 5*time.Second
}

func (config quotaRelayConfig) validateRuntime(allowInsecureLoopback bool) error {
	if config.HTTPTimeout <= 0 || !deliveryLeaseCovers(config.Lease, config.HTTPTimeout) || config.InitialBackoff <= 0 ||
		config.MaxBackoff < config.InitialBackoff || config.PollInterval <= 0 || config.MaxLag <= 0 ||
		config.ErrorPause <= 0 {
		return errors.New("invalid quota relay durations")
	}
	if config.BatchSize <= 0 || config.BatchSize > maxQuotaBatchSize {
		return errors.New("quota relay batch size must be between 1 and 500")
	}
	if strings.ContainsAny(config.RelayOwner, "\r\n") ||
		!validUpstreamURL(config.BaseURL, allowInsecureLoopback) ||
		!validUpstreamURL(config.TokenURL, allowInsecureLoopback) {
		return errors.New("invalid quota relay endpoint or owner")
	}
	return nil
}

func retentionProjectionDefaults(getenv func(string) string) (retentionProjectionConfig, error) {
	timeout, err := envDuration(getenv, "SNAPLINK_BILLING_RETENTION_HTTP_TIMEOUT", defaultRetentionTimeout)
	if err != nil {
		return retentionProjectionConfig{}, err
	}
	return retentionProjectionConfig{
		BaseURL:      getenv("SNAPLINK_BILLING_RETENTION_BASE_URL"),
		TokenURL:     getenv("SNAPLINK_BILLING_RETENTION_TOKEN_URL"),
		ClientID:     getenv("SNAPLINK_BILLING_RETENTION_CLIENT_ID"),
		ClientSecret: getenv("SNAPLINK_BILLING_RETENTION_CLIENT_SECRET"),
		Resource:     getenv("SNAPLINK_BILLING_RETENTION_RESOURCE"), HTTPTimeout: timeout,
	}, nil
}

func addRetentionProjectionFlags(flags *flag.FlagSet, config *retentionProjectionConfig) {
	flags.StringVar(&config.BaseURL, "retention-base-url", config.BaseURL, "Audit Governance base URL; empty disables retention projection")
	flags.StringVar(&config.TokenURL, "retention-token-url", config.TokenURL, "OAuth token URL (defaults to issuer /token)")
	flags.StringVar(&config.ClientID, "retention-client-id", config.ClientID, "dedicated retention projection OAuth client ID")
	flags.StringVar(&config.Resource, "retention-resource", config.Resource, "exact Audit Governance control audience")
	flags.DurationVar(&config.HTTPTimeout, "retention-http-timeout", config.HTTPTimeout, "retention projection HTTP timeout")
}

func (config *retentionProjectionConfig) finalize(issuer string) {
	config.BaseURL = strings.TrimSpace(config.BaseURL)
	config.TokenURL = strings.TrimSpace(config.TokenURL)
	config.ClientID = strings.TrimSpace(config.ClientID)
	config.Resource = strings.TrimSpace(config.Resource)
	if config.BaseURL == "" {
		return
	}
	if config.TokenURL == "" {
		config.TokenURL = strings.TrimRight(issuer, "/") + core.PathToken
	}
	if config.Resource == "" {
		config.Resource = defaultAuditResource
	}
}

func (config retentionProjectionConfig) enabled() bool { return config.BaseURL != "" }

func (config retentionProjectionConfig) validate(allowInsecureLoopback bool, quota quotaRelayConfig) error {
	if !config.enabled() {
		if config.TokenURL != "" || config.ClientID != "" || config.ClientSecret != "" || config.Resource != "" {
			return errors.New("retention base URL is required when retention projection settings are configured")
		}
		return nil
	}
	if !quota.enabled() {
		return errors.New("retention projection requires the entitlement quota delivery pipeline")
	}
	if config.TokenURL == "" || config.ClientID == "" || config.ClientSecret == "" || config.Resource == "" {
		return errors.New("enabled retention projection requires token URL, dedicated credentials, and resource")
	}
	if config.HTTPTimeout <= 0 || !deliveryLeaseCovers(quota.Lease, quota.HTTPTimeout, config.HTTPTimeout) ||
		!validUpstreamURL(config.BaseURL, allowInsecureLoopback) ||
		!validUpstreamURL(config.TokenURL, allowInsecureLoopback) {
		return errors.New("invalid retention projection endpoint or timeout")
	}
	return nil
}

func deliveryLeaseCovers(lease time.Duration, timeouts ...time.Duration) bool {
	remaining := lease
	for _, timeout := range timeouts {
		if timeout <= 0 || remaining <= 0 || timeout >= remaining/2 {
			return false
		}
		remaining -= 2 * timeout
	}
	return remaining > 0
}

func validateProjectionCredentialSeparation(config runtimeConfig) error {
	type credential struct{ clientID, secret string }
	credentials := make([]credential, 0, 3)
	if config.Audit.enabled() {
		credentials = append(credentials, credential{config.Audit.ClientID, config.Audit.ClientSecret})
	}
	if config.Quota.enabled() {
		credentials = append(credentials, credential{config.Quota.ClientID, config.Quota.ClientSecret})
	}
	if config.Retention.enabled() {
		credentials = append(credentials, credential{config.Retention.ClientID, config.Retention.ClientSecret})
	}
	for left := range credentials {
		for right := left + 1; right < len(credentials); right++ {
			if credentials[left].clientID == credentials[right].clientID || credentials[left].secret == credentials[right].secret {
				return errors.New("audit, quota, and retention projections require distinct client credentials")
			}
		}
	}
	return nil
}

type quotaRelayRunner struct {
	relay      *quotaprojection.Relay
	poll       time.Duration
	errorPause time.Duration
}

func buildQuotaRelay(
	config runtimeConfig, store tenantcommerce.QuotaProjectionDeliveryStore,
	reader tenantcommerce.EntitlementReader,
) (*quotaRelayRunner, error) {
	if !config.Quota.enabled() {
		return nil, nil
	}
	httpClient := newUpstreamHTTPClient(config.Quota.HTTPTimeout)
	tokens, err := buildQuotaTokenSource(config, httpClient)
	if err != nil {
		return nil, err
	}
	client, err := quotaprojection.NewHTTPClient(quotaprojection.HTTPConfig{
		BaseURL: config.Quota.BaseURL, Timeout: config.Quota.HTTPTimeout,
		AllowInsecureLoopback: config.AllowInsecureLoopback,
	}, quotaAuthorizer(config.Quota.SourcePrefix, tokens), httpClient)
	if err != nil {
		return nil, err
	}
	projectionClient, err := withRetentionProjection(config, client, reader, httpClient)
	if err != nil {
		return nil, err
	}
	relay, err := quotaprojection.NewRelay(store, reader, projectionClient, quotaprojection.RelayConfig{
		Owner: config.Quota.RelayOwner, Lease: config.Quota.Lease, BatchSize: config.Quota.BatchSize,
		InitialBackoff: config.Quota.InitialBackoff, MaxBackoff: config.Quota.MaxBackoff,
		PollInterval: config.Quota.PollInterval, MaxLag: config.Quota.MaxLag,
	})
	if err != nil {
		return nil, err
	}
	return &quotaRelayRunner{relay: relay, poll: config.Quota.PollInterval, errorPause: config.Quota.ErrorPause}, nil
}

type retentionPolicySetter interface {
	SetRetentionPolicy(context.Context, auditgovernance.RetentionPolicyRecord) (auditgovernance.RetentionPolicyRecord, error)
}

type entitlementProjectionClient struct {
	quota     quotaprojection.Client
	retention retentionPolicySetter
	reader    tenantcommerce.EntitlementReader
}

func withRetentionProjection(
	config runtimeConfig, quota quotaprojection.Client, reader tenantcommerce.EntitlementReader,
	httpClient *http.Client,
) (quotaprojection.Client, error) {
	if !config.Retention.enabled() {
		return quota, nil
	}
	tokens, err := auditgovernance.NewPlatformTokenSource(auditgovernance.PlatformTokenConfig{
		TokenURL: config.Retention.TokenURL, ClientID: config.Retention.ClientID,
		ClientSecret: config.Retention.ClientSecret, Resource: config.Retention.Resource,
		Scope: auditgovernance.PlatformRetentionScope, Timeout: config.Retention.HTTPTimeout,
		AllowInsecureLoopback: config.AllowInsecureLoopback,
	}, httpClient)
	if err != nil {
		return nil, err
	}
	control, err := auditgovernance.NewControlClient(auditgovernance.ControlConfig{
		BaseURL: config.Retention.BaseURL, Timeout: config.Retention.HTTPTimeout,
		AllowInsecureLoopback: config.AllowInsecureLoopback,
	}, tokens, httpClient)
	if err != nil {
		return nil, err
	}
	return &entitlementProjectionClient{quota: quota, retention: control, reader: reader}, nil
}

func (client *entitlementProjectionClient) Publish(
	ctx context.Context, event *tenantcommerce.OutboxEvent, projection core.TenantQuotaProjection,
) (quotaprojection.Receipt, error) {
	receipt, err := client.quota.Publish(ctx, event, projection)
	if err != nil {
		return receipt, err
	}
	snapshot, err := client.reader.CurrentEntitlement(ctx, event.TenantID)
	if err != nil {
		return receipt, err
	}
	policy, err := commercialRetentionPolicy(event, snapshot)
	if err != nil {
		return receipt, err
	}
	_, err = client.retention.SetRetentionPolicy(ctx, policy)
	return receipt, normalizeRetentionError(err)
}

func commercialRetentionPolicy(
	event *tenantcommerce.OutboxEvent, snapshot *tenantcommerce.EntitlementSnapshot,
) (auditgovernance.RetentionPolicyRecord, error) {
	if event == nil || snapshot == nil || snapshot.TenantID != event.TenantID ||
		snapshot.Revision < event.AggregateVersion {
		return auditgovernance.RetentionPolicyRecord{}, quotaprojection.ErrInvalidProjection
	}
	grant, ok := snapshot.Limits[tenantcommerce.LimitAuditRetentionDays]
	if !ok || grant.Unlimited || grant.Hard <= 0 || grant.Hard > maxRetentionDays {
		return auditgovernance.RetentionPolicyRecord{}, quotaprojection.ErrInvalidProjection
	}
	days := int(grant.Hard)
	return auditgovernance.RetentionPolicyRecord{
		TenantID: event.TenantID, HotDays: min(days, 7), WarmDays: min(days, 30), ArchiveDays: days,
		RetentionClass: "standard",
	}, nil
}

func normalizeRetentionError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, auditgovernance.ErrTokenUnavailable) {
		return quotaprojection.ErrAuthorizationRejected
	}
	if errors.Is(err, auditgovernance.ErrInvalidReceipt) || errors.Is(err, auditgovernance.ErrInvalidConfig) {
		return quotaprojection.ErrProtocolConflict
	}
	var status *auditgovernance.ControlStatusError
	if !errors.As(err, &status) {
		return err
	}
	if status.StatusCode == http.StatusUnauthorized || status.StatusCode == http.StatusForbidden {
		return quotaprojection.ErrAuthorizationRejected
	}
	return &quotaprojection.HTTPStatusError{StatusCode: status.StatusCode}
}

func buildQuotaTokenSource(
	config runtimeConfig, client *http.Client,
) (*auditgovernance.OAuthTokenSource, error) {
	quota := config.Quota
	return auditgovernance.NewOAuthTokenSource(auditgovernance.OAuthTokenConfig{
		TokenURL: quota.TokenURL, ClientID: quota.ClientID, ClientSecret: quota.ClientSecret,
		SourcePrefix: quota.SourcePrefix, Scope: quota.Scope, Resources: []string{quota.Resource},
		Timeout: quota.HTTPTimeout, AllowInsecureLoopback: config.AllowInsecureLoopback,
	}, client)
}

func quotaAuthorizer(
	prefix string, tokens auditgovernance.ClientCredentialsTokenSource,
) quotaprojection.Authorizer {
	return quotaprojection.AuthorizerFunc(func(ctx context.Context, tenantID string) (quotaprojection.Authorization, error) {
		sourceID, err := auditgovernance.TenantSourceID(prefix, tenantID)
		if err != nil {
			return quotaprojection.Authorization{}, quotaprojection.ErrTokenUnavailable
		}
		token, err := tokens.AccessToken(ctx, auditgovernance.SourceBinding{
			TenantID: tenantID, SourceSystem: sourceID,
		})
		if err != nil {
			return quotaprojection.Authorization{}, err
		}
		return quotaprojection.Authorization{
			TenantID: tenantID, SourceSystem: sourceID, BearerToken: token,
		}, nil
	})
}

func (runner *quotaRelayRunner) run(ctx context.Context, logger *log.Logger) {
	for ctx.Err() == nil {
		result, err := runner.relay.RunOnce(ctx)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				logger.Printf("tenant quota projection relay paused after error: %v", err)
			}
			if !waitQuotaRelay(ctx, runner.errorPause) {
				return
			}
			continue
		}
		if result.Claimed == 0 && !waitQuotaRelay(ctx, runner.poll) {
			return
		}
	}
}

func (runner *quotaRelayRunner) Ready(ctx context.Context) error {
	return runner.relay.Ready(ctx)
}

func waitQuotaRelay(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
