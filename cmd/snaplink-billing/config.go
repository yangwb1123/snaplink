package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/auditgovernance"
	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	programName          = "snaplink-billing"
	defaultListen        = "127.0.0.1:8090"
	defaultAuditScope    = "audit:event:write"
	defaultAuditResource = "audit-governance"
	defaultAuditPrefix   = "snaplink-billing"
)

type runtimeConfig struct {
	Listen                string
	DevMemory             bool
	Issuer                string
	JWKSURL               string
	Audience              string
	CatalogFile           string
	SourceBindingsFile    string
	AllowInsecureLoopback bool
	Postgres              postgresConfig
	Audit                 auditConfig
	Quota                 quotaRelayConfig
	Retention             retentionProjectionConfig
	Renewals              renewalConfig
	ReadyTimeout          time.Duration
}

type postgresConfig struct {
	DSN             string
	MaxOpen         int
	MaxIdle         int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

type auditConfig struct {
	BaseURL      string
	TokenURL     string
	ClientID     string
	ClientSecret string
	RuntimeFile  string
	SourcePrefix string
	Scope        string
	Resource     string
	RelayOwner   string
	HTTPTimeout  time.Duration
	AuthPause    time.Duration
	ErrorPause   time.Duration
}

func (c auditConfig) enabled() bool { return c.BaseURL != "" }

func parseRuntimeConfig(
	args []string, getenv func(string) string, stderr io.Writer,
) (runtimeConfig, error) {
	config, err := defaultsFromEnvironment(getenv)
	if err != nil {
		return runtimeConfig{}, err
	}
	flags := flag.NewFlagSet(programName, flag.ContinueOnError)
	flags.SetOutput(stderr)
	addFlags(flags, &config)
	if err := flags.Parse(args); err != nil {
		return runtimeConfig{}, err
	}
	if flags.NArg() != 0 {
		return runtimeConfig{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	config.finalize()
	return config, config.validate()
}

func defaultsFromEnvironment(getenv func(string) string) (runtimeConfig, error) {
	devMemory, err := envBool(getenv, "SNAPLINK_BILLING_DEV_MEMORY", false)
	if err != nil {
		return runtimeConfig{}, err
	}
	allowInsecure, err := envBool(getenv, "SNAPLINK_BILLING_ALLOW_INSECURE_LOOPBACK", false)
	if err != nil {
		return runtimeConfig{}, err
	}
	durations, err := durationDefaults(getenv)
	if err != nil {
		return runtimeConfig{}, err
	}
	postgres, err := postgresDefaults(getenv, durations)
	if err != nil {
		return runtimeConfig{}, err
	}
	sourcePrefix, err := auditSourcePrefix(getenv)
	if err != nil {
		return runtimeConfig{}, err
	}
	renewals, err := renewalDefaults(getenv)
	if err != nil {
		return runtimeConfig{}, err
	}
	quota, err := quotaRelayDefaults(getenv)
	if err != nil {
		return runtimeConfig{}, err
	}
	retention, err := retentionProjectionDefaults(getenv)
	if err != nil {
		return runtimeConfig{}, err
	}
	return runtimeConfig{
		Listen: envOr(getenv, "SNAPLINK_BILLING_LISTEN", defaultListen), DevMemory: devMemory,
		Issuer: getenv("SNAPLINK_BILLING_ISSUER"), JWKSURL: getenv("SNAPLINK_BILLING_JWKS_URL"),
		Audience:              getenv("SNAPLINK_BILLING_AUDIENCE"),
		CatalogFile:           getenv("SNAPLINK_BILLING_CATALOG_FILE"),
		SourceBindingsFile:    getenv("SNAPLINK_BILLING_SOURCE_BINDINGS_FILE"),
		AllowInsecureLoopback: allowInsecure,
		Postgres:              postgres,
		Audit:                 auditDefaults(getenv, durations, sourcePrefix),
		Quota:                 quota,
		Retention:             retention,
		Renewals:              renewals,
		ReadyTimeout:          durations.ready,
	}, nil
}

func auditDefaults(
	getenv func(string) string, durations configDurations, sourcePrefix string,
) auditConfig {
	return auditConfig{
		BaseURL: getenv("SNAPLINK_BILLING_AUDIT_BASE_URL"), TokenURL: getenv("SNAPLINK_BILLING_AUDIT_TOKEN_URL"),
		ClientID: getenv("SNAPLINK_BILLING_AUDIT_CLIENT_ID"), ClientSecret: getenv("SNAPLINK_BILLING_AUDIT_CLIENT_SECRET"),
		RuntimeFile:  getenv("SNAPLINK_BILLING_AUDIT_RUNTIME_FILE"),
		SourcePrefix: sourcePrefix, Scope: envOr(getenv, "SNAPLINK_BILLING_AUDIT_SCOPE", defaultAuditScope),
		Resource:   envOr(getenv, "SNAPLINK_BILLING_AUDIT_RESOURCE", defaultAuditResource),
		RelayOwner: getenv("SNAPLINK_BILLING_RELAY_OWNER"), HTTPTimeout: durations.auditHTTP,
		AuthPause: durations.auditAuthPause, ErrorPause: durations.auditErrorPause,
	}
}

func postgresDefaults(getenv func(string) string, durations configDurations) (postgresConfig, error) {
	maxOpen, err := envInt(getenv, "SNAPLINK_BILLING_POSTGRES_MAX_OPEN", 20)
	if err != nil {
		return postgresConfig{}, err
	}
	maxIdle, err := envInt(getenv, "SNAPLINK_BILLING_POSTGRES_MAX_IDLE", 5)
	if err != nil {
		return postgresConfig{}, err
	}
	return postgresConfig{
		DSN: getenv("SNAPLINK_BILLING_POSTGRES_DSN"), MaxOpen: maxOpen, MaxIdle: maxIdle,
		ConnMaxLifetime: durations.connLifetime, ConnMaxIdleTime: durations.connIdle,
	}, nil
}

type configDurations struct {
	connLifetime, connIdle    time.Duration
	auditHTTP, auditAuthPause time.Duration
	auditErrorPause, ready    time.Duration
}

func durationDefaults(getenv func(string) string) (configDurations, error) {
	values := []struct {
		key      string
		fallback time.Duration
		target   *time.Duration
	}{}
	result := configDurations{}
	values = append(values,
		struct {
			key      string
			fallback time.Duration
			target   *time.Duration
		}{"SNAPLINK_BILLING_POSTGRES_CONN_MAX_LIFETIME", 30 * time.Minute, &result.connLifetime},
		struct {
			key      string
			fallback time.Duration
			target   *time.Duration
		}{"SNAPLINK_BILLING_POSTGRES_CONN_MAX_IDLE_TIME", 5 * time.Minute, &result.connIdle},
		struct {
			key      string
			fallback time.Duration
			target   *time.Duration
		}{"SNAPLINK_BILLING_AUDIT_HTTP_TIMEOUT", 5 * time.Second, &result.auditHTTP},
		struct {
			key      string
			fallback time.Duration
			target   *time.Duration
		}{"SNAPLINK_BILLING_AUDIT_AUTH_PAUSE", time.Minute, &result.auditAuthPause},
		struct {
			key      string
			fallback time.Duration
			target   *time.Duration
		}{"SNAPLINK_BILLING_AUDIT_ERROR_PAUSE", 5 * time.Second, &result.auditErrorPause},
		struct {
			key      string
			fallback time.Duration
			target   *time.Duration
		}{"SNAPLINK_BILLING_READY_TIMEOUT", 3 * time.Second, &result.ready},
	)
	for _, value := range values {
		parsed, err := envDuration(getenv, value.key, value.fallback)
		if err != nil {
			return configDurations{}, err
		}
		*value.target = parsed
	}
	return result, nil
}

func addFlags(flags *flag.FlagSet, config *runtimeConfig) {
	flags.StringVar(&config.Listen, "listen", config.Listen, "HTTP listen address")
	flags.BoolVar(&config.DevMemory, "dev-memory", config.DevMemory, "use non-durable memory stores (loopback only)")
	flags.StringVar(&config.Issuer, "issuer", config.Issuer, "required Snaplink token issuer")
	flags.StringVar(&config.JWKSURL, "jwks-url", config.JWKSURL, "Snaplink JWKS URL (defaults from issuer)")
	flags.StringVar(&config.Audience, "audience", config.Audience, "required billing API resource audience")
	flags.StringVar(&config.CatalogFile, "catalog-file", config.CatalogFile, "optional strict JSON plan catalog")
	flags.StringVar(&config.SourceBindingsFile, "source-bindings-file", config.SourceBindingsFile, "optional strict JSON machine-source bindings")
	flags.BoolVar(&config.AllowInsecureLoopback, "allow-insecure-loopback", config.AllowInsecureLoopback, "allow HTTP only for loopback upstreams")
	flags.IntVar(&config.Postgres.MaxOpen, "postgres-max-open", config.Postgres.MaxOpen, "PostgreSQL maximum open connections")
	flags.IntVar(&config.Postgres.MaxIdle, "postgres-max-idle", config.Postgres.MaxIdle, "PostgreSQL maximum idle connections")
	flags.StringVar(&config.Audit.BaseURL, "audit-base-url", config.Audit.BaseURL, "Audit Governance base URL; empty disables relay")
	flags.StringVar(&config.Audit.TokenURL, "audit-token-url", config.Audit.TokenURL, "OAuth token URL (defaults to issuer /token)")
	flags.StringVar(&config.Audit.ClientID, "audit-client-id", config.Audit.ClientID, "pre-registered relay OAuth client ID")
	flags.StringVar(&config.Audit.RuntimeFile, "audit-runtime-file", config.Audit.RuntimeFile, "strict hot enable/disable desired-state file")
	flags.StringVar(&config.Audit.SourcePrefix, "audit-source-prefix", config.Audit.SourcePrefix, "tenant-scoped Audit Governance source prefix")
	flags.StringVar(&config.Audit.Scope, "audit-scope", config.Audit.Scope, "relay OAuth scope")
	flags.StringVar(&config.Audit.Resource, "audit-resource", config.Audit.Resource, "relay OAuth resource audience")
	flags.StringVar(&config.Audit.RelayOwner, "relay-owner", config.Audit.RelayOwner, "unique outbox lease owner")
	addQuotaRelayFlags(flags, &config.Quota)
	addRetentionProjectionFlags(flags, &config.Retention)
	addRenewalFlags(flags, &config.Renewals)
}

func (config *runtimeConfig) finalize() {
	config.Listen = strings.TrimSpace(config.Listen)
	config.Issuer = strings.TrimSpace(config.Issuer)
	config.Audience = strings.TrimSpace(config.Audience)
	config.CatalogFile = strings.TrimSpace(config.CatalogFile)
	config.SourceBindingsFile = strings.TrimSpace(config.SourceBindingsFile)
	config.Postgres.DSN = strings.TrimSpace(config.Postgres.DSN)
	config.Audit.BaseURL = strings.TrimSpace(config.Audit.BaseURL)
	config.Audit.ClientID = strings.TrimSpace(config.Audit.ClientID)
	config.Audit.RuntimeFile = strings.TrimSpace(config.Audit.RuntimeFile)
	config.Audit.SourcePrefix = strings.TrimSpace(config.Audit.SourcePrefix)
	config.Audit.Scope = strings.Join(strings.Fields(config.Audit.Scope), " ")
	config.Audit.Resource = strings.TrimSpace(config.Audit.Resource)
	issuerBase := strings.TrimRight(config.Issuer, "/")
	if config.JWKSURL == "" && config.Issuer != "" {
		config.JWKSURL = issuerBase + core.PathJWKS
	}
	if config.Audit.enabled() && config.Audit.TokenURL == "" {
		config.Audit.TokenURL = issuerBase + core.PathToken
	}
	if config.Audit.enabled() && config.Audit.RelayOwner == "" {
		config.Audit.RelayOwner = defaultRelayOwner()
	}
	config.Quota.finalize(config.Issuer)
	config.Retention.finalize(config.Issuer)
	config.Renewals.finalize()
}

func (config runtimeConfig) validate() error {
	validations := []func() error{
		config.validateIdentity, config.validateStorage, config.validateTimeouts,
		config.validateTrust, config.validateAudit,
		func() error { return config.Quota.validate(config.AllowInsecureLoopback) },
		func() error { return config.Retention.validate(config.AllowInsecureLoopback, config.Quota) },
		func() error { return validateProjectionCredentialSeparation(config) },
		config.Renewals.validate,
	}
	for _, validate := range validations {
		if err := validate(); err != nil {
			return err
		}
	}
	return nil
}

func (config runtimeConfig) validateIdentity() error {
	if config.Listen == "" || config.Issuer == "" || config.JWKSURL == "" || config.Audience == "" {
		return errors.New("listen, issuer, jwks-url, and audience are required")
	}
	if _, _, err := net.SplitHostPort(config.Listen); err != nil {
		return errors.New("listen must be a host:port address")
	}
	if !loopbackListen(config.Listen) {
		return errors.New("listen must be loopback; expose it only through a trusted TLS edge")
	}
	return nil
}

func (config runtimeConfig) validateStorage() error {
	if config.DevMemory && config.Postgres.DSN != "" {
		return errors.New("dev-memory cannot be combined with a PostgreSQL DSN")
	}
	if !config.DevMemory && config.Postgres.DSN == "" {
		return errors.New("PostgreSQL DSN is required unless dev-memory is explicit")
	}
	if config.Postgres.MaxOpen <= 0 || config.Postgres.MaxIdle < 0 || config.Postgres.MaxIdle > config.Postgres.MaxOpen {
		return errors.New("invalid PostgreSQL pool limits")
	}
	return nil
}

func (config runtimeConfig) validateTimeouts() error {
	if config.ReadyTimeout <= 0 || config.Postgres.ConnMaxLifetime <= 0 || config.Postgres.ConnMaxIdleTime <= 0 {
		return errors.New("timeouts must be positive")
	}
	return nil
}

func (config runtimeConfig) validateTrust() error {
	if !validUpstreamURL(config.Issuer, config.AllowInsecureLoopback) ||
		!validUpstreamURL(config.JWKSURL, config.AllowInsecureLoopback) {
		return errors.New("issuer and JWKS URL require HTTPS or explicit loopback HTTP")
	}
	return nil
}

func (config runtimeConfig) validateAudit() error {
	if !config.Audit.enabled() {
		return config.validateDisabledAudit()
	}
	if err := config.validateAuditIdentity(); err != nil {
		return err
	}
	return config.validateAuditRuntime()
}

func (config runtimeConfig) validateDisabledAudit() error {
	if config.Audit.ClientID != "" || config.Audit.ClientSecret != "" || config.Audit.TokenURL != "" ||
		config.Audit.RuntimeFile != "" {
		return errors.New("audit base URL is required when relay credentials are configured")
	}
	return nil
}

func (config runtimeConfig) validateAuditIdentity() error {
	audit := config.Audit
	if audit.TokenURL == "" || audit.ClientID == "" || audit.ClientSecret == "" ||
		audit.SourcePrefix == "" || audit.Resource == "" || audit.RelayOwner == "" {
		return errors.New("enabled audit relay requires token URL, client credentials, source prefix, resource, and owner")
	}
	if _, err := auditgovernance.TenantSourceID(audit.SourcePrefix, "validation-tenant"); err != nil {
		return errors.New("invalid audit source prefix")
	}
	if audit.Scope != defaultAuditScope {
		return errors.New("audit relay scope must be exactly audit:event:write")
	}
	return nil
}

func (config runtimeConfig) validateAuditRuntime() error {
	audit := config.Audit
	if audit.HTTPTimeout <= 0 || audit.AuthPause <= 0 || audit.ErrorPause <= 0 {
		return errors.New("audit relay timeouts must be positive")
	}
	if strings.ContainsAny(audit.RelayOwner, "\r\n") ||
		!validUpstreamURL(audit.BaseURL, config.AllowInsecureLoopback) ||
		!validUpstreamURL(audit.TokenURL, config.AllowInsecureLoopback) {
		return errors.New("invalid audit relay endpoint or owner")
	}
	return nil
}

func validUpstreamURL(raw string, allowInsecureLoopback bool) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if strings.EqualFold(parsed.Scheme, "https") {
		return true
	}
	return allowInsecureLoopback && strings.EqualFold(parsed.Scheme, "http") && loopbackHost(parsed.Hostname())
}

func loopbackListen(address string) bool {
	host, _, err := net.SplitHostPort(address)
	return err == nil && loopbackHost(host)
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func defaultRelayOwner() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown-host"
	}
	return hostname + "-" + strconv.Itoa(os.Getpid())
}

func envOr(getenv func(string) string, key, fallback string) string {
	if value := getenv(key); value != "" {
		return value
	}
	return fallback
}

func auditSourcePrefix(getenv func(string) string) (string, error) {
	prefix := strings.TrimSpace(getenv("SNAPLINK_BILLING_AUDIT_SOURCE_PREFIX"))
	legacy := strings.TrimSpace(getenv("SNAPLINK_BILLING_AUDIT_SOURCE_SYSTEM"))
	if prefix != "" && legacy != "" && prefix != legacy {
		return "", errors.New("audit source prefix conflicts with legacy source system")
	}
	if prefix != "" {
		return prefix, nil
	}
	if legacy != "" {
		return legacy, nil
	}
	return defaultAuditPrefix, nil
}

func envBool(getenv func(string) string, key string, fallback bool) (bool, error) {
	value := strings.TrimSpace(getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}
	return parsed, nil
}

func envInt(getenv func(string) string, key string, fallback int) (int, error) {
	value := strings.TrimSpace(getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return parsed, nil
}

func envDuration(getenv func(string) string, key string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return parsed, nil
}
