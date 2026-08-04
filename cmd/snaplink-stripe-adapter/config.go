package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const maxBindingsFileBytes = int64(2 * 1024 * 1024)

var (
	envReferencePattern  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	stripeVersionPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(\.[A-Za-z0-9_-]+)?$`)
)

type runtimeConfig struct {
	Listen              string
	TLSCertFile         string
	TLSKeyFile          string
	PostgresDSN         string
	Issuer              string
	JWKSURL             string
	Audience            string
	BillingBaseURL      string
	TokenURL            string
	BillingResource     string
	StripeAPIBaseURL    string
	StripeAPIVersion    string
	StripeAPIKey        string
	WebhookSecrets      []string
	StripeLiveMode      bool
	StripeAccount       string
	WebhookAPIVersion   string
	ReturnOrigins       map[string]struct{}
	Bindings            []tenantBinding
	CheckoutBindings    map[string]*tenantBinding
	TenantBindings      map[string]*tenantBinding
	AllowInsecureLocal  bool
	HTTPTimeout         time.Duration
	HandlerTimeout      time.Duration
	ReadyTimeout        time.Duration
	PollInterval        time.Duration
	ClaimLease          time.Duration
	ShutdownDrain       time.Duration
	BatchSize           int
	DeliveryConcurrency int
	MaxBacklog          int64
	MaxBacklogAge       time.Duration
}

type bindingFile struct {
	Version  int               `json:"version"`
	Bindings []bindingFileItem `json:"bindings"`
}

type bindingFileItem struct {
	TenantID               string   `json:"tenant_id"`
	CheckoutClientIDs      []string `json:"checkout_client_ids"`
	BillingClientID        string   `json:"billing_client_id"`
	BillingClientSecretEnv string   `json:"billing_client_secret_env"`
}

func loadConfig(getenv func(string) string) (runtimeConfig, error) {
	allowLocal, err := parseBool(getenv("SNAPLINK_STRIPE_ALLOW_INSECURE_LOOPBACK"), false)
	if err != nil {
		return runtimeConfig{}, err
	}
	config := runtimeConfig{
		Listen:      envDefault(getenv, "SNAPLINK_STRIPE_LISTEN", "127.0.0.1:8091"),
		TLSCertFile: getenv("SNAPLINK_STRIPE_TLS_CERT_FILE"), TLSKeyFile: getenv("SNAPLINK_STRIPE_TLS_KEY_FILE"),
		PostgresDSN: getenv("SNAPLINK_STRIPE_POSTGRES_DSN"), Issuer: getenv("SNAPLINK_STRIPE_ISSUER"),
		JWKSURL: getenv("SNAPLINK_STRIPE_JWKS_URL"), Audience: getenv("SNAPLINK_STRIPE_AUDIENCE"),
		BillingBaseURL: getenv("SNAPLINK_STRIPE_BILLING_BASE_URL"), TokenURL: getenv("SNAPLINK_STRIPE_TOKEN_URL"),
		BillingResource:  getenv("SNAPLINK_STRIPE_BILLING_RESOURCE"),
		StripeAPIBaseURL: envDefault(getenv, "SNAPLINK_STRIPE_API_BASE_URL", "https://api.stripe.com"),
		StripeAPIVersion: getenv("SNAPLINK_STRIPE_API_VERSION"), StripeAPIKey: getenv("SNAPLINK_STRIPE_API_KEY"),
		WebhookSecrets:     splitNonEmpty(getenv("SNAPLINK_STRIPE_WEBHOOK_SECRETS")),
		StripeAccount:      getenv("SNAPLINK_STRIPE_ACCOUNT"),
		WebhookAPIVersion:  getenv("SNAPLINK_STRIPE_WEBHOOK_API_VERSION"),
		AllowInsecureLocal: allowLocal,
	}
	liveMode, err := parseRequiredBool(getenv("SNAPLINK_STRIPE_LIVE_MODE"))
	if err != nil {
		return runtimeConfig{}, err
	}
	config.StripeLiveMode = liveMode
	if err := loadConfigLimits(&config, getenv); err != nil {
		return runtimeConfig{}, err
	}
	origins, err := parseOrigins(getenv("SNAPLINK_STRIPE_RETURN_ORIGINS"), allowLocal)
	if err != nil {
		return runtimeConfig{}, err
	}
	config.ReturnOrigins = origins
	bindings, err := loadBindings(getenv("SNAPLINK_STRIPE_BINDINGS_FILE"), getenv)
	if err != nil {
		return runtimeConfig{}, err
	}
	config.Bindings = bindings
	if err := config.indexBindings(); err != nil {
		return runtimeConfig{}, err
	}
	return config, config.validate()
}

func loadConfigLimits(config *runtimeConfig, getenv func(string) string) error {
	var err error
	if config.HTTPTimeout, err = parseDuration(getenv("SNAPLINK_STRIPE_HTTP_TIMEOUT"), 10*time.Second); err != nil {
		return err
	}
	if config.HandlerTimeout, err = parseDuration(getenv("SNAPLINK_STRIPE_HANDLER_TIMEOUT"), 25*time.Second); err != nil {
		return err
	}
	if config.ReadyTimeout, err = parseDuration(getenv("SNAPLINK_STRIPE_READY_TIMEOUT"), 2*time.Second); err != nil {
		return err
	}
	if config.PollInterval, err = parseDuration(getenv("SNAPLINK_STRIPE_POLL_INTERVAL"), time.Second); err != nil {
		return err
	}
	if config.ClaimLease, err = parseDuration(getenv("SNAPLINK_STRIPE_CLAIM_LEASE"), 45*time.Second); err != nil {
		return err
	}
	if config.ShutdownDrain, err = parseDuration(getenv("SNAPLINK_STRIPE_SHUTDOWN_DRAIN"), 50*time.Second); err != nil {
		return err
	}
	if config.MaxBacklogAge, err = parseDuration(getenv("SNAPLINK_STRIPE_MAX_BACKLOG_AGE"), 15*time.Minute); err != nil {
		return err
	}
	if config.BatchSize, err = parseInt(getenv("SNAPLINK_STRIPE_BATCH_SIZE"), 50); err != nil {
		return err
	}
	if config.DeliveryConcurrency, err = parseInt(getenv("SNAPLINK_STRIPE_DELIVERY_CONCURRENCY"), 8); err != nil {
		return err
	}
	config.MaxBacklog, err = parseInt64(getenv("SNAPLINK_STRIPE_MAX_BACKLOG"), 10000)
	return err
}

func (c *runtimeConfig) indexBindings() error {
	c.CheckoutBindings = make(map[string]*tenantBinding)
	c.TenantBindings = make(map[string]*tenantBinding)
	billingClients := make(map[string]struct{})
	for index := range c.Bindings {
		binding := &c.Bindings[index]
		if _, exists := c.TenantBindings[binding.TenantID]; exists {
			return fmt.Errorf("%w: duplicate tenant binding", errInvalidConfig)
		}
		if _, exists := billingClients[binding.BillingClientID]; exists {
			return fmt.Errorf("%w: billing client is not tenant-unique", errInvalidConfig)
		}
		billingClients[binding.BillingClientID] = struct{}{}
		c.TenantBindings[binding.TenantID] = binding
		for _, clientID := range binding.CheckoutClientIDs {
			if _, exists := c.CheckoutBindings[clientID]; exists {
				return fmt.Errorf("%w: checkout client is not tenant-unique", errInvalidConfig)
			}
			c.CheckoutBindings[clientID] = binding
		}
	}
	return nil
}

func (c runtimeConfig) validate() error {
	checks := []func() error{
		c.validateRequired, c.validateSecrets, c.validateStripeBinding, c.validateURLs, c.validateBounds,
	}
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

func (c runtimeConfig) validateRequired() error {
	if c.PostgresDSN == "" || c.Issuer == "" || c.JWKSURL == "" || c.Audience == "" ||
		c.BillingBaseURL == "" || c.TokenURL == "" || c.BillingResource == "" ||
		c.StripeAPIVersion == "" || c.WebhookAPIVersion == "" || c.StripeAccount == "" ||
		len(c.Bindings) == 0 || len(c.ReturnOrigins) == 0 {
		return fmt.Errorf("%w: required setting is empty", errInvalidConfig)
	}
	return validateListen(c.Listen, c.TLSCertFile, c.TLSKeyFile)
}

func (c runtimeConfig) validateSecrets() error {
	if !validStripeAPIKey(c.StripeAPIKey, c.StripeLiveMode) || len(c.WebhookSecrets) == 0 ||
		len(c.WebhookSecrets) > maxWebhookSecrets {
		return fmt.Errorf("%w: invalid Stripe secret", errInvalidConfig)
	}
	for _, secret := range c.WebhookSecrets {
		if !validSecret(secret) || !strings.HasPrefix(secret, "whsec_") {
			return fmt.Errorf("%w: invalid webhook secret", errInvalidConfig)
		}
	}
	return nil
}

func (c runtimeConfig) validateStripeBinding() error {
	validAccount := c.StripeAccount == "platform" ||
		(strings.HasPrefix(c.StripeAccount, "acct_") && len(c.StripeAccount) > len("acct_") && validStripeID(c.StripeAccount))
	if !validAccount || !stripeVersionPattern.MatchString(c.StripeAPIVersion) ||
		!stripeVersionPattern.MatchString(c.WebhookAPIVersion) {
		return fmt.Errorf("%w: invalid Stripe event binding", errInvalidConfig)
	}
	return nil
}

func (c runtimeConfig) validateURLs() error {
	urls := []string{c.Issuer, c.JWKSURL, c.BillingBaseURL, c.TokenURL, c.StripeAPIBaseURL}
	for _, raw := range urls {
		if _, err := validateServiceURL(raw, c.AllowInsecureLocal); err != nil {
			return err
		}
	}
	return nil
}

func (c runtimeConfig) validateBounds() error {
	if c.BatchSize < 1 || c.BatchSize > 500 || c.DeliveryConcurrency < 1 || c.DeliveryConcurrency > 100 ||
		c.MaxBacklog < 1 || c.HTTPTimeout < time.Second ||
		c.HandlerTimeout < 2*c.HTTPTimeout+time.Second ||
		c.ClaimLease < 2*c.HTTPTimeout+2*time.Second || c.PollInterval < 100*time.Millisecond ||
		c.ReadyTimeout < 100*time.Millisecond || c.ShutdownDrain < c.ClaimLease || c.MaxBacklogAge < time.Second {
		return fmt.Errorf("%w: invalid runtime bounds", errInvalidConfig)
	}
	return nil
}

func loadBindings(path string, getenv func(string) string) ([]tenantBinding, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: bindings file is required", errInvalidConfig)
	}
	payload, err := readBoundedFile(path, maxBindingsFileBytes)
	if err != nil {
		return nil, err
	}
	var document bindingFile
	if err := decodeStrictJSON(payload, &document); err != nil || document.Version != 1 || len(document.Bindings) == 0 {
		return nil, fmt.Errorf("%w: invalid bindings file", errInvalidConfig)
	}
	bindings := make([]tenantBinding, 0, len(document.Bindings))
	for _, item := range document.Bindings {
		if !validIdentity(item.TenantID) || !validIdentity(item.BillingClientID) ||
			len(item.CheckoutClientIDs) == 0 || !envReferencePattern.MatchString(item.BillingClientSecretEnv) {
			return nil, fmt.Errorf("%w: invalid binding identity", errInvalidConfig)
		}
		secret := getenv(item.BillingClientSecretEnv)
		if !validSecret(secret) {
			return nil, fmt.Errorf("%w: billing client secret is unavailable", errInvalidConfig)
		}
		clients := make([]string, 0, len(item.CheckoutClientIDs))
		seen := make(map[string]struct{})
		for _, clientID := range item.CheckoutClientIDs {
			if !validIdentity(clientID) {
				return nil, fmt.Errorf("%w: invalid checkout client", errInvalidConfig)
			}
			if _, exists := seen[clientID]; exists {
				return nil, fmt.Errorf("%w: duplicate checkout client", errInvalidConfig)
			}
			seen[clientID] = struct{}{}
			clients = append(clients, clientID)
		}
		bindings = append(bindings, tenantBinding{
			TenantID: item.TenantID, CheckoutClientIDs: clients,
			BillingClientID: item.BillingClientID, BillingSecret: secret,
		})
	}
	return bindings, nil
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !safeDesiredStateFile(before) {
		return nil, fmt.Errorf("%w: unsafe bindings file", errInvalidConfig)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: open bindings file", errInvalidConfig)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !safeDesiredStateFile(after) || !os.SameFile(before, after) {
		return nil, fmt.Errorf("%w: bindings file changed during open", errInvalidConfig)
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) > maximum {
		return nil, fmt.Errorf("%w: read bindings file", errInvalidConfig)
	}
	return payload, nil
}

func safeDesiredStateFile(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm()&0o022 == 0 && info.Size() >= 0
}

func decodeStrictJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func parseOrigins(raw string, allowLocal bool) (map[string]struct{}, error) {
	result := make(map[string]struct{})
	for _, candidate := range splitNonEmpty(raw) {
		parsed, err := validateServiceURL(candidate, allowLocal)
		if err != nil || (parsed.Path != "" && parsed.Path != "/") {
			return nil, fmt.Errorf("%w: invalid return origin", errInvalidConfig)
		}
		result[parsed.Scheme+"://"+parsed.Host] = struct{}{}
	}
	return result, nil
}

func validateServiceURL(raw string, allowLocal bool) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: invalid service URL", errInvalidConfig)
	}
	if parsed.Scheme == "https" {
		return parsed, nil
	}
	if parsed.Scheme == "http" && allowLocal && loopbackHost(parsed.Hostname()) {
		return parsed, nil
	}
	return nil, fmt.Errorf("%w: service URL must use HTTPS", errInvalidConfig)
}

func validateListen(address, certFile, keyFile string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil || (certFile == "") != (keyFile == "") {
		return fmt.Errorf("%w: invalid listen or TLS pair", errInvalidConfig)
	}
	if !loopbackHost(host) && certFile == "" {
		return fmt.Errorf("%w: non-loopback listen requires TLS", errInvalidConfig)
	}
	return nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func validIdentity(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 256 || strings.ContainsAny(value, "/\\") {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func validSecret(value string) bool {
	return value != "" && len(value) <= 4096 && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\r\n\x00")
}

func validStripeAPIKey(value string, live bool) bool {
	if !validSecret(value) {
		return false
	}
	prefixes := []string{"sk_test_", "rk_test_"}
	if live {
		prefixes = []string{"sk_live_", "rk_live_"}
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) && len(value) > len(prefix) {
			return true
		}
	}
	return false
}

func splitNonEmpty(raw string) []string {
	var result []string
	for _, value := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func envDefault(getenv func(string) string, key, fallback string) string {
	if value := strings.TrimSpace(getenv(key)); value != "" {
		return value
	}
	return fallback
}

func parseBool(raw string, fallback bool) (bool, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%w: invalid boolean", errInvalidConfig)
	}
	return value, nil
}

func parseRequiredBool(raw string) (bool, error) {
	if strings.TrimSpace(raw) == "" {
		return false, fmt.Errorf("%w: required boolean is empty", errInvalidConfig)
	}
	return parseBool(raw, false)
}

func parseDuration(raw string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%w: invalid duration", errInvalidConfig)
	}
	return value, nil
}

func parseInt(raw string, fallback int) (int, error) {
	value, err := parseInt64(raw, int64(fallback))
	return int(value), err
}

func parseInt64(raw string, fallback int64) (int64, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%w: invalid integer", errInvalidConfig)
	}
	return value, nil
}
