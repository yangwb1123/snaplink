package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	programName            = "snaplink-audit-provisioner"
	defaultListen          = ":8092"
	defaultPollInterval    = 30 * time.Second
	defaultRequestTimeout  = 5 * time.Second
	defaultShutdownTimeout = 15 * time.Second
	maxRequestTimeout      = time.Minute
	maxSecretBytes         = 64 << 10
)

type runtimeConfig struct {
	ManifestFile          string
	BaseURL               string
	TokenURL              string
	ClientID              string
	ClientSecret          string
	Resource              string
	Listen                string
	PollInterval          time.Duration
	RequestTimeout        time.Duration
	ShutdownTimeout       time.Duration
	OneShot               bool
	AllowInsecureLoopback bool
}

func parseRuntimeConfig(
	args []string, getenv func(string) string, stderr io.Writer,
) (runtimeConfig, error) {
	config, err := configFromEnvironment(getenv)
	if err != nil {
		return runtimeConfig{}, err
	}
	flags := flag.NewFlagSet(programName, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&config.ManifestFile, "manifest-file", config.ManifestFile, "strict desired-state JSON file")
	flags.StringVar(&config.BaseURL, "audit-base-url", config.BaseURL, "Audit Governance base URL")
	flags.StringVar(&config.TokenURL, "token-url", config.TokenURL, "platform OAuth token URL")
	flags.StringVar(&config.ClientID, "client-id", config.ClientID, "dedicated platform provisioner client ID")
	flags.StringVar(&config.Resource, "resource", config.Resource, "fixed Audit Governance control resource")
	flags.StringVar(&config.Listen, "listen", config.Listen, "health and metrics listen address")
	flags.DurationVar(&config.PollInterval, "poll-interval", config.PollInterval, "desired-state poll interval")
	flags.DurationVar(&config.RequestTimeout, "request-timeout", config.RequestTimeout, "per-request timeout")
	flags.BoolVar(&config.OneShot, "one-shot", config.OneShot, "reconcile once and exit")
	flags.BoolVar(&config.AllowInsecureLoopback, "allow-insecure-loopback", config.AllowInsecureLoopback, "allow HTTP loopback development endpoints")
	if err := flags.Parse(args); err != nil {
		return runtimeConfig{}, err
	}
	if flags.NArg() != 0 {
		return runtimeConfig{}, errors.New("positional arguments are not supported")
	}
	config.normalize()
	if err := config.validate(); err != nil {
		return runtimeConfig{}, err
	}
	return config, nil
}

func configFromEnvironment(getenv func(string) string) (runtimeConfig, error) {
	poll, err := envDuration(getenv, "SNAPLINK_AUDIT_PROVISIONER_POLL_INTERVAL", defaultPollInterval)
	if err != nil {
		return runtimeConfig{}, err
	}
	timeout, err := envDuration(getenv, "SNAPLINK_AUDIT_PROVISIONER_REQUEST_TIMEOUT", defaultRequestTimeout)
	if err != nil {
		return runtimeConfig{}, err
	}
	oneShot, err := envBool(getenv, "SNAPLINK_AUDIT_PROVISIONER_ONE_SHOT", false)
	if err != nil {
		return runtimeConfig{}, err
	}
	allowHTTP, err := envBool(getenv, "SNAPLINK_AUDIT_PROVISIONER_ALLOW_INSECURE_LOOPBACK", false)
	if err != nil {
		return runtimeConfig{}, err
	}
	secret, err := provisionerSecret(getenv)
	if err != nil {
		return runtimeConfig{}, err
	}
	return runtimeConfig{
		ManifestFile: getenv("SNAPLINK_AUDIT_PROVISIONER_MANIFEST_FILE"),
		BaseURL:      getenv("SNAPLINK_AUDIT_PROVISIONER_BASE_URL"), TokenURL: getenv("SNAPLINK_AUDIT_PROVISIONER_TOKEN_URL"),
		ClientID: getenv("SNAPLINK_AUDIT_PROVISIONER_CLIENT_ID"), ClientSecret: secret,
		Resource: getenv("SNAPLINK_AUDIT_PROVISIONER_RESOURCE"), Listen: envDefault(getenv, "SNAPLINK_AUDIT_PROVISIONER_LISTEN", defaultListen),
		PollInterval: poll, RequestTimeout: timeout, ShutdownTimeout: defaultShutdownTimeout,
		OneShot: oneShot, AllowInsecureLoopback: allowHTTP,
	}, nil
}

func (config *runtimeConfig) normalize() {
	config.ManifestFile = strings.TrimSpace(config.ManifestFile)
	config.BaseURL = strings.TrimSpace(config.BaseURL)
	config.TokenURL = strings.TrimSpace(config.TokenURL)
	config.ClientID = strings.TrimSpace(config.ClientID)
	config.Resource = strings.TrimSpace(config.Resource)
	config.Listen = strings.TrimSpace(config.Listen)
}

func (config runtimeConfig) validate() error {
	if config.ManifestFile == "" || config.BaseURL == "" || config.TokenURL == "" ||
		config.ClientID == "" || config.ClientSecret == "" || config.Resource == "" {
		return errors.New("manifest, endpoints, dedicated client credentials, and resource are required")
	}
	if strings.ContainsAny(config.ClientSecret, "\r\n") {
		return errors.New("client secret contains a line break")
	}
	if config.PollInterval < time.Second || config.RequestTimeout <= 0 ||
		config.RequestTimeout > maxRequestTimeout || config.ShutdownTimeout <= 0 {
		return errors.New("poll interval and timeouts are invalid")
	}
	if !config.OneShot && config.Listen == "" {
		return errors.New("listen address is required outside one-shot mode")
	}
	return nil
}

func provisionerSecret(getenv func(string) string) (string, error) {
	direct := getenv("SNAPLINK_AUDIT_PROVISIONER_CLIENT_SECRET")
	path := strings.TrimSpace(getenv("SNAPLINK_AUDIT_PROVISIONER_CLIENT_SECRET_FILE"))
	if direct != "" && path != "" {
		return "", errors.New("configure exactly one provisioner client secret source")
	}
	if path == "" {
		return direct, nil
	}
	return readSecretFile(path)
}

func readSecretFile(path string) (string, error) {
	file, opened, err := openSecretFile(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	body, err := readSecretBytes(file)
	if err != nil {
		return "", errors.New("provisioner client secret file is invalid")
	}
	if !secretFileUnchanged(path, file, opened) {
		return "", errors.New("provisioner client secret file changed")
	}
	return parseSecretBytes(body)
}

func openSecretFile(path string) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil || !safeSecretInfo(before) {
		return nil, nil, errors.New("provisioner client secret file is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, errors.New("provisioner client secret file cannot be opened")
	}
	after, err := file.Stat()
	if err != nil || !safeSecretInfo(after) || !os.SameFile(before, after) {
		file.Close()
		return nil, nil, errors.New("provisioner client secret file changed")
	}
	return file, after, nil
}

func readSecretBytes(file *os.File) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(file, maxSecretBytes+1))
	if err != nil || len(body) > maxSecretBytes {
		return nil, errors.New("invalid secret bytes")
	}
	return body, nil
}

func secretFileUnchanged(path string, file *os.File, opened os.FileInfo) bool {
	latest, fileErr := file.Stat()
	current, pathErr := os.Lstat(path)
	return fileErr == nil && pathErr == nil && safeSecretInfo(latest) && safeSecretInfo(current) &&
		latest.Size() == opened.Size() && os.SameFile(latest, current)
}

func parseSecretBytes(body []byte) (string, error) {
	secret := strings.TrimSuffix(string(body), "\n")
	if secret == "" || strings.ContainsAny(secret, "\r\n") {
		return "", errors.New("provisioner client secret file is invalid")
	}
	return secret, nil
}

func safeSecretInfo(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Size() <= maxSecretBytes && info.Mode().Perm()&0o022 == 0
}

func envDuration(getenv func(string) string, key string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration", key)
	}
	return parsed, nil
}

func envBool(getenv func(string) string, key string, fallback bool) (bool, error) {
	value := strings.TrimSpace(getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", key)
	}
	return parsed, nil
}

func envDefault(getenv func(string) string, key, fallback string) string {
	if value := getenv(key); value != "" {
		return value
	}
	return fallback
}
