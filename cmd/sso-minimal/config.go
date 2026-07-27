package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
)

const (
	defaultListen       = "127.0.0.1:8080"
	defaultUserID       = "user-alice"
	defaultUsername     = "alice"
	defaultUserPassword = "s3cret"
	defaultClientID     = "demo-app"
	defaultClientSecret = "demo-secret"
	defaultRedirectURI  = "http://127.0.0.1:3000/callback"
	defaultSecondID     = "demo-app-b"
	defaultSecondSecret = "demo-secret-b"
	defaultSecondURI    = "http://127.0.0.1:3001/callback"
	defaultScopes       = "openid,profile,email"
)

type runtimeConfig struct {
	Listen string
	Issuer string
	User   userSeed
	Client clientSeed
	Second clientSeed
}

type userSeed struct {
	ID          string
	Username    string
	Password    string
	Email       string
	DisplayName string
}

type clientSeed struct {
	ID          string
	Secret      string
	RedirectURI string
	Scopes      []string
}

func parseRuntimeConfig(args []string, getenv func(string) string, stderr io.Writer) (runtimeConfig, error) {
	cfg := defaultsFromEnv(getenv)
	fs := flag.NewFlagSet(programName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	addFlags(fs, &cfg)
	fs.Usage = func() { writeUsage(stderr, fs) }
	if err := fs.Parse(args); err != nil {
		return runtimeConfig{}, err
	}
	if fs.NArg() != 0 {
		return runtimeConfig{}, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	cfg.Client.Scopes = splitScopes(strings.Join(cfg.Client.Scopes, ","))
	cfg.Second.Scopes = splitScopes(strings.Join(cfg.Second.Scopes, ","))
	if cfg.Issuer == "" {
		cfg.Issuer = issuerFromListen(cfg.Listen)
	}
	return cfg, cfg.validate()
}

func defaultsFromEnv(getenv func(string) string) runtimeConfig {
	return runtimeConfig{
		Listen: envOr(getenv, "SSO_MINIMAL_LISTEN", defaultListen),
		Issuer: getenv("SSO_MINIMAL_ISSUER"),
		User: userSeed{
			ID:          envOr(getenv, "SSO_MINIMAL_USER_ID", defaultUserID),
			Username:    envOr(getenv, "SSO_MINIMAL_USERNAME", defaultUsername),
			Password:    envOr(getenv, "SSO_MINIMAL_USER_PASSWORD", defaultUserPassword),
			Email:       getenv("SSO_MINIMAL_USER_EMAIL"),
			DisplayName: getenv("SSO_MINIMAL_USER_DISPLAY_NAME"),
		},
		Client: clientSeed{
			ID:          envOr(getenv, "SSO_MINIMAL_CLIENT_ID", defaultClientID),
			Secret:      envOr(getenv, "SSO_MINIMAL_CLIENT_SECRET", defaultClientSecret),
			RedirectURI: envOr(getenv, "SSO_MINIMAL_REDIRECT_URI", defaultRedirectURI),
			Scopes:      splitScopes(envOr(getenv, "SSO_MINIMAL_SCOPES", defaultScopes)),
		},
		Second: clientSeed{
			ID:          envOr(getenv, "SSO_MINIMAL_SECOND_CLIENT_ID", defaultSecondID),
			Secret:      envOr(getenv, "SSO_MINIMAL_SECOND_CLIENT_SECRET", defaultSecondSecret),
			RedirectURI: envOr(getenv, "SSO_MINIMAL_SECOND_REDIRECT_URI", defaultSecondURI),
			Scopes:      splitScopes(envOr(getenv, "SSO_MINIMAL_SECOND_SCOPES", defaultScopes)),
		},
	}
}

func addFlags(fs *flag.FlagSet, cfg *runtimeConfig) {
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "HTTP listen address")
	fs.StringVar(&cfg.Issuer, "issuer", cfg.Issuer, "public issuer URL")
	fs.StringVar(&cfg.User.ID, "user-id", cfg.User.ID, "seed user ID")
	fs.StringVar(&cfg.User.Username, "username", cfg.User.Username, "seed login username")
	fs.StringVar(&cfg.User.Password, "user-password", cfg.User.Password, "seed login password")
	fs.StringVar(&cfg.User.Email, "user-email", cfg.User.Email, "seed user email")
	fs.StringVar(&cfg.User.DisplayName, "user-display-name", cfg.User.DisplayName, "seed display name")
	fs.StringVar(&cfg.Client.ID, "client-id", cfg.Client.ID, "seed OIDC client ID")
	fs.StringVar(&cfg.Client.Secret, "client-secret", cfg.Client.Secret, "seed OIDC client secret")
	fs.StringVar(&cfg.Client.RedirectURI, "redirect-uri", cfg.Client.RedirectURI, "seed redirect URI")
	fs.StringVar(&cfg.Second.ID, "second-client-id", cfg.Second.ID, "second seed client ID")
	fs.StringVar(&cfg.Second.Secret, "second-client-secret", cfg.Second.Secret, "second seed client secret")
	fs.StringVar(&cfg.Second.RedirectURI, "second-redirect-uri", cfg.Second.RedirectURI, "second seed redirect URI")
	scopes := strings.Join(cfg.Client.Scopes, ",")
	fs.Func("scopes", "comma- or space-separated seed scopes", func(value string) error {
		scopes = value
		cfg.Client.Scopes = splitScopes(scopes)
		return nil
	})
	secondScopes := strings.Join(cfg.Second.Scopes, ",")
	fs.Func("second-scopes", "second seed client scopes", func(value string) error {
		secondScopes = value
		cfg.Second.Scopes = splitScopes(secondScopes)
		return nil
	})
}

func (cfg runtimeConfig) validate() error {
	if cfg.Listen == "" || cfg.Issuer == "" {
		return errors.New("listen and issuer are required")
	}
	if !isLoopbackListen(cfg.Listen) {
		return errors.New("prototype listen address must be loopback")
	}
	if !validHTTPURL(cfg.Issuer) {
		return errors.New("issuer must be an absolute http or https URL")
	}
	if cfg.User.ID == "" || cfg.User.Username == "" || cfg.User.Password == "" {
		return errors.New("user-id, username, and user-password are required")
	}
	if err := validateClientSeed(cfg.Client, "primary"); err != nil {
		return err
	}
	if err := validateClientSeed(cfg.Second, "second"); err != nil {
		return err
	}
	if cfg.Client.ID == cfg.Second.ID {
		return errors.New("seed client IDs must be distinct")
	}
	return nil
}

func validateClientSeed(client clientSeed, label string) error {
	if client.ID == "" || client.Secret == "" {
		return fmt.Errorf("%s client ID and secret are required", label)
	}
	if !validHTTPURL(client.RedirectURI) {
		return fmt.Errorf("%s redirect URI must be an absolute http or https URL", label)
	}
	if !contains(client.Scopes, "openid") {
		return fmt.Errorf("%s scopes must include openid", label)
	}
	return nil
}

func isLoopbackListen(listen string) bool {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func issuerFromListen(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return ""
	}
	return "http://" + net.JoinHostPort(host, port)
}

func validHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https")
}

func splitScopes(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
}

func envOr(getenv func(string) string, key, fallback string) string {
	if value := getenv(key); value != "" {
		return value
	}
	return fallback
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
