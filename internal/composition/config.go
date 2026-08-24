package composition

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
	DefaultListen       = "127.0.0.1:8080"
	DefaultUserID       = "user-alice"
	DefaultUsername     = "alice"
	DefaultUserPassword = "s3cret"
	DefaultClientID     = "demo-app"
	DefaultClientSecret = "demo-secret"
	DefaultRedirectURI  = "http://127.0.0.1:3000/callback"
	DefaultSecondID     = "demo-app-b"
	DefaultSecondSecret = "demo-secret-b"
	DefaultSecondURI    = "http://127.0.0.1:3001/callback"
)

// RuntimeConfig is the resolved runtime configuration for a small-edition
// server. It is edition-parameterized: default scopes and scope validation
// derive from Edition, so each composition root behaves exactly as its
// edition prescribes.
type RuntimeConfig struct {
	Listen  string
	Issuer  string
	Edition Edition
	User    UserSeed
	Client  ClientSeed
	Second  ClientSeed
}

type UserSeed struct {
	ID          string
	Username    string
	Password    string
	Email       string
	DisplayName string
}

type ClientSeed struct {
	ID          string
	Secret      string
	RedirectURI string
	Scopes      []string
}

// ParseRuntimeConfig resolves flags, environment, and edition defaults and
// validates the result.
func ParseRuntimeConfig(
	args []string,
	getenv func(string) string,
	stderr io.Writer,
	edition Edition,
) (RuntimeConfig, error) {
	cfg := DefaultsFromEnv(getenv, edition)
	fs := flag.NewFlagSet(ProgramName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	addFlags(fs, &cfg)
	fs.Usage = func() { writeUsage(stderr, fs) }
	if err := fs.Parse(args); err != nil {
		return RuntimeConfig{}, err
	}
	if fs.NArg() != 0 {
		return RuntimeConfig{}, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	cfg.Client.Scopes = splitScopes(strings.Join(cfg.Client.Scopes, ","))
	cfg.Second.Scopes = splitScopes(strings.Join(cfg.Second.Scopes, ","))
	if cfg.Issuer == "" {
		cfg.Issuer = issuerFromListen(cfg.Listen)
	}
	return cfg, cfg.validate()
}

// DefaultsFromEnv seeds the runtime configuration from SSO_MINIMAL_* variables
// and the edition's default scopes.
func DefaultsFromEnv(getenv func(string) string, edition Edition) RuntimeConfig {
	return RuntimeConfig{
		Listen:  envOr(getenv, "SSO_MINIMAL_LISTEN", DefaultListen),
		Issuer:  getenv("SSO_MINIMAL_ISSUER"),
		Edition: edition,
		User: UserSeed{
			ID:          envOr(getenv, "SSO_MINIMAL_USER_ID", DefaultUserID),
			Username:    envOr(getenv, "SSO_MINIMAL_USERNAME", DefaultUsername),
			Password:    envOr(getenv, "SSO_MINIMAL_USER_PASSWORD", DefaultUserPassword),
			Email:       getenv("SSO_MINIMAL_USER_EMAIL"),
			DisplayName: getenv("SSO_MINIMAL_USER_DISPLAY_NAME"),
		},
		Client: ClientSeed{
			ID:          envOr(getenv, "SSO_MINIMAL_CLIENT_ID", DefaultClientID),
			Secret:      envOr(getenv, "SSO_MINIMAL_CLIENT_SECRET", DefaultClientSecret),
			RedirectURI: envOr(getenv, "SSO_MINIMAL_REDIRECT_URI", DefaultRedirectURI),
			Scopes:      splitScopes(envOr(getenv, "SSO_MINIMAL_SCOPES", edition.DefaultScopes)),
		},
		Second: ClientSeed{
			ID:          envOr(getenv, "SSO_MINIMAL_SECOND_CLIENT_ID", DefaultSecondID),
			Secret:      envOr(getenv, "SSO_MINIMAL_SECOND_CLIENT_SECRET", DefaultSecondSecret),
			RedirectURI: envOr(getenv, "SSO_MINIMAL_SECOND_REDIRECT_URI", DefaultSecondURI),
			Scopes:      splitScopes(envOr(getenv, "SSO_MINIMAL_SECOND_SCOPES", edition.DefaultScopes)),
		},
	}
}

func addFlags(fs *flag.FlagSet, cfg *RuntimeConfig) {
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

func (cfg RuntimeConfig) validate() error {
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
	if err := validateClientSeed(cfg.Client, "primary", cfg.Edition); err != nil {
		return err
	}
	if err := validateClientSeed(cfg.Second, "second", cfg.Edition); err != nil {
		return err
	}
	if cfg.Client.ID == cfg.Second.ID {
		return errors.New("seed client IDs must be distinct")
	}
	return nil
}

func validateClientSeed(client ClientSeed, label string, edition Edition) error {
	if client.ID == "" || client.Secret == "" {
		return fmt.Errorf("%s client ID and secret are required", label)
	}
	if !validHTTPURL(client.RedirectURI) {
		return fmt.Errorf("%s redirect URI must be an absolute http or https URL", label)
	}
	if edition.OIDC && !contains(client.Scopes, "openid") {
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
