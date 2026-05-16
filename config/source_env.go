package config

import (
	"context"
	"os"
	"strings"

	"github.com/snaplink/sso/config/internal/parse"
)

// Default conventions used by NewEnvSource. ENV vars matching
// "<Prefix><UPPER_SNAKE>" map into the config tree using <Separator>
// as the nesting boundary.
//
// Example with the defaults:
//
//	SSO_SERVER__LISTEN=:9090            → server.listen = ":9090"
//	SSO_SNAPSHOT__STORAGE__BACKEND=file → snapshot.storage.backend = "file"
//	SSO_BOOTSTRAP__DISABLED=true        → bootstrap.disabled = true (parsed as bool)
//	SSO_LOGGING__LEVEL=debug            → logging.level = "debug"
//
// Keys are lowercased after the prefix is stripped — this matches
// the yaml field tags throughout the codebase (all snake_case lower).
const (
	DefaultEnvPrefix    = "SSO_"
	DefaultEnvSeparator = "__"
)

// EnvSource maps process environment variables into the config tree.
//
// Value handling: every ENV value is a string at the OS level, but
// operators expect "true" → bool and "5s" → string-as-duration to
// just work. We run each value through yaml.Unmarshal — that gives
// us native bool/int/float for the YAML-typed literals, and falls
// back to plain string for everything else. The downstream Loader
// then re-marshals + unmarshals into the typed *Config, which is
// where time.Duration parsing (and friends) happens.
//
// Slices through ENV are supported via YAML-list literal syntax:
//
//	SSO_CLIENTS='[{id: app-a}, {id: app-b}]'
//
// This is intentionally awkward — listy config belongs in the file,
// ENV is for scalar overrides.
type EnvSource struct {
	Prefix    string
	Separator string
	// Environ supplies the env var pairs ("KEY=VAL"). Defaults to
	// os.Environ when nil; injectable for tests.
	Environ func() []string
}

// NewEnvSource builds an EnvSource with the default convention
// ("SSO_" prefix, "__" separator).
func NewEnvSource() *EnvSource {
	return &EnvSource{Prefix: DefaultEnvPrefix, Separator: DefaultEnvSeparator}
}

// Name returns "env".
func (s *EnvSource) Name() string {
	return "env"
}

// Load scans the process environment, picks up vars matching the
// prefix, and folds them into a nested map.
func (s *EnvSource) Load(_ context.Context) (map[string]any, error) {
	prefix := s.Prefix
	if prefix == "" {
		prefix = DefaultEnvPrefix
	}
	sep := s.Separator
	if sep == "" {
		sep = DefaultEnvSeparator
	}
	env := s.Environ
	if env == nil {
		env = os.Environ
	}
	out := map[string]any{}
	for _, pair := range env() {
		k, v, ok := strings.Cut(pair, "=")
		if !ok || !strings.HasPrefix(k, prefix) {
			continue
		}
		path := strings.Split(strings.ToLower(strings.TrimPrefix(k, prefix)), strings.ToLower(sep))
		if len(path) == 0 || path[0] == "" {
			continue
		}
		parse.SetPath(out, path, parse.Value(v))
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
