package config

import (
	"context"
	"fmt"
	"strings"
)

// secretURLPrefix is the URL scheme prefix for secret references in config
// values. Any leaf string value beginning with this prefix is resolved
// at load time by the registered SecretResolver.
//
// Format: secret://<provider>/<path>
//
// Examples:
//
//	secret://aws/postgres/prod/dsn       → AWS Secrets Manager
//	secret://gcp/sso-server/db-password  → GCP Secret Manager
//	secret://azure/KeyVaultName/secret   → Azure Key Vault
//
// Use Loader.WithSecretResolvers to register resolvers.
const secretURLPrefix = "secret://"

// SecretResolver resolves a "secret://<provider>/<path>" reference to its
// secret value at config load time. Implementations must be safe for
// concurrent use and should cache resolved values to avoid redundant API
// calls when the same secret key appears in multiple config paths.
//
// The provider is the first path segment after "secret://":
//
//	secret://aws/...     → provider = "aws"
//	secret://gcp/...     → provider = "gcp"
//	secret://azure/...   → provider = "azure"
//
// Resolve returns the plaintext secret value. Returning an error fails
// the entire config load.
type SecretResolver interface {
	// Provider returns the provider name this resolver handles
	// ("aws", "gcp", "azure", etc.).
	Provider() string

	// Resolve fetches the secret at the given path and returns its
	// plaintext value. Implementations should cache the result so
	// repeated calls for the same path return the same value without
	// a network round-trip.
	Resolve(ctx context.Context, path string) (string, error)
}

// ResolveSecretReferences walks the given config tree and replaces every
// leaf string value matching "secret://<provider>/<path>" with the resolved
// secret value. resolvers is a map keyed by provider name.
//
// This is called by Loader.Load after merging sources but before YAML
// unmarshal, so typed fields (bool, int, time.Duration) already have their
// final values — only string leaves are candidates for secret resolution.
func ResolveSecretReferences(ctx context.Context, m map[string]any, resolvers map[string]SecretResolver) error {
	if len(resolvers) == 0 {
		return nil
	}
	return resolveMap(ctx, m, resolvers)
}

func resolveMap(ctx context.Context, m map[string]any, resolvers map[string]SecretResolver) error {
	for k, v := range m {
		switch val := v.(type) {
		case string:
			resolved, err := resolveIfSecret(ctx, val, resolvers)
			if err != nil {
				return fmt.Errorf("config: resolve secret at %q: %w", k, err)
			}
			if resolved != nil {
				m[k] = *resolved
			}
		case map[string]any:
			if err := resolveMap(ctx, val, resolvers); err != nil {
				return fmt.Errorf("config: %s: %w", k, err)
			}
		}
	}
	return nil
}

func resolveIfSecret(ctx context.Context, s string, resolvers map[string]SecretResolver) (*string, error) {
	if !strings.HasPrefix(s, secretURLPrefix) {
		return nil, nil
	}

	rest := s[len(secretURLPrefix):]
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return nil, fmt.Errorf("malformed secret URL %q: expected secret://<provider>/<path>", s)
	}
	provider := rest[:slash]
	path := rest[slash+1:]
	if path == "" {
		return nil, fmt.Errorf("malformed secret URL %q: empty path", s)
	}

	resolver, ok := resolvers[provider]
	if !ok {
		return nil, fmt.Errorf("no secret resolver registered for provider %q (URL: %s)", provider, s)
	}

	val, err := resolver.Resolve(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", s, err)
	}
	return &val, nil
}
