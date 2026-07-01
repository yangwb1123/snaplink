package sources

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// secretURLPrefix is the URL scheme prefix for secret references in config
// values. Matches config.SecretResolver's convention.
const secretURLPrefix = "secret://"

// SecretResolver defines the interface for resolving secret:// URLs at
// config load time. This is the same contract as config.SecretResolver
// but defined here so implementations in this package don't import the
// parent config package (no circular dependency).
//
// Implementations MUST be safe for concurrent use.
type SecretResolver interface {
	Provider() string
	Resolve(ctx context.Context, path string) (string, error)
}

// StaticSecretResolver is a SecretResolver backed by a static map of
// path → value pairs. Useful for testing, local development, and
// environments where secrets are injected as environment variables
// before config load (the operator pre-populates the map from env).
type StaticSecretResolver struct {
	provider string
	data     map[string]string
	mu       sync.RWMutex
}

// NewStaticSecretResolver builds a resolver that returns values from a
// static map. The provider name should match the URL scheme segment
// (e.g., "static" for "secret://static/...").
func NewStaticSecretResolver(provider string) *StaticSecretResolver {
	return &StaticSecretResolver{
		provider: provider,
		data:     make(map[string]string),
	}
}

// Add registers a path→value mapping. This is safe to call before
// or after Load() — values are additive (last write wins).
func (s *StaticSecretResolver) Add(path, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[path] = value
}

// Provider returns the provider name.
func (s *StaticSecretResolver) Provider() string { return s.provider }

// Resolve returns the value for the given path.
func (s *StaticSecretResolver) Resolve(_ context.Context, path string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[path]
	if !ok {
		return "", fmt.Errorf("static secret %q: not found", path)
	}
	return v, nil
}

// ExecSecretResolver resolves secret:// URLs by executing an external
// command. The command receives the path as its argument and must print
// the secret value to stdout.
//
// Example for AWS Secrets Manager:
//
//	resolver := NewExecSecretResolver("aws",
//	    func(ctx context.Context, path string) (string, error) {
//	        cmd := exec.CommandContext(ctx, "aws", "secretsmanager",
//	            "get-secret-value", "--secret-id", path,
//	            "--query", "SecretString", "--output", "text")
//	        out, err := cmd.Output()
//	        if err != nil { return "", err }
//	        return strings.TrimSpace(string(out)), nil
//	    })
type ExecSecretResolver struct {
	provider string
	resolve  func(context.Context, string) (string, error)
	cache    map[string]string
	mu       sync.RWMutex
}

// NewExecSecretResolver builds a resolver that calls fn for each
// resolution. Results are cached so repeated lookups of the same path
// don't re-invoke the command.
func NewExecSecretResolver(provider string, fn func(context.Context, string) (string, error)) *ExecSecretResolver {
	return &ExecSecretResolver{
		provider: provider,
		resolve:  fn,
		cache:    make(map[string]string),
	}
}

// Provider returns the provider name.
func (e *ExecSecretResolver) Provider() string { return e.provider }

// Resolve returns the cached value or calls the resolve function.
func (e *ExecSecretResolver) Resolve(ctx context.Context, path string) (string, error) {
	e.mu.RLock()
	v, ok := e.cache[path]
	e.mu.RUnlock()
	if ok {
		return v, nil
	}

	val, err := e.resolve(ctx, path)
	if err != nil {
		return "", err
	}
	val = strings.TrimSpace(val)

	e.mu.Lock()
	e.cache[path] = val
	e.mu.Unlock()
	return val, nil
}
