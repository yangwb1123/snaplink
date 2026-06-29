package config

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/goccy/go-yaml"
)

// Source is one contributor to the merged configuration document.
// Sources return their data as nested map[string]any, matching the
// YAML document tree (keys = YAML field names, leaves = scalars / lists).
//
// Returning (nil, nil) is fine — a source that has nothing to say
// shouldn't pretend it does. Returning a non-empty map adds it to the
// merge; later sources in the Loader chain override earlier ones at
// matching key paths.
//
// Implementations are expected to be cheap to call (no network on the
// hot path) and goroutine-safe. The Loader itself only calls Load
// once per construction, so caching inside Source is optional.
type Source interface {
	// Name identifies the source in error messages + debug logs.
	// Should be human-readable and stable ("file:/etc/sso.yaml", "env",
	// "flag", "etcd:/sso/config").
	Name() string

	// Load returns the source's contribution. Errors are wrapped by
	// the Loader with the source Name(), so implementations don't
	// need to prefix their own.
	Load(ctx context.Context) (map[string]any, error)
}

// Loader composes a prioritized chain of Sources into a fully-resolved
// *Config. Sources are merged in declaration order: the FIRST source
// is the lowest priority, the LAST source overrides everything else.
// This matches the natural "defaults → file → env → flag" reading
// order operators expect.
//
// Merge semantics:
//   - Scalars (string/number/bool): last source wins.
//   - Maps: deep-merged key by key.
//   - Slices: last source REPLACES the previous slice entirely (no
//     append). This avoids the "I added one client and now the seed
//     list is duplicated" surprise common in Viper-style mergers.
//   - Type mismatch (scalar vs map at same path): last source wins,
//     the previous value is discarded. Loud-fail isn't an option
//     because the merge layer doesn't know the Config schema.
//
// The merged map is then YAML-marshaled and unmarshaled into *Config
// — this lets goccy/go-yaml's existing field-tag + custom-type
// (time.Duration, Pointer-to-struct, etc.) handling do the heavy
// lifting instead of reinventing reflection here.
type Loader struct {
	sources []Source
}

// NewLoader builds a Loader from the given sources. Order matters:
// sources[0] is lowest priority, sources[len-1] is highest.
func NewLoader(sources ...Source) *Loader {
	return &Loader{sources: sources}
}

// Sources returns the Loader's source chain in priority order
// (lowest → highest). Exposed for diagnostics / tests; treat the
// slice as read-only.
func (l *Loader) Sources() []Source {
	return l.sources
}

// Load walks the source chain, deep-merges each contribution onto
// the accumulator, then materializes the result into *Config with
// defaults applied + validated. The first source error short-circuits
// the load.
//
// Strict parsing: the merged YAML is first decoded with
// DisallowUnknownField enabled. If unknown keys are found, a WARNING
// is logged listing them, and the config is re-decoded without the
// restriction — existing configs continue to work, but operators get
// actionable feedback about misspellings or stale keys.
func (l *Loader) Load(ctx context.Context) (*Config, error) {
	merged := map[string]any{}
	for _, s := range l.sources {
		m, err := s.Load(ctx)
		if err != nil {
			return nil, fmt.Errorf("config: source %s: %w", s.Name(), err)
		}
		if m != nil {
			deepMerge(merged, m)
		}
	}
	raw, err := yaml.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("config: marshal merged: %w", err)
	}

	c := &Config{}

	// Strict pass — reject unknown fields so operators catch typos.
	if err := yaml.UnmarshalWithOptions(raw, c, yaml.DisallowUnknownField()); err != nil {
		unknownKeys := extractUnknownFields(err)

		// Re-decode without strict mode so the config still works.
		c = &Config{}
		if err2 := yaml.Unmarshal(raw, c); err2 != nil {
			return nil, fmt.Errorf("config: unmarshal merged: %w", err2)
		}

		if len(unknownKeys) > 0 {
			slog.Warn("config: unknown keys detected in YAML config — they are ignored and will become errors in a future version",
				"unknown_keys", unknownKeys,
				"hint", "check the YAML config file(s) for typos or keys that no longer exist",
			)
		}
	}

	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// extractUnknownFields parses goccy/go-yaml's "unknown field" error
// messages and returns the field names. The error format is:
//
//	[line:col] unknown field "field_name"
//
// Matching is best-effort — if the format changes, the function
// returns nil and the caller simply won't log a hint (the strict
// decode already failed, so it falls through to lenient mode).
func extractUnknownFields(err error) []string {
	if err == nil {
		return nil
	}
	re := regexp.MustCompile(`unknown field "([^"]+)"`)
	matches := re.FindAllStringSubmatch(err.Error(), -1)
	if len(matches) == 0 {
		return nil
	}
	fields := make([]string, 0, len(matches))
	for _, m := range matches {
		fields = append(fields, m[1])
	}
	return fields
}

// deepMerge writes src into dst, recursively merging nested maps and
// overwriting on every other type (including slice-vs-slice — see
// Loader doc for the rationale).
func deepMerge(dst, src map[string]any) {
	for k, v := range src {
		if sm, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				deepMerge(dm, sm)
				continue
			}
		}
		dst[k] = v
	}
}
