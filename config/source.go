package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/yangwb1123/snaplink/config/schema"
	"github.com/yangwb1123/snaplink/config/sources"
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
//
// Secret resolution:
// Before marshaling, the Loader walks the merged map and resolves every
// leaf string value matching "secret://<provider>/<path>" via the
// registered SecretResolvers. Register resolvers with WithSecretResolvers.
type Loader struct {
	sources   []Source
	resolvers map[string]SecretResolver
}

// NewLoader builds a Loader from the given sources. Order matters:
// sources[0] is lowest priority, sources[len-1] is highest.
func NewLoader(sources ...Source) *Loader {
	return &Loader{sources: sources, resolvers: map[string]SecretResolver{}}
}

// WithSecretResolvers registers one or more SecretResolvers on the Loader.
// Returns the receiver for fluent chaining.
//
// Example:
//
//	loader := config.NewLoader(fileSrc, envSrc, flagSrc).
//	    WithSecretResolvers(awsResolver, gcpResolver)
//
// Each resolver is indexed by its Provider() name. If two resolvers have
// the same provider name, the last one wins.
func (l *Loader) WithSecretResolvers(resolvers ...SecretResolver) *Loader {
	for _, r := range resolvers {
		l.resolvers[r.Provider()] = r
	}
	return l
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

	// Resolve secret:// URLs in the merged config before marshaling.
	// This lets operators store secret references in YAML, env, or flags
	// and have them resolved at load time by the registered resolvers.
	if len(l.resolvers) > 0 {
		if err := ResolveSecretReferences(ctx, merged, l.resolvers); err != nil {
			return nil, err
		}
	}

	checkSchema(merged)

	raw, err := marshalMergedBounded(merged)
	if err != nil {
		return nil, err
	}

	c, err := decodeStrictWithFallback(raw)
	if err != nil {
		return nil, err
	}

	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// checkSchema runs an ADDITIONAL validation pass alongside (not replacing)
// Loader.Load's strict/lenient YAML decode. Operates on `merged` (the
// pre-decode map[string]any) so it sees unknown keys at any nesting depth
// with a full path — an improvement over decodeStrictWithFallback's
// single-level, regex-extracted unknown_keys warning. Deliberately
// warn-only, same as that existing check: see schema.Validate's doc for why
// a generated schema must not become a hard load-time gate. Callers wanting
// a hard gate (e.g. a CI pre-deploy check) use `sso-ctl config
// validate-schema`, which treats the same violations as fatal.
func checkSchema(merged map[string]any) {
	if violations := schema.Validate(Schema(), merged); len(violations) > 0 {
		logSchemaViolations(violations)
	}
}

// maxConfigMarshalDuration bounds how long the merged-config YAML re-encode
// (marshalMergedBounded) may run.
//
// A config source built from nested YAML anchors/aliases (e.g.
// `b: &b [*a,*a,...,*a]` repeated across several levels) decodes into a DAG
// of shared slice/map pointers — Unmarshal is cheap because aliased
// branches aren't copied — but yaml.Marshal must flatten every alias into
// literal text, so a handful of nested anchors can amplify into a
// multi-second (or much worse) re-encode: a billion-laughs-style DoS
// reachable from any config file or SIGHUP-reloaded source that contains
// anchors.
//
// An earlier attempt fixed this with goccy/go-yaml's WithSmartAnchor
// (re-detect the shared pointers at encode time and re-emit them as
// anchors instead of expanding). That had to be reverted: its
// pointer-identity sharing detection produces FALSE POSITIVES on ordinary
// zero-value fields — Go's runtime returns the same address for unrelated
// empty-slice allocations — which corrupted legitimate configs with
// spurious, wrong anchors, reproduced against this repo's own shipped
// cmd/sso-server/config.yaml (zero real anchors, yet failed to re-parse
// after the "fix").
//
// A bounded timeout instead turns an unbounded hang into a clear, fast
// failure without changing yaml.Marshal's behavior at all for the happy
// path (the overwhelming majority of loads: no anchors, or a handful that
// never amplify). 3s is generous for any real config (kilobytes of YAML)
// while comfortably catching a multi-second amplification bomb well before
// it would otherwise complete.
const maxConfigMarshalDuration = 3 * time.Second

// marshalMergedBounded runs yaml.Marshal(merged) with the timeout described
// above. On timeout the marshal goroutine is abandoned (not killed — Go has
// no way to preempt it) and continues running to completion in the
// background; it is never a permanent leak, since yaml.Marshal always
// terminates eventually (the amplification is exponential slowdown, not an
// infinite loop), just later than this function is willing to wait.
func marshalMergedBounded(merged map[string]any) ([]byte, error) {
	type result struct {
		raw []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		raw, err := yaml.Marshal(merged)
		done <- result{raw, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return nil, fmt.Errorf("config: marshal merged: %w", r.err)
		}
		return r.raw, nil
	case <-time.After(maxConfigMarshalDuration):
		return nil, fmt.Errorf("config: marshal merged: exceeded %s — possible YAML anchor/alias amplification in a config source: %w",
			maxConfigMarshalDuration, errConfigMarshalTimeout)
	}
}

// errConfigMarshalTimeout is the sentinel wrapped by marshalMergedBounded's
// timeout error, so callers can errors.Is-match it independent of the
// formatted message.
var errConfigMarshalTimeout = errors.New("config: marshal timeout")

// configSchema is generated once at package init — Config's shape is
// static (reflection only inspects the TYPE, never a value), so there is
// nothing to recompute per Load call.
var configSchema = schema.Generate(Config{})

// Schema returns the reflection-generated JSON Schema document describing
// Config's shape (field names, types, and a best-effort required set — see
// the schema package's doc for the heuristic's limits). Exposed so
// `sso-ctl config schema` can emit it and `sso-ctl config validate-schema`
// can run the same check as Loader.Load's warn-only pass as a hard CI gate.
func Schema() *schema.Document {
	return configSchema
}

// logSchemaViolations logs every schema.Violation Loader.Load's schema
// check found, at WARN — see Load's doc for why this stays advisory rather
// than failing the load.
func logSchemaViolations(violations []schema.Violation) {
	details := make([]string, len(violations))
	for i, v := range violations {
		details[i] = v.String()
	}
	slog.Warn("config: schema violations detected — see docs/config-reference.md's JSON Schema section",
		"violations", details,
		"hint", "run `sso-ctl config validate-schema --file <path>` for a strict, path+type-annotated report",
	)
}

// decodeStrictWithFallback decodes the merged YAML with
// DisallowUnknownField first so operators catch typos; on unknown keys it
// warns and re-decodes without the restriction so existing configs continue
// to work.
func decodeStrictWithFallback(raw []byte) (*Config, error) {
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

// The pluggable config Source backends (env, file, flag) live in the config/sources
// leaf package so this directory stays within the per-directory file-count budget —
// mirroring the existing config/etcd backend. These aliases preserve the historical
// config.{EnvSource,FileSource,FlagSource} / config.New*Source import surface for the
// server wiring (cmd/sso-server) and the internal Load() path; each backend satisfies
// the Source interface structurally, so no interface guard or import-back is needed.

type (
	EnvSource  = sources.EnvSource
	FileSource = sources.FileSource
	FlagSource = sources.FlagSource
)

const (
	DefaultEnvPrefix    = sources.DefaultEnvPrefix
	DefaultEnvSeparator = sources.DefaultEnvSeparator
)

var (
	NewEnvSource  = sources.NewEnvSource
	NewFileSource = sources.NewFileSource
	NewFlagSource = sources.NewFlagSource
)

// SecretResolver aliases are intentionally NOT re-exported here: the
// config.SecretResolver interface lives in package config (secrets.go),
// and the implementations (StaticSecretResolver, ExecSecretResolver) live
// in config/sources. Downstream code (cmd/sso-server) imports them directly
// from config/sources and registers them via Loader.WithSecretResolvers.
//
// Example wiring:
//
//	import (
//	    "github.com/yangwb1123/snaplink/config"
//	    "github.com/yangwb1123/snaplink/config/sources"
//	)
//
//	resolver := sources.NewExecSecretResolver("aws", myResolveFunc)
//	cfg, err := config.NewLoader(sources...).
//	    WithSecretResolvers(resolver).
//	    Load(ctx)
