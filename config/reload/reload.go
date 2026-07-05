// Package reload implements SIGHUP-style hot reload for config.Config: a
// Reloader re-reads the config from its original Source chain and applies
// ONLY the fields that are safe to change on a live server, leaving every
// other field untouched.
//
// Why an allowlist, not a denylist: config.Config has ~90 top-level fields
// today and will grow. Reload defaults to "requires a restart" for anything
// it doesn't explicitly recognize (safeReloadPaths below) — a newly added
// Config field is automatically NOT hot-reloaded until someone deliberately
// reviews it and adds it to the allowlist, rather than silently starting to
// (maybe incorrectly) apply live the moment it's added to the struct.
//
// Currently wired safe field:
//
//   - logging.level — swaps the *slog.LevelVar the caller's setLogLevel
//     callback controls. Nothing else in the request/response path reads
//     Logging.Level after boot, so this is a pure, side-effect-free change.
//
// Deliberately NOT wired yet, despite looking "safe" on paper (numeric
// knobs, feature toggles — no store/connection to re-provision):
//
//   - security.rate_limit.* — interfaces/sso/server_routes.go builds the
//     rate-limit middleware ONCE at Handler()-construction time:
//     `ratelimit.Middleware(*s.rateLimitPolicy)(inner)`. Middleware(p Policy)
//     takes p BY VALUE, so mutating the Policy (or its Limiters) after that
//     call has already run has no effect on the already-built handler chain.
//     Making this genuinely live needs a mutable-limiter registry threaded
//     through cmd/sso-server's wiring — a separate, focused change.
//   - feature_gates.* — interfaces/sso decides which route groups Mount()
//     registers ONCE, at server-construction time. Toggling a gate after
//     boot cannot add or remove already-registered/unregistered mux routes
//     without a full re-Mount, which this SDK does not support at runtime.
//   - storage backends, listen addresses, TLS material, cluster/etcd
//     endpoints, DSNs — all require closing and re-opening a connection or
//     listener; applying them in place risks leaking the old
//     connection/listener or serving with an inconsistent half-applied
//     state. These always require a restart.
//
// A failed Reload (e.g. the config file was hand-edited into an invalid
// state) leaves the Reloader's tracked state untouched and returns the
// error — callers should log it and keep running on the last-good
// configuration rather than treat it as fatal (a bad edit should never be
// able to crash a running server via SIGHUP).
package reload

import (
	"context"
	"fmt"
	"sync"

	"github.com/goccy/go-yaml"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/platform/configaudit"
)

// safeReloadPaths lists the RFC 6901 JSON-Pointer paths (matching
// configaudit.Diff's Op.Path shape) this package treats as safe to apply
// to a live server. See the package doc for what's deliberately excluded
// and why.
var safeReloadPaths = map[string]bool{
	"/logging/level": true,
}

// Result reports what one Reload call did.
type Result struct {
	// Applied lists human-readable "field: old -> new" entries for every
	// change that was actually applied live.
	Applied []string
	// Ignored lists the JSON-Pointer path of every OTHER change detected
	// between the previous and reloaded config — present but left
	// untouched because applying it live isn't safe (see package doc).
	// Callers should surface this so operators know a restart is needed
	// to pick up these changes.
	Ignored []string
}

// Changed reports whether Reload found any difference at all (applied or
// merely detected-and-ignored).
func (r Result) Changed() bool {
	return len(r.Applied) > 0 || len(r.Ignored) > 0
}

// Reloader holds the config a running process currently considers
// authoritative and knows how to re-read it from the original source
// chain. Safe for concurrent use.
type Reloader struct {
	mu      sync.Mutex
	current *config.Config
	source  func(context.Context) (*config.Config, error)

	// setLogLevel applies a reloaded logging.level live (e.g.
	// (*slog.LevelVar).Set via a small adapter in the caller). nil means no
	// hook was wired, so a logging.level change is reported as Ignored
	// instead of Applied — Reload never claims to have applied a change
	// that had nowhere to land.
	setLogLevel func(level string)
}

// New builds a Reloader seeded with the config the process booted with.
// source re-reads config from wherever the process originally loaded it —
// typically a closure over the same Source chain passed to
// config.LoadFromSources at startup, e.g.:
//
//	reloader := reload.New(cfg, func(ctx context.Context) (*config.Config, error) {
//	    return config.LoadFromSources(ctx, sources...)
//	}, myLogger.SetLevel)
//
// setLogLevel may be nil (logging.level changes are then reported as
// Ignored rather than Applied — see Reloader.setLogLevel's doc).
func New(initial *config.Config, source func(context.Context) (*config.Config, error), setLogLevel func(string)) *Reloader {
	if initial == nil {
		initial = &config.Config{}
	}
	return &Reloader{current: initial, source: source, setLogLevel: setLogLevel}
}

// Current returns a copy of the config the Reloader currently considers
// authoritative (the original boot-time config with any Applied changes
// folded in). A copy, not the live pointer, so a caller inspecting it
// can't race a concurrent Reload.
func (r *Reloader) Current() *config.Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	cfgCopy := *r.current
	return &cfgCopy
}

// Reload re-reads the config via the source function, diffs it against the
// currently-tracked config (via platform/configaudit's existing JSON-Patch
// diff engine — the same one the running-vs-applied admin endpoint uses),
// applies whatever is in safeReloadPaths, and reports everything else as
// Ignored.
//
// A reload-source error (e.g. the file no longer parses) is returned
// as-is and does NOT touch the tracked state — see the package doc for why
// this must never crash a running server.
func (r *Reloader) Reload(ctx context.Context) (Result, error) {
	if r.source == nil {
		return Result{}, fmt.Errorf("config reload: no reload source configured")
	}
	newCfg, err := r.source(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("config reload: %w", err)
	}
	if newCfg == nil {
		return Result{}, fmt.Errorf("config reload: reload source returned a nil config")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	beforeMap, err := snapshotMap(r.current)
	if err != nil {
		return Result{}, fmt.Errorf("config reload: snapshot current config: %w", err)
	}
	afterMap, err := snapshotMap(newCfg)
	if err != nil {
		return Result{}, fmt.Errorf("config reload: snapshot reloaded config: %w", err)
	}

	// Diff over the RAW snapshots, redact the resulting patch VALUES
	// afterward — never the other order (see configaudit.RedactOps's doc):
	// redacting before diffing would make two different secrets diff to
	// "no change".
	ops := configaudit.RedactOps(configaudit.Diff(beforeMap, afterMap))

	var res Result
	for _, op := range ops {
		if !safeReloadPaths[op.Path] {
			res.Ignored = append(res.Ignored, op.Path)
			continue
		}
		applied := r.applySafe(op.Path, newCfg)
		if len(applied) == 0 {
			// Recognized as safe-shaped, but nothing actually applied it
			// (e.g. no setLogLevel hook was wired) — report it exactly
			// like any other restart-required change rather than silently
			// dropping it.
			res.Ignored = append(res.Ignored, op.Path)
			continue
		}
		res.Applied = append(res.Applied, applied...)
	}
	return res, nil
}

// applySafe applies one recognized safe-reload path onto the tracked
// config and returns the human-readable "field: old -> new" description to
// record in Result.Applied. Called with r.mu held.
func (r *Reloader) applySafe(path string, newCfg *config.Config) []string {
	switch path {
	case "/logging/level":
		return r.applyLogLevel(newCfg)
	default:
		// A path was added to safeReloadPaths without a matching apply
		// case here — treat as not-yet-wired rather than silently no-op.
		return nil
	}
}

// applyLogLevel is the single currently-wired safe-reload case. Reports the
// change as Applied only when a setLogLevel hook is actually wired — see
// the field's doc for why an unwired hook must not be claimed as applied.
func (r *Reloader) applyLogLevel(newCfg *config.Config) []string {
	old := r.current.Logging.Level
	newLevel := newCfg.Logging.Level
	if r.setLogLevel == nil {
		return nil
	}
	r.setLogLevel(newLevel)
	r.current.Logging.Level = newLevel
	return []string{fmt.Sprintf("logging.level: %q -> %q", old, newLevel)}
}

// snapshotMap renders cfg the same way
// cmd/sso-server/serverbuildplatform.EffectiveConfigSnapshot does (a
// yaml.Marshal/Unmarshal round trip into map[string]any) so its keys match
// the yaml tags configaudit.Diff's paths are built from.
func snapshotMap(cfg *config.Config) (map[string]any, error) {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}
