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
// Currently wired safe fields:
//
//   - logging.level — swaps the *slog.LevelVar the caller's setLogLevel
//     callback controls. Nothing else in the request/response path reads
//     Logging.Level after boot, so this is a pure, side-effect-free change.
//
//   - security.rate_limit.* — rebuilds the whole ratelimit.Policy (via the
//     caller's setRateLimitPolicy hook, wired with SetRateLimitHook) and
//     swaps it into the already-installed ratelimit.PolicyStore
//     (interfaces/sso's Server.SetRateLimitPolicy). Unlike a plain
//     `ratelimit.Middleware(policy)` closure — which bakes in a Policy VALUE
//     once at Handler()-build time, so a later mutation has no effect on the
//     already-built handler chain — DynamicMiddleware reads its Policy from
//     the store fresh on every request, so a swap takes effect immediately.
//     Every leaf field under security.rate_limit is treated as ONE atomic
//     unit (matched by JSON-Pointer PREFIX, not exact path, and rebuilt as a
//     whole via the same BuildRateLimitPolicy the boot path uses) rather
//     than applied field-by-field, since limiters are re-created wholesale
//     on every rebuild anyway (in-memory bucket state resets — a safe,
//     side-effect-free change, not a correctness concern).
//
//   - feature_gates.{admin_api,web_spa,oidc,ciba,caep,federation,
//     self_service} — interfaces/sso now mounts every one of these seven
//     route groups UNCONDITIONALLY at Mount() time and wraps each
//     registered route in a request-time gate check
//     (shared/core.GatedRouter / GateHTTPHandler) instead of deciding
//     "mount or don't" once, at boot. Reload flips the matching live check
//     via each field's Set*GateHook — wired to the matching
//     Server.Set*GateEnabled method — with NO restart and no re-Mount. Some
//     of these have an asymmetry that surfaces as Ignored rather than
//     silently claimed Applied, when the underlying route group has
//     NOTHING mounted for the flag to affect (no SPA filesystem for
//     web_spa, no CAEP receiver for caep, none of protected-resource-
//     metadata/federation-entity/connection-store for federation) — a gate
//     can only suppress/reveal an ALREADY-mounted route, it can never
//     conjure one that was never constructed. admin_api/oidc/ciba/
//     self_service have no such gap: each always has at least one
//     unconditionally-mounted route in its group, so its Set*GateEnabled is
//     always effective.
//
// Still deliberately NOT wired, despite looking "safe" on paper (a toggle,
// no store/connection to re-provision):
//
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
	"strings"
	"sync"

	"github.com/goccy/go-yaml"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/platform/configaudit"
)

// safeReloadPaths lists the RFC 6901 JSON-Pointer paths (matching
// configaudit.Diff's Op.Path shape) this package treats as safe to apply
// to a live server, exactly (one leaf field, one apply case). See the
// package doc for what's deliberately excluded and why.
var safeReloadPaths = map[string]bool{
	"/logging/level":              true,
	"/feature_gates/admin_api":    true,
	"/feature_gates/web_spa":      true,
	"/feature_gates/oidc":         true,
	"/feature_gates/ciba":         true,
	"/feature_gates/caep":         true,
	"/feature_gates/federation":   true,
	"/feature_gates/self_service": true,
}

// safeReloadPrefixes lists JSON-Pointer path PREFIXES treated as safe when
// ANY field under them changes. Used for blocks — like security.rate_limit,
// which nests a nested Prefixes slice — rebuilt as a whole, atomic unit
// rather than matched leaf-by-leaf; see the package doc.
var safeReloadPrefixes = []string{
	"/security/rate_limit",
}

// hasSafePrefix reports whether path falls under one of safeReloadPrefixes.
func hasSafePrefix(path string) bool {
	for _, prefix := range safeReloadPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
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

	// setRateLimitPolicy applies a reloaded security.rate_limit.* block
	// live — typically a closure over
	// serverbuildplatform.BuildRateLimitPolicy + Server.SetRateLimitPolicy.
	// nil means no hook was wired, so a rate_limit change is reported as
	// Ignored instead of Applied. Set via SetRateLimitHook (not a New
	// constructor param, to avoid breaking existing callers' positional
	// argument lists).
	setRateLimitPolicy func(config.RateLimitConfig) error

	// setAdminAPIGate / setWebSPAGate apply a reloaded feature_gates.admin_api
	// / feature_gates.web_spa value live — typically
	// Server.SetAdminAPIGateEnabled / Server.SetWebSPAGateEnabled. Each
	// returns false when the change had nowhere to land (see those methods'
	// docs for when that happens), in which case Reload reports the change
	// as Ignored rather than Applied, mirroring setRateLimitPolicy's error
	// contract. nil (the default) means no hook was wired at all — also
	// Ignored. Set via SetAdminAPIGateHook / SetWebSPAGateHook.
	setAdminAPIGate func(enabled bool) bool
	setWebSPAGate   func(enabled bool) bool

	// setOIDCGate / setCIBAGate / setCAEPGate / setFederationGate /
	// setSelfServiceGate are feature_gates.{oidc,ciba,caep,federation,
	// self_service}'s analogs of setAdminAPIGate/setWebSPAGate above —
	// typically the matching Server.Set*GateEnabled method. Each returns
	// false when the change had nowhere to land (see those methods' docs),
	// reported as Ignored rather than Applied. nil (the default) means no
	// hook was wired — also Ignored. Set via the matching Set*GateHook,
	// defined in reload_feature_gates.go (which also holds the apply*
	// methods for all seven gates) to keep this file under the maintainability
	// line budget.
	setOIDCGate        func(enabled bool) bool
	setCIBAGate        func(enabled bool) bool
	setCAEPGate        func(enabled bool) bool
	setFederationGate  func(enabled bool) bool
	setSelfServiceGate func(enabled bool) bool
}

// SetRateLimitHook wires the callback Reload uses to apply a live
// security.rate_limit.* change — see the package doc for why this needed a
// dedicated wiring point instead of blanket "safe field" treatment (the
// rate-limit middleware bakes in a Policy VALUE at Handler()-build time).
// nil (the default) makes any detected rate_limit change appear in
// Result.Ignored instead of Result.Applied, mirroring setLogLevel's
// unwired-hook contract.
func (r *Reloader) SetRateLimitHook(fn func(config.RateLimitConfig) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setRateLimitPolicy = fn
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
	return r.applyOps(ops, newCfg), nil
}

// applyOps classifies every diff op as an exact safeReloadPaths match, a
// safeReloadPrefixes block match, or unsafe, and applies each accordingly.
// Split out of Reload to stay within the function-length budget. Called
// with r.mu held.
func (r *Reloader) applyOps(ops []configaudit.Op, newCfg *config.Config) Result {
	var res Result
	rateLimitChanged := false
	for _, op := range ops {
		switch {
		case safeReloadPaths[op.Path]:
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
		case hasSafePrefix(op.Path):
			// Deferred to after the loop: every leaf under security.rate_limit
			// rebuilds as ONE atomic Policy, not once per changed leaf field
			// (see applyRateLimit's doc).
			rateLimitChanged = true
		default:
			res.Ignored = append(res.Ignored, op.Path)
		}
	}
	if rateLimitChanged {
		if applied := r.applyRateLimit(newCfg); applied != "" {
			res.Applied = append(res.Applied, applied)
		} else {
			res.Ignored = append(res.Ignored, "/security/rate_limit")
		}
	}
	return res
}

// applySafe applies one recognized safe-reload path onto the tracked
// config and returns the human-readable "field: old -> new" description to
// record in Result.Applied. Called with r.mu held.
func (r *Reloader) applySafe(path string, newCfg *config.Config) []string {
	switch path {
	case "/logging/level":
		return r.applyLogLevel(newCfg)
	case "/feature_gates/admin_api":
		return stringOrNil(r.applyAdminAPIGate(newCfg))
	case "/feature_gates/web_spa":
		return stringOrNil(r.applyWebSPAGate(newCfg))
	case "/feature_gates/oidc":
		return stringOrNil(r.applyOIDCGate(newCfg))
	case "/feature_gates/ciba":
		return stringOrNil(r.applyCIBAGate(newCfg))
	case "/feature_gates/caep":
		return stringOrNil(r.applyCAEPGate(newCfg))
	case "/feature_gates/federation":
		return stringOrNil(r.applyFederationGate(newCfg))
	case "/feature_gates/self_service":
		return stringOrNil(r.applySelfServiceGate(newCfg))
	default:
		// A path was added to safeReloadPaths without a matching apply
		// case here — treat as not-yet-wired rather than silently no-op.
		return nil
	}
}

// stringOrNil adapts one of applyAdminAPIGate/applyWebSPAGate's "" == not
// applied contract (matching applyRateLimit's existing string-return
// convention) onto applySafe's []string contract (matching applyLogLevel's,
// which can in principle report more than one line).
func stringOrNil(applied string) []string {
	if applied == "" {
		return nil
	}
	return []string{applied}
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

// applyRateLimit rebuilds the whole security.rate_limit.* Policy from
// newCfg and hands it to the wired setRateLimitPolicy hook — reported as
// Applied only when the hook is actually wired, mirroring applyLogLevel's
// unwired-hook contract. Called ONCE per Reload regardless of how many
// individual rate_limit leaf fields changed (see Reload's doc): the hook
// (typically serverbuildplatform.BuildRateLimitPolicy +
// Server.SetRateLimitPolicy) always rebuilds the ENTIRE Policy from the
// whole RateLimitConfig, so applying per-leaf would just redo the same
// rebuild multiple times for one logical change.
func (r *Reloader) applyRateLimit(newCfg *config.Config) string {
	if r.setRateLimitPolicy == nil {
		return ""
	}
	if err := r.setRateLimitPolicy(newCfg.Security.RateLimit); err != nil {
		return ""
	}
	r.current.Security.RateLimit = newCfg.Security.RateLimit
	return "security.rate_limit: policy rebuilt"
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
