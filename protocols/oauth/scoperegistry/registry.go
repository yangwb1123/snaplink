// Package scoperegistry implements the global scope registry (scope-matrix-v2,
// campaign B4-2): an opt-in, build-once allowlist of every scope the /token
// family may mint. An unwired (nil) registry is a structural no-op — the
// server stays byte-identical to a build without the feature.
//
// Jurisdiction is /token grants only. Direct mints outside /token (login-time
// authcode wiring, webauthn, kerberos) are not checked here; their scopes
// enter the registry's jurisdiction at the next /token exchange or refresh,
// where the per-branch effective-scope checks apply.
package scoperegistry

import (
	"strings"

	"github.com/yangwb1123/snaplink/shared/core"
)

// Registry answers whether a scope is registered (mintable at /token).
// A nil Registry is the default-off state: every check is a no-op so an
// unwired server behaves byte-identically to the pre-feature baseline.
type Registry interface {
	// Registered reports whether the effective scope is registered. The
	// shipped Memory implementation treats a registered pattern as
	// exact-or-":*" (mirroring permissions.Matches); other implementations
	// must keep mint/enforce semantics aligned or tokens minted under one
	// rule could 403 under another.
	Registered(scope string) bool
}

// Memory is the build-once registry shipped with the server: the seven
// protocol scopes (OIDC standard set + device_sso) pre-seeded by
// construction, plus the nine-scope tenant matrix passed in by the
// composition root, plus operator extra_scopes. Construction is the only
// mutation — after NewMemory returns the registry is frozen (any later
// Register is an error), so concurrent mint-path reads race-free.
type Memory struct {
	patterns []string
	frozen   bool
}

// ProtocolScopes is the deterministic built-in set: the OIDC standard scopes
// and the Native-SSO trigger. These are protocol scopes, not tenant resource
// scopes — the registry registers them by construction so the seam carries no
// hardcoded exemption list (a future bypass constant added to
// oauthvalidate.GrantedScopes is compile-time visible here and the registry
// cannot silently diverge). Imports the core constants, so the set is pinned
// structurally (test A-8e).
func ProtocolScopes() []string {
	return []string{
		core.ScopeOpenID,
		core.ScopeDeviceSSO,
		core.ScopeProfile,
		core.ScopeEmail,
		core.ScopeAddress,
		core.ScopePhone,
		core.ScopeOfflineAccess,
	}
}

// NewMemory builds a frozen registry from the tenant matrix (the nine
// scope-matrix-v2 scopes, supplied by interfaces/scopecontract — protocols
// must not import interfaces, so the composition root composes the two) plus
// operator extra_scopes. Validation is fail-closed and runs ALWAYS: a bare
// "*" or any non-":*" wildcard (e.g. "admin*") is a construction error, so a
// typo can never silently widen the gate. Built-ins are always registered and
// cannot be shadowed; listing them in extra is a harmless idempotent no-op
// (set semantics, no error).
func NewMemory(matrix, extra []string) (*Memory, error) {
	seen := make(map[string]struct{}, len(matrix)+len(extra)+len(ProtocolScopes()))
	patterns := make([]string, 0, len(matrix)+len(extra)+len(ProtocolScopes()))
	add := func(s string) error {
		if err := ValidatePattern(s); err != nil {
			return err
		}
		if _, dup := seen[s]; dup {
			return nil // set semantics: duplicates are a no-op, never a shadow
		}
		seen[s] = struct{}{}
		patterns = append(patterns, s)
		return nil
	}
	for _, s := range ProtocolScopes() {
		if err := add(s); err != nil {
			return nil, err
		}
	}
	for _, s := range matrix {
		if err := add(s); err != nil {
			return nil, err
		}
	}
	for _, s := range extra {
		if err := add(s); err != nil {
			return nil, err
		}
	}
	return &Memory{patterns: patterns, frozen: true}, nil
}

// Register is a post-build mutation guard: the registry is frozen after
// NewMemory, so this always errors. It exists so misuse (hot-reload,
// runtime registration) fails loudly instead of racing the mint path.
func (m *Memory) Register(scope string) error {
	if m.frozen {
		return errFrozen
	}
	return nil
}

// Registered implements Registry with the exact-or-":*" pattern rule that
// mirrors permissions.Matches and tokenpolicy scopePresent: "admin:read"
// matches "admin:read"; "admin:*" matches any "admin:..." scope. Any other
// pattern shape was rejected at construction, so this lookup is total —
// a registry error can never pass as a 200.
func (m *Memory) Registered(scope string) bool {
	if scope == "" {
		return false
	}
	for _, p := range m.patterns {
		if p == scope {
			return true
		}
		if domain, ok := strings.CutSuffix(p, ":*"); ok && strings.HasPrefix(scope, domain+":") {
			return true
		}
	}
	return false
}

// ValidatePattern enforces the fail-closed pattern grammar: a scope must be
// non-empty and either exact (no "*") or a domain-":*" wildcard. A bare "*"
// (the whole gate becomes a no-op) and any other star placement are rejected.
// Config validation runs this ALWAYS (even when scope_registry.enabled is
// false) so a malformed snapshot fails boot loudly instead of silently
// diverging at a later restart.
func ValidatePattern(s string) error {
	if s == "" {
		return errEmptyScope
	}
	if s == "*" {
		return errBareWildcard
	}
	if strings.Contains(s, "*") && !strings.HasSuffix(s, ":*") {
		return errBadWildcard
	}
	return nil
}
