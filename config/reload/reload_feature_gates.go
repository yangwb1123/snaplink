package reload

import (
	"fmt"

	"github.com/yangwb1123/snaplink/config"
)

// This file holds the Set*GateHook setters and apply*Gate methods for every
// feature_gates.* field reload treats as safe (see reload.go's package doc
// and safeReloadPaths) — split out of reload.go to stay within the
// maintainability line budget. Each gate's hook mirrors setRateLimitPolicy's
// error contract: nil (unwired) or a false return means the change had
// nowhere to land, so Reload reports it as Ignored rather than Applied.

// SetAdminAPIGateHook wires the callback Reload uses to apply a live
// feature_gates.admin_api change — typically Server.SetAdminAPIGateEnabled.
// nil (the default) makes a detected admin_api change appear in
// Result.Ignored instead of Result.Applied, mirroring every other unwired-
// hook contract in this file.
func (r *Reloader) SetAdminAPIGateHook(fn func(enabled bool) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setAdminAPIGate = fn
}

// SetBrandingGateHook wires the callback Reload uses to apply a live
// feature_gates.branding change — typically Server.SetBrandingGateEnabled.
// nil (the default) makes a detected branding change appear in
// Result.Ignored instead of Result.Applied, mirroring every other unwired-
// hook contract in this file. The legacy name SetWebSPAGateHook remains as
// a deprecated alias.
func (r *Reloader) SetBrandingGateHook(fn func(enabled bool) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setBrandingGate = fn
}

// SetWebSPAGateHook is the deprecated alias of SetBrandingGateHook,
// retained for source compatibility. See SetBrandingGateHook.
func (r *Reloader) SetWebSPAGateHook(fn func(enabled bool) bool) {
	r.SetBrandingGateHook(fn)
}

// SetOIDCGateHook wires the callback Reload uses to apply a live
// feature_gates.oidc change — typically Server.SetOIDCGateEnabled. nil (the
// default) makes a detected oidc change appear in Result.Ignored.
func (r *Reloader) SetOIDCGateHook(fn func(enabled bool) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setOIDCGate = fn
}

// SetCIBAGateHook wires the callback Reload uses to apply a live
// feature_gates.ciba change — typically Server.SetCIBAGateEnabled.
func (r *Reloader) SetCIBAGateHook(fn func(enabled bool) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setCIBAGate = fn
}

// SetCAEPGateHook wires the callback Reload uses to apply a live
// feature_gates.caep change — typically Server.SetCAEPGateEnabled. Like
// SetWebSPAGateHook, the hook itself can report false (no CAEP receiver was
// ever wired), surfaced as Ignored rather than Applied.
func (r *Reloader) SetCAEPGateHook(fn func(enabled bool) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setCAEPGate = fn
}

// SetFederationGateHook wires the callback Reload uses to apply a live
// feature_gates.federation change — typically Server.SetFederationGateEnabled.
// The hook can report false when none of the federation sub-features were
// ever wired, surfaced as Ignored rather than Applied.
func (r *Reloader) SetFederationGateHook(fn func(enabled bool) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setFederationGate = fn
}

// SetSelfServiceGateHook wires the callback Reload uses to apply a live
// feature_gates.self_service change — typically
// Server.SetSelfServiceGateEnabled.
func (r *Reloader) SetSelfServiceGateHook(fn func(enabled bool) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setSelfServiceGate = fn
}

// resolveGate mirrors interfaces/sso's unexported gateOn: nil (the operator
// never mentioned the field) or an explicit true both mean the surface is
// ON — only an explicit false turns it off. Duplicated here rather than
// imported (interfaces/sso does not export it) — this package intentionally
// stays decoupled from interfaces/sso, talking to it only through the
// set*Gate func hooks a caller wires in.
func resolveGate(explicit *bool) bool {
	return explicit == nil || *explicit
}

// applyAdminAPIGate applies a reloaded feature_gates.admin_api change live
// via the wired setAdminAPIGate hook. Reported as Applied only when a hook
// is wired AND it reports success — see SetAdminAPIGateHook's doc for why
// this hook, unlike setRateLimitPolicy, has no "not enabled at boot" failure
// mode in practice (mountAdminSurface's group is unconditional).
func (r *Reloader) applyAdminAPIGate(newCfg *config.Config) string {
	if r.setAdminAPIGate == nil {
		return ""
	}
	old := resolveGate(r.current.FeatureGates.AdminAPI)
	resolved := resolveGate(newCfg.FeatureGates.AdminAPI)
	if !r.setAdminAPIGate(resolved) {
		return ""
	}
	r.current.FeatureGates.AdminAPI = newCfg.FeatureGates.AdminAPI
	return fmt.Sprintf("feature_gates.admin_api: %v -> %v", old, resolved)
}

// applyBrandingGate is feature_gates.branding's analog of applyAdminAPIGate.
// Unlike admin_api, the wired hook (Server.SetBrandingGateEnabled) CAN report
// false here — when no tenant store was ever wired at NewServer time there
// is no already-mounted route for this gate to affect, so the change is
// reported as Ignored (by the "" return) rather than falsely Applied. The
// deprecated /feature_gates/web_spa reload path lands here too; the
// normalized config carries the value in FeatureGates.Branding either way.
func (r *Reloader) applyBrandingGate(newCfg *config.Config) string {
	if r.setBrandingGate == nil {
		return ""
	}
	old := resolveGate(r.current.FeatureGates.Branding)
	resolved := resolveGate(newCfg.FeatureGates.Branding)
	if !r.setBrandingGate(resolved) {
		return ""
	}
	r.current.FeatureGates.Branding = newCfg.FeatureGates.Branding
	return fmt.Sprintf("feature_gates.branding: %v -> %v", old, resolved)
}

// applyOIDCGate is feature_gates.oidc's analog of applyAdminAPIGate — the
// wired hook (Server.SetOIDCGateEnabled) always reports success, since
// mountOIDCUserEndpoints unconditionally mounts /userinfo + /end_session.
func (r *Reloader) applyOIDCGate(newCfg *config.Config) string {
	if r.setOIDCGate == nil {
		return ""
	}
	old := resolveGate(r.current.FeatureGates.OIDC)
	resolved := resolveGate(newCfg.FeatureGates.OIDC)
	if !r.setOIDCGate(resolved) {
		return ""
	}
	r.current.FeatureGates.OIDC = newCfg.FeatureGates.OIDC
	return fmt.Sprintf("feature_gates.oidc: %v -> %v", old, resolved)
}

// applyCIBAGate is feature_gates.ciba's analog of applyAdminAPIGate — the
// wired hook (Server.SetCIBAGateEnabled) always reports success, since
// mountCIBAEndpoint unconditionally mounts POST /backchannel-authentication.
func (r *Reloader) applyCIBAGate(newCfg *config.Config) string {
	if r.setCIBAGate == nil {
		return ""
	}
	old := resolveGate(r.current.FeatureGates.CIBA)
	resolved := resolveGate(newCfg.FeatureGates.CIBA)
	if !r.setCIBAGate(resolved) {
		return ""
	}
	r.current.FeatureGates.CIBA = newCfg.FeatureGates.CIBA
	return fmt.Sprintf("feature_gates.ciba: %v -> %v", old, resolved)
}

// applyCAEPGate is feature_gates.caep's analog of applyWebSPAGate — the
// wired hook (Server.SetCAEPGateEnabled) CAN report false when no CAEP
// receiver was ever wired via WithCAEPReceiver, surfaced as Ignored.
func (r *Reloader) applyCAEPGate(newCfg *config.Config) string {
	if r.setCAEPGate == nil {
		return ""
	}
	old := resolveGate(r.current.FeatureGates.CAEP)
	resolved := resolveGate(newCfg.FeatureGates.CAEP)
	if !r.setCAEPGate(resolved) {
		return ""
	}
	r.current.FeatureGates.CAEP = newCfg.FeatureGates.CAEP
	return fmt.Sprintf("feature_gates.caep: %v -> %v", old, resolved)
}

// applyFederationGate is feature_gates.federation's analog of
// applyWebSPAGate — the wired hook (Server.SetFederationGateEnabled) CAN
// report false when none of the federation sub-features (protected-resource
// metadata, federation entity, connection store) were ever wired.
func (r *Reloader) applyFederationGate(newCfg *config.Config) string {
	if r.setFederationGate == nil {
		return ""
	}
	old := resolveGate(r.current.FeatureGates.Federation)
	resolved := resolveGate(newCfg.FeatureGates.Federation)
	if !r.setFederationGate(resolved) {
		return ""
	}
	r.current.FeatureGates.Federation = newCfg.FeatureGates.Federation
	return fmt.Sprintf("feature_gates.federation: %v -> %v", old, resolved)
}

// applySelfServiceGate is feature_gates.self_service's analog of
// applyAdminAPIGate — the wired hook (Server.SetSelfServiceGateEnabled)
// always reports success, since mountSelfServiceProfile unconditionally
// mounts GET /me/permissions, /me/menus, and /me/roles.
func (r *Reloader) applySelfServiceGate(newCfg *config.Config) string {
	if r.setSelfServiceGate == nil {
		return ""
	}
	old := resolveGate(r.current.FeatureGates.SelfService)
	resolved := resolveGate(newCfg.FeatureGates.SelfService)
	if !r.setSelfServiceGate(resolved) {
		return ""
	}
	r.current.FeatureGates.SelfService = newCfg.FeatureGates.SelfService
	return fmt.Sprintf("feature_gates.self_service: %v -> %v", old, resolved)
}
