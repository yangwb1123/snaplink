package serverbuildplatform

import (
	"errors"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	userlifecyclememory "github.com/yangwb1123/snaplink/domains/userlifecycle/memory"
)

// BuildUserLifecycle builds the userlifecycle.Store backing
// sso.WithUserLifecycle when user_lifecycle.enabled — the admin GET/POST
// /api/v1/admin/users/:id/lifecycle state-machine surface. Only a memory
// backend exists today (domains/userlifecycle/memory); a durable peer
// implementing the same Store contract can be swapped in later without
// touching this seam. Returns nil when disabled — byte-identical to a build
// without the feature.
func BuildUserLifecycle(cfg config.UserLifecycleConfig) userlifecycle.Store {
	if !cfg.Enabled {
		return nil
	}
	return userlifecyclememory.New()
}

// BuildUserAutoDeprovision translates the auto_deprovision config block into
// the userlifecycle.DeprovisionConfig backing sso.WithUserAutoDeprovision.
// This is a SEPARATE opt-in from BuildUserLifecycle (mirrors
// sso.WithUserAutoDeprovision itself requiring sso.WithUserLifecycle at the
// SDK layer, since the sweep persists through that SAME store):
// lifecycleEnabled must be true or this fails loud — auto-deprovision with
// no lifecycle store wired has nowhere to persist a transition, so it is
// refused at boot rather than silently degrading to a permanent no-op.
//
// Returns a zero (disabled) DeprovisionConfig + nil error when
// auto_deprovision.enabled is false — byte-identical to a build without the
// sweep. The caller (cmd) is responsible for starting
// Server.RunUserAutoDeprovision with cfg.SweepInterval once this returns a
// DeprovisionConfig whose Enabled() is true — this function has no
// background-loop side effects of its own.
func BuildUserAutoDeprovision(cfg config.UserAutoDeprovisionConfig, lifecycleEnabled bool) (userlifecycle.DeprovisionConfig, error) {
	if !cfg.Enabled {
		return userlifecycle.DeprovisionConfig{}, nil
	}
	if !lifecycleEnabled {
		return userlifecycle.DeprovisionConfig{}, errors.New("user_lifecycle.auto_deprovision.enabled requires user_lifecycle.enabled")
	}
	if cfg.DormantAfter <= 0 {
		return userlifecycle.DeprovisionConfig{}, errors.New("user_lifecycle.auto_deprovision.dormant_after must be > 0 when enabled")
	}
	if cfg.SweepInterval <= 0 {
		return userlifecycle.DeprovisionConfig{}, errors.New("user_lifecycle.auto_deprovision.sweep_interval must be > 0 when enabled")
	}
	return userlifecycle.DeprovisionConfig{
		DormantAfter: cfg.DormantAfter,
		ArchiveAfter: cfg.ArchiveAfter,
		MaxPerSweep:  cfg.MaxPerSweep,
	}, nil
}
