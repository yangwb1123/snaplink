package sso_test

// rootcov_lifecycle_test.go drives the user-lifecycle state-machine admin
// endpoints (GET/POST /api/v1/admin/users/:id/lifecycle) end-to-end through the
// real AdminMiddleware, and proves the surface is absent (default-off) when
// WithUserLifecycle is not wired.

import (
	"net/http"
	"testing"

	"github.com/yangwb1123/snaplink/domains/userlifecycle/memory"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestRcovAdmin_UserLifecycle(t *testing.T) {
	t.Parallel()
	env := rcovNewAdminServer(t, sso.WithUserLifecycle(memory.New()))
	base := env.url + "/api/v1/admin/users/" + rcovUser + "/lifecycle"

	// GET: a user with no record reports the implicit default (active) + the
	// moves legal from it, and an empty (never null) history.
	status, out := rcovDo(t, http.MethodGet, base, env.token, nil)
	if status != http.StatusOK {
		t.Fatalf("GET lifecycle = %d body=%v", status, out)
	}
	if out["state"] != "active" {
		t.Errorf("initial state = %v, want active", out["state"])
	}
	if allowed, ok := out["allowed_transitions"].([]any); !ok || len(allowed) == 0 {
		t.Errorf("allowed_transitions = %v, want non-empty list", out["allowed_transitions"])
	}
	if hist, ok := out["history"].([]any); !ok || len(hist) != 0 {
		t.Errorf("initial history = %v, want []", out["history"])
	}

	// POST a legal transition (active -> suspended) => 200, new state reported.
	status, out = rcovPostJSON(t, base, env.token, map[string]any{"state": "suspended", "reason": "policy hold"})
	if status != http.StatusOK {
		t.Fatalf("POST suspend = %d body=%v", status, out)
	}
	if out["state"] != "suspended" || out["previous_state"] != "active" {
		t.Errorf("transition result = %v, want suspended (from active)", out)
	}

	// GET reflects the new state + the recorded history entry.
	_, out = rcovDo(t, http.MethodGet, base, env.token, nil)
	if out["state"] != "suspended" {
		t.Errorf("state after suspend = %v, want suspended", out["state"])
	}
	if hist, _ := out["history"].([]any); len(hist) != 1 {
		t.Errorf("history = %v, want one entry", out["history"])
	}

	// POST an illegal transition (suspended -> purged) => 400 illegal_lifecycle_transition.
	status, out = rcovPostJSON(t, base, env.token, map[string]any{"state": "purged"})
	if status != http.StatusBadRequest || out["error"] != "illegal_lifecycle_transition" {
		t.Errorf("illegal transition = %d %v, want 400 illegal_lifecycle_transition", status, out)
	}

	// POST an unknown target state => 400 unknown_lifecycle_state.
	status, out = rcovPostJSON(t, base, env.token, map[string]any{"state": "bogus"})
	if status != http.StatusBadRequest || out["error"] != "unknown_lifecycle_state" {
		t.Errorf("unknown state = %d %v, want 400 unknown_lifecycle_state", status, out)
	}

	// A transition for a user the provider doesn't know => 404.
	ghost := env.url + "/api/v1/admin/users/ghost/lifecycle"
	status, _ = rcovPostJSON(t, ghost, env.token, map[string]any{"state": "suspended"})
	if status != http.StatusNotFound {
		t.Errorf("transition unknown user = %d, want 404", status)
	}
}

// TestRcovAdmin_UserLifecycle_DefaultOff proves the lifecycle routes are not
// mounted when WithUserLifecycle is absent — a probe gets the router's native
// 404, byte-identical to a build without the feature.
func TestRcovAdmin_UserLifecycle_DefaultOff(t *testing.T) {
	t.Parallel()
	env := rcovNewAdminServer(t) // no WithUserLifecycle
	base := env.url + "/api/v1/admin/users/" + rcovUser + "/lifecycle"
	if status, _ := rcovDo(t, http.MethodGet, base, env.token, nil); status != http.StatusNotFound {
		t.Errorf("GET lifecycle (feature off) = %d, want 404 (route not mounted)", status)
	}
	if status, _ := rcovPostJSON(t, base, env.token, map[string]any{"state": "suspended"}); status != http.StatusNotFound {
		t.Errorf("POST lifecycle (feature off) = %d, want 404 (route not mounted)", status)
	}
}
