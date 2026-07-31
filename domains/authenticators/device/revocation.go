package device

import (
	"context"

	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	MutationRevoked   = "revoked"
	MutationDeleted   = "deleted"
	MutationSuspended = "suspended"
	MutationFailed    = "failed"
)

// SessionRevocationResult is the stable per-session outcome returned by
// physical-device mutation endpoints.
type SessionRevocationResult struct {
	SessionID string `json:"session_id,omitempty"`
	Operation string `json:"operation"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}

// MutationResult reports both the device write and every associated session
// revocation, so callers can reconcile partial completion.
type MutationResult struct {
	DeviceID     string                    `json:"device_id"`
	DeviceStatus string                    `json:"device_status"`
	DeviceError  string                    `json:"device_error,omitempty"`
	Sessions     []SessionRevocationResult `json:"sessions"`
}

func (r MutationResult) Succeeded() bool {
	if r.DeviceStatus == MutationFailed {
		return false
	}
	for _, session := range r.Sessions {
		if session.Status == MutationFailed {
			return false
		}
	}
	return true
}

// RevokeSessions attempts every session associated with a physical device.
// Infrastructure errors are converted to stable codes rather than leaked.
func RevokeSessions(ctx context.Context, sessions core.SessionManager, userID, deviceID, lastIP string) []SessionRevocationResult {
	if sessions == nil {
		return []SessionRevocationResult{{Operation: "list", Status: MutationFailed, Error: "session_manager_unavailable"}}
	}
	list, err := sessions.ListByUser(ctx, userID)
	if err != nil {
		return []SessionRevocationResult{{Operation: "list", Status: MutationFailed, Error: "session_list_failed"}}
	}
	out := make([]SessionRevocationResult, 0)
	for _, session := range list {
		if session.DeviceID != deviceID && (session.DeviceID != "" || session.IP != lastIP) {
			continue
		}
		result := SessionRevocationResult{SessionID: session.ID, Operation: "destroy", Status: MutationRevoked}
		if err := sessions.Destroy(ctx, session.ID); err != nil {
			result.Status = MutationFailed
			result.Error = "session_destroy_failed"
		}
		out = append(out, result)
	}
	return out
}
