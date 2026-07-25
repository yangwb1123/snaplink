// Package device — login security analysis.
//
// LoginSecurityContext provides security-relevant signals about a login
// attempt: whether the device is new, whether the location (IP/geo) is new
// for this user, and the previous login context for comparison.
package device

import "time"

// PreviousLogin describes the user's most recent login before this one.
type PreviousLogin struct {
	Time     time.Time `json:"time,omitempty"`
	IP       string    `json:"ip,omitempty"`
	DeviceID string    `json:"device_id,omitempty"`
	Device   string    `json:"device,omitempty"` // device type + name summary
	Location string    `json:"location,omitempty"` // city, region summary
}

// LoginSecurityContext is the security analysis for one login attempt.
type LoginSecurityContext struct {
	// DeviceIsNew is true when this device fingerprint has not been seen before.
	DeviceIsNew bool `json:"device_is_new"`

	// LocationIsNew is true when the IP/geo has not been seen before for this user.
	LocationIsNew bool `json:"location_is_new"`

	// ActiveDevices is the number of devices the user currently has.
	ActiveDevices int `json:"active_devices"`

	// ActiveSessions is the total number of active sessions across all devices.
	ActiveSessions int `json:"active_sessions"`

	// PreviousLogin is the user's previous login info, if available.
	PreviousLogin *PreviousLogin `json:"previous_login,omitempty"`
}

// BuildSecurityContext builds a LoginSecurityContext for a login attempt.
// It queries the device store and session manager to determine if the
// device/location are new, and provides previous login context.
//
// Parameters:
//   - store: the DeviceStore (nil = no security context)
//   - sessionList: function to list user's sessions
//   - userID: the authenticating user
//   - fingerprint: the device fingerprint (X-Device-Id)
//   - ip: the client IP address
//
// Returns nil when store is nil (security context disabled).
func BuildSecurityContext(store Store, listSessions func(string) (int, error), userID, fingerprint, ip string) *LoginSecurityContext {
	if store == nil {
		return nil
	}
	ctx := &LoginSecurityContext{}

	// Check if this device is new.
	existing, err := store.GetByFingerprint(nil, userID, fingerprint)
	ctx.DeviceIsNew = err != nil

	// Count devices.
	devices, _ := store.ListByUser(nil, userID)
	ctx.ActiveDevices = len(devices)

	// Count sessions.
	if listSessions != nil {
		if count, err := listSessions(userID); err == nil {
			ctx.ActiveSessions = count
		}
	}

	// Check if this location (IP) is new.
	if existing != nil && existing.LastIP != "" && existing.LastIP != ip {
		ctx.LocationIsNew = true
	}

	// Build previous login context from the existing device record.
	if existing != nil && !ctx.DeviceIsNew {
		loc := ""
		ctx.PreviousLogin = &PreviousLogin{
			Time:     existing.LastSeenAt,
			IP:       existing.LastIP,
			DeviceID: existing.ID,
			Device:   deviceSummary(existing),
			Location: loc,
		}
	}

	return ctx
}

// deviceSummary returns a short human-readable summary of a device.
func deviceSummary(d *Device) string {
	if d.DeviceName != "" {
		if d.Platform != "" {
			return d.Platform + " · " + d.DeviceName
		}
		return d.DeviceName
	}
	if d.BrowserName != "" {
		if d.Platform != "" {
			return d.Platform + " · " + d.BrowserName
		}
		return d.BrowserName
	}
	if d.Platform != "" {
		return d.Platform
	}
	return string(d.Type)
}
