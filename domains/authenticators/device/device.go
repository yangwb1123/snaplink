// Package device models authenticated devices — the physical or virtual clients
// a user authenticates from (browsers, mobile apps, desktop apps, CLIs). Each
// device is identified by a fingerprint (X-Device-Id) and carries parsed
// UserAgent metadata (OS, platform, browser). Devices are TENANT-SCOPED through
// their owning user's tenant; a user can have multiple devices, and a session
// is bound to exactly one device.
//
// The device model powers:
//   - Self-service "where am I logged in?" listing
//   - Per-device session revocation
//   - Multi-device policy enforcement (max devices, new-device alerts)
//   - Login history with device context
//   - Security analysis (new device detection, impossible travel)
package device

import "time"

// DeviceType classifies the client platform.
type DeviceType string

const (
	DeviceTypeBrowser DeviceType = "browser"
	DeviceTypeMobile  DeviceType = "mobile"
	DeviceTypeApp     DeviceType = "app"
	DeviceTypeDesktop DeviceType = "desktop"
	DeviceTypeTablet  DeviceType = "tablet"
	DeviceTypeBot     DeviceType = "bot"
	DeviceTypeUnknown DeviceType = "unknown"
)

// Device represents an authenticated client device.
type Device struct {
	// ID is a unique identifier for this device record.
	ID string `json:"id"`

	// UserID is the user who owns this device.
	UserID string `json:"user_id"`

	// Fingerprint is the opaque device identifier from X-Device-Id header,
	// or a generated hash when the client doesn't supply one.
	Fingerprint string `json:"fingerprint"`

	// Type classifies the device platform.
	Type DeviceType `json:"type"`

	// Platform is the OS family ("iOS", "Android", "Windows", "macOS", "Linux").
	Platform string `json:"platform,omitempty"`

	// OSVersion is the OS version ("17.4", "14", "11", "24.04").
	OSVersion string `json:"os_version,omitempty"`

	// BrowserName is the web browser ("Chrome", "Safari", "Firefox").
	BrowserName string `json:"browser_name,omitempty"`

	// BrowserVersion is the browser version ("125.0", "17.4").
	BrowserVersion string `json:"browser_version,omitempty"`

	// DeviceName is a human-readable device label ("iPhone 15 Pro", "Pixel 8").
	DeviceName string `json:"device_name,omitempty"`

	// RawUserAgent is the original User-Agent header value.
	RawUserAgent string `json:"raw_user_agent,omitempty"`

	// FirstSeenAt is when this device was first seen.
	FirstSeenAt time.Time `json:"first_seen_at"`

	// LastSeenAt is when this device was last active.
	LastSeenAt time.Time `json:"last_seen_at"`

	// LastIP is the last known IP address for this device.
	LastIP string `json:"last_ip,omitempty"`

	// LastLocation is the last known geographic location for this device
	// (e.g. "Beijing, CN-BJ"). Populated from geo context during login.
	LastLocation string `json:"last_location,omitempty"`

	// TrustScore is the device trust level [0,1], computed from login history.
	// Higher values indicate more trusted devices. Updated on each login.
	TrustScore float64 `json:"trust_score,omitempty"`

	// TrustLabel is a human-readable trust level derived from TrustScore.
	TrustLabel string `json:"trust_label,omitempty"`

	// TrustHistory tracks trust score changes over time.
	TrustHistory []TrustHistoryEntry `json:"trust_history,omitempty"`

	// LoginCount is the total number of successful logins from this device.
	LoginCount int `json:"login_count,omitempty"`

	// Notes is a user-provided free-text annotation for this device
	// (e.g. "Work iPhone", "Shared family iPad"). Set via PATCH /me/devices/:id.
	Notes string `json:"notes,omitempty"`

	// Suspicious flags devices that triggered anomaly detection.
	Suspicious bool `json:"suspicious,omitempty"`
}

// DecayTrustScore reduces a device's trust score based on days since last seen.
// A device not seen in 30+ days loses 0.1 per 30 days, to a minimum of 0.2.
func DecayTrustScore(score float64, daysSinceLastSeen int) float64 {
	if daysSinceLastSeen <= 0 { return score }
	decay := float64(daysSinceLastSeen) / 30.0 * 0.1
	if decay > 0.5 { decay = 0.5 } // max decay
	score -= decay
	if score < 0.2 { score = 0.2 }
	return score
}

// TrustHistoryEntry records one trust score at a point in time.
type TrustHistoryEntry struct {
	Time   time.Time `json:"time"`
	Score  float64   `json:"score"`
	Label  string    `json:"label"`
	Reason string    `json:"reason,omitempty"` // e.g. "login", "decay", "admin_reset", "manual_trust"
}

// TrustLabelForScore converts a numeric trust score to a human-readable label.
func TrustLabelForScore(score float64) string {
	switch {
	case score >= 0.8:
		return "Very High"
	case score >= 0.6:
		return "High"
	case score >= 0.4:
		return "Medium"
	case score >= 0.2:
		return "Low"
	default:
		return "Very Low"
	}
}

// Clone returns a deep copy of the device.
func (d *Device) Clone() *Device {
	cp := *d
	return &cp
}
