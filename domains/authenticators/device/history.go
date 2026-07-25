package device

import (
	"time"
)

// LoginRecord represents one completed login event.
type LoginRecord struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Time      time.Time `json:"time"`
	IP        string    `json:"ip"`
	DeviceID  string    `json:"device_id,omitempty"`
	Device    string    `json:"device,omitempty"`      // device summary from UA
	Location  string    `json:"location,omitempty"`   // geo summary
	Provider  string    `json:"provider,omitempty"`   // auth provider used
	Success   bool      `json:"success"`
	SessionID string    `json:"session_id,omitempty"`

	// TrustScore is the device's trust score at the time of this login.
	TrustScore float64 `json:"trust_score,omitempty"`

	// Security flags — set during login when device is new or location changes.
	DeviceIsNew    bool `json:"device_is_new,omitempty"`
	LocationIsNew bool `json:"location_is_new,omitempty"`
}

// HistoryStore persists login events.
type HistoryStore interface {
	// Record persists a login event.
	Record(rec *LoginRecord) error

	// RecentByUser returns the most recent login events for a user,
	// ordered by time descending, limited to n entries.
	RecentByUser(userID string, limit int) ([]*LoginRecord, error)

	// RecentByDevice returns login events for a specific device.
	RecentByDevice(deviceID string, limit int) ([]*LoginRecord, error)
}
