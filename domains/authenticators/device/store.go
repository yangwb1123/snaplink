package device

import (
	"context"
	"errors"
)

// ErrNoSuchDevice is returned when a device is not found.
var ErrNoSuchDevice = errors.New("device: no such device")

// Store persists device records. Implementations MUST be safe for concurrent use.
type Store interface {
	// Upsert creates or updates a device record (keyed by user_id + fingerprint).
	Upsert(ctx context.Context, d *Device) error

	// Get returns a device by ID, or ErrNoSuchDevice.
	Get(ctx context.Context, id string) (*Device, error)

	// GetByFingerprint returns a device by user_id + fingerprint, or ErrNoSuchDevice.
	GetByFingerprint(ctx context.Context, userID, fingerprint string) (*Device, error)

	// ListByUser returns every device owned by userID (most recent first).
	ListByUser(ctx context.Context, userID string) ([]*Device, error)

	// Delete removes a device by ID. Idempotent — missing IDs return nil.
	Delete(ctx context.Context, id string) error

	// ListAll returns all devices across all users. Backends with millions
	// of devices MAY return ErrUnsupportedOperation. Used by admin API.
	ListAll(ctx context.Context) ([]*Device, error)

	// DeleteByUser removes all devices for a user. Used on account deletion.
	DeleteByUser(ctx context.Context, userID string) error
}

// NewFingerprint generates a device fingerprint from X-Device-Id or User-Agent.
// When deviceID is non-empty it is used as-is; otherwise a hash of User-Agent
// serves as a best-effort fingerprint (less reliable but still useful).
func NewFingerprint(deviceID, userAgent string) string {
	if deviceID != "" {
		return deviceID
	}
	// Use a prefix of User-Agent as a weak fingerprint when no device ID
	// is provided. Short enough to avoid PII concerns.
	if len(userAgent) > 64 {
		return userAgent[:64]
	}
	return userAgent
}
