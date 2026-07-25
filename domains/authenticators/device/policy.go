package device

// Policy defines device-related security rules for a tenant or deployment.
// Zero values mean "no restriction" (unlimited, allowed, disabled).
type Policy struct {
	// MaxDevicesPerUser limits how many distinct devices a single user may
	// register. 0 = unlimited (default).
	MaxDevicesPerUser int `json:"max_devices_per_user,omitempty" yaml:"max_devices_per_user,omitempty"`

	// MaxSessionsPerDevice limits how many concurrent sessions a single device
	// may have. 0 = unlimited (default).
	MaxSessionsPerDevice int `json:"max_sessions_per_device,omitempty" yaml:"max_sessions_per_device,omitempty"`

	// AllowMultipleDevices controls whether a user may be logged in on more
	// than one device at a time. When false, a new device login evicts all
	// sessions on other devices (the user is still logged in on the new
	// device, but old sessions are revoked). Default true.
	AllowMultipleDevices *bool `json:"allow_multiple_devices,omitempty" yaml:"allow_multiple_devices,omitempty"`

	// RequireDeviceFingerprint, when true, rejects login attempts that don't
	// provide a device identifier (X-Device-Id header). Default false.
	RequireDeviceFingerprint bool `json:"require_device_fingerprint,omitempty" yaml:"require_device_fingerprint,omitempty"`

	// RequireMFAForNewDevice, when true, requires MFA step-up when logging in
	// from a device that has never been seen before. Requires WithMFAProvider
	// + WithMFAChallengeStore to be wired. Default false.
	RequireMFAForNewDevice bool `json:"require_mfa_for_new_device,omitempty" yaml:"require_mfa_for_new_device,omitempty"`

	// DeviceFingerprintTTL sets how long a device fingerprint remains valid
	// without being seen again. After this period, the device may be treated
	// as a new device. 0 = unlimited (never expires).
	DeviceFingerprintTTL int `json:"device_fingerprint_ttl_seconds,omitempty" yaml:"device_fingerprint_ttl_seconds,omitempty"`
}

// AllowMultiple returns true when multiple devices are allowed (default).
func (p Policy) AllowMultiple() bool {
	return p.AllowMultipleDevices == nil || *p.AllowMultipleDevices
}

// DeviceDecision is the result of evaluating device policy for a login.
type DeviceDecision struct {
	// Allowed is true when the login is permitted under device policy.
	Allowed bool

	// Reason describes why the login was denied, when Allowed is false.
	Reason string

	// IsNewDevice is true when this is the first time this device is seen.
	IsNewDevice bool

	// CurrentDeviceCount is the number of devices the user currently has.
	CurrentDeviceCount int

	// EvictedDeviceIDs lists the devices whose sessions were revoked to make
	// room when MaxDevicesPerUser was exceeded (LRU eviction).
	EvictedDeviceIDs []string
}

// EvaluatePolicy checks a login attempt against the device policy.
// store is the DeviceStore to query current device state.
// userID is the authenticating user.
// fingerprint is the device fingerprint (X-Device-Id).
// Returns a DeviceDecision indicating whether the login should proceed.
func EvaluatePolicy(p Policy, store Store, userID, fingerprint string) DeviceDecision {
	if store == nil {
		return DeviceDecision{Allowed: true}
	}
	// Check if device fingerprint is required.
	if p.RequireDeviceFingerprint && fingerprint == "" {
		return DeviceDecision{Allowed: false, Reason: "device fingerprint required"}
	}
	// Detect if this is a new device.
	_, err := store.GetByFingerprint(nil, userID, fingerprint)
	isNew := err != nil
	// Count current devices.
	devices, _ := store.ListByUser(nil, userID)
	currentCount := len(devices)
	// Check max devices.
	if p.MaxDevicesPerUser > 0 && currentCount >= p.MaxDevicesPerUser && isNew {
		return DeviceDecision{
			Allowed:            false,
			Reason:             "maximum number of devices reached",
			IsNewDevice:        isNew,
			CurrentDeviceCount: currentCount,
		}
	}
	// Check if multiple devices are allowed.
	if !p.AllowMultiple() && currentCount > 0 && isNew {
		return DeviceDecision{
			Allowed:            false,
			Reason:             "multiple devices not allowed",
			IsNewDevice:        isNew,
			CurrentDeviceCount: currentCount,
		}
	}
	// All checks passed.
	return DeviceDecision{
		Allowed:            true,
		IsNewDevice:        isNew,
		CurrentDeviceCount: currentCount,
	}
}
