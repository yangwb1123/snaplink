package trust

import "context"

// DevicePostureScorer is an explicit STUB reserved for a future MDM
// integration (device compliance, OS/patch level, jailbreak/root
// detection). Snaplink core has no device inventory of its own — the source
// analysis doc's Phase 1 scope explicitly reserves this scorer rather than
// faking a signal it can't actually observe. It ALWAYS returns the
// configured Default, unconditionally, and NEVER errors.
//
// Deployments integrating an MDM (Jamf, Intune, Workspace ONE, ...) should
// implement TrustScorer directly against their MDM API rather than
// extending this stub.
type DevicePostureScorer struct {
	// Default is returned for every call. See NewDevicePostureScorer for the
	// recommended construction (clamps + stamps the "not integrated"
	// reason).
	Default TrustScore
}

// NewDevicePostureScorer builds a DevicePostureScorer returning defaultValue
// (clamped to [0,1]) with a reason documenting the signal is unimplemented.
// The source analysis doc's device-posture-privacy edge case recommends a
// conservative (not full-trust) default — e.g. 0.3 — since "no report" and
// "no MDM integration" are indistinguishable to this scorer; callers should
// NOT default to 1.0 just because posture is unavailable.
func NewDevicePostureScorer(defaultValue float64) *DevicePostureScorer {
	return &DevicePostureScorer{Default: TrustScore{
		Value:   ClampScore(defaultValue),
		Reasons: []string{"device_posture:not_integrated"},
	}}
}

// Name implements TrustScorer.
func (s *DevicePostureScorer) Name() string { return "device_posture" }

// Score implements TrustScorer.
func (s *DevicePostureScorer) Score(_ context.Context, _ TrustSignals) (TrustScore, error) {
	return s.Default, nil
}

var _ TrustScorer = (*DevicePostureScorer)(nil)
