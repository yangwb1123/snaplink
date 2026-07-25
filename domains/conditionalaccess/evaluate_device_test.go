package conditionalaccess

import (
	"testing"
)

func TestMatchDeviceConditions_NoConditions(t *testing.T) {
	// No device conditions should always match
	c := Conditions{}
	ac := AccessContext{}
	if !matchDeviceConditions(c, ac) {
		t.Error("empty conditions should match any device")
	}
}

func TestMatchDeviceConditions_DeviceTypeMatch(t *testing.T) {
	c := Conditions{DeviceType: "mobile"}
	ac := AccessContext{DeviceType: "mobile"}
	if !matchDeviceConditions(c, ac) {
		t.Error("mobile should match mobile")
	}
}

func TestMatchDeviceConditions_DeviceTypeMismatch(t *testing.T) {
	c := Conditions{DeviceType: "mobile"}
	ac := AccessContext{DeviceType: "desktop"}
	if matchDeviceConditions(c, ac) {
		t.Error("mobile should not match desktop")
	}
}

func TestMatchDeviceConditions_DeviceTypeEmpty(t *testing.T) {
	c := Conditions{DeviceType: "mobile"}
	ac := AccessContext{DeviceType: ""}
	if matchDeviceConditions(c, ac) {
		t.Error("mobile should not match empty device type")
	}
}

func TestMatchDeviceConditions_TrustLevelAboveThreshold(t *testing.T) {
	c := Conditions{DeviceTrustLevel: 0.5}
	ac := AccessContext{DeviceTrustLevel: 0.7}
	if !matchDeviceConditions(c, ac) {
		t.Error("trust 0.7 should be >= 0.5 threshold")
	}
}

func TestMatchDeviceConditions_TrustLevelBelowThreshold(t *testing.T) {
	c := Conditions{DeviceTrustLevel: 0.5}
	ac := AccessContext{DeviceTrustLevel: 0.3}
	if matchDeviceConditions(c, ac) {
		t.Error("trust 0.3 should NOT be >= 0.5 threshold")
	}
}

func TestMatchDeviceConditions_TrustLevelZeroThreshold(t *testing.T) {
	// Zero threshold means unconstrained
	c := Conditions{DeviceTrustLevel: 0}
	ac := AccessContext{DeviceTrustLevel: 0.1}
	if !matchDeviceConditions(c, ac) {
		t.Error("zero threshold should not constrain")
	}
}

func TestMatchDeviceConditions_IsNewDevice(t *testing.T) {
	c := Conditions{IsNewDevice: true}
	ac := AccessContext{IsNewDevice: true}
	if !matchDeviceConditions(c, ac) {
		t.Error("IsNewDevice should match when both true")
	}
}

func TestMatchDeviceConditions_IsNewDeviceMismatch(t *testing.T) {
	c := Conditions{IsNewDevice: true}
	ac := AccessContext{IsNewDevice: false}
	if matchDeviceConditions(c, ac) {
		t.Error("IsNewDevice should NOT match when request has false")
	}
}

func TestMatchDeviceConditions_IsNewLocation(t *testing.T) {
	c := Conditions{IsNewLocation: true}
	ac := AccessContext{IsNewLocation: true}
	if !matchDeviceConditions(c, ac) {
		t.Error("IsNewLocation should match when both true")
	}
}

func TestMatchDeviceConditions_MultipleConditions(t *testing.T) {
	// All conditions must match
	c := Conditions{
		DeviceType:        "mobile",
		DeviceTrustLevel:  0.5,
		IsNewDevice:       true,
	}
	ac := AccessContext{
		DeviceType:        "mobile",
		DeviceTrustLevel:  0.7,
		IsNewDevice:       true,
	}
	if !matchDeviceConditions(c, ac) {
		t.Error("all conditions should match")
	}
}

func TestMatchDeviceConditions_MultipleConditionsOneFails(t *testing.T) {
	c := Conditions{
		DeviceType:        "mobile",
		DeviceTrustLevel:  0.5,
		IsNewDevice:       true,
	}
	ac := AccessContext{
		DeviceType:        "mobile",
		DeviceTrustLevel:  0.7,
		IsNewDevice:       false, // this one fails
	}
	if matchDeviceConditions(c, ac) {
		t.Error("should fail when IsNewDevice doesn't match")
	}
}

func TestMatchDeviceConditions_ManagedMatch(t *testing.T) {
	managed := true
	c := Conditions{DeviceManaged: &managed}
	ac := AccessContext{DevicePosture: PostureManaged}
	if !matchDeviceConditions(c, ac) {
		t.Error("managed device should match PostureManaged")
	}
}

func TestMatchDeviceConditions_ManagedMismatch(t *testing.T) {
	managed := true
	c := Conditions{DeviceManaged: &managed}
	ac := AccessContext{DevicePosture: PostureUnmanaged}
	if matchDeviceConditions(c, ac) {
		t.Error("unmanaged device should NOT match managed condition")
	}
}

// Adversarial: empty DeviceType in AccessContext
func TestAdversarial_DeviceConditions_EmptyDeviceType(t *testing.T) {
	c := Conditions{DeviceType: "browser"}
	ac := AccessContext{DeviceType: ""}
	if matchDeviceConditions(c, ac) {
		t.Error("empty device type should not match 'browser'")
	}
}

// Adversarial: negative trust score
func TestAdversarial_DeviceConditions_NegativeTrust(t *testing.T) {
	c := Conditions{DeviceTrustLevel: 0.5}
	ac := AccessContext{DeviceTrustLevel: -0.1}
	if matchDeviceConditions(c, ac) {
		t.Error("negative trust (-0.1) should not be >= 0.5")
	}
}

// Adversarial: very high trust threshold
func TestAdversarial_DeviceConditions_HighThreshold(t *testing.T) {
	c := Conditions{DeviceTrustLevel: 0.99}
	ac := AccessContext{DeviceTrustLevel: 0.95}
	if matchDeviceConditions(c, ac) {
		t.Error("trust 0.95 should not be >= 0.99")
	}
}

// Adversarial: all false conditions
func TestAdversarial_DeviceConditions_AllFalse(t *testing.T) {
	c := Conditions{IsNewDevice: false, IsNewLocation: false}
	ac := AccessContext{IsNewDevice: true}
	// Conditions with false values should match any (false is the default/unset)
	// Our implementation checks: if c.IsNewDevice && !ac.IsNewDevice { return false }
	// c.IsNewDevice=false → skip check
	if !matchDeviceConditions(c, ac) {
		t.Error("false conditions should not constrain")
	}
}

func TestDeviceTypeSpecificity(t *testing.T) {
	c := Conditions{DeviceType: "mobile"}
	c2 := Conditions{DeviceType: "mobile", IsNewDevice: true}
	// c2 should be more specific
	if c2.specificity() <= c.specificity() {
		t.Errorf("c2 specificity (%d) should be > c specificity (%d)", c2.specificity(), c.specificity())
	}
}

func TestDeviceTrustSpecificity(t *testing.T) {
	c := Conditions{DeviceTrustLevel: 0.5}
	c2 := Conditions{DeviceTrustLevel: 0.5, DeviceType: "mobile"}
	if c2.specificity() <= c.specificity() {
		t.Errorf("c2 specificity (%d) should be > c specificity (%d)", c2.specificity(), c.specificity())
	}
}
