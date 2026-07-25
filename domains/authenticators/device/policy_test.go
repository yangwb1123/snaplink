package device

import "testing"

func boolPtr(b bool) *bool { return &b }

func TestEvaluatePolicy_NoPolicy_AllowsAll(t *testing.T) {
	store := NewMemoryStore()
	_ = store.Upsert(nil, &Device{UserID: "u1", Fingerprint: "fp1"})

	dec := EvaluatePolicy(Policy{}, store, "u1", "fp_new")
	if !dec.Allowed {
		t.Errorf("empty policy should allow, got denied: %s", dec.Reason)
	}
	if !dec.IsNewDevice {
		t.Error("fp_new should be new")
	}
}

func TestEvaluatePolicy_MaxDevices_RejectsWhenFull(t *testing.T) {
	store := NewMemoryStore()
	// Register existing devices.
	for i := 0; i < 3; i++ {
		_ = store.Upsert(nil, &Device{
			UserID:      "u1",
			Fingerprint: "fp_existing_" + string(rune('0'+i)),
			Type:        DeviceTypeMobile,
		})
	}
	p := Policy{MaxDevicesPerUser: 3}
	dec := EvaluatePolicy(p, store, "u1", "fp_new")
	if dec.Allowed {
		t.Error("max devices = 3 with 3 existing + new = should deny")
	}
	if dec.Reason != "maximum number of devices reached" {
		t.Errorf("reason = %q", dec.Reason)
	}
}

func TestEvaluatePolicy_MaxDevices_AllowsExisting(t *testing.T) {
	store := NewMemoryStore()
	_ = store.Upsert(nil, &Device{UserID: "u1", Fingerprint: "fp1"})
	_ = store.Upsert(nil, &Device{UserID: "u1", Fingerprint: "fp2"})

	// 2 existing devices, max = 3, existing device should be allowed.
	p := Policy{MaxDevicesPerUser: 3}
	dec := EvaluatePolicy(p, store, "u1", "fp1")
	if !dec.Allowed {
		t.Errorf("existing device should be allowed: %s", dec.Reason)
	}
	if dec.IsNewDevice {
		t.Error("existing device should not be flagged as new")
	}
}

func TestEvaluatePolicy_MaxDevices_AllowsUnderLimit(t *testing.T) {
	store := NewMemoryStore()
	_ = store.Upsert(nil, &Device{UserID: "u1", Fingerprint: "fp1"})

	p := Policy{MaxDevicesPerUser: 3}
	dec := EvaluatePolicy(p, store, "u1", "fp_new")
	if !dec.Allowed {
		t.Errorf("1 existing + 1 new = 2 < 3, should allow: %s", dec.Reason)
	}
	if !dec.IsNewDevice {
		t.Error("new fingerprint should be flagged as new")
	}
}

func TestEvaluatePolicy_RequireFingerprint_RejectsEmpty(t *testing.T) {
	store := NewMemoryStore()
	p := Policy{RequireDeviceFingerprint: true}

	dec := EvaluatePolicy(p, store, "u1", "")
	if dec.Allowed {
		t.Error("should reject empty fingerprint when required")
	}
	if dec.Reason != "device fingerprint required" {
		t.Errorf("reason = %q", dec.Reason)
	}
}

func TestEvaluatePolicy_RequireFingerprint_AllowsWithFP(t *testing.T) {
	store := NewMemoryStore()
	p := Policy{RequireDeviceFingerprint: true}

	dec := EvaluatePolicy(p, store, "u1", "fp_valid")
	if !dec.Allowed {
		t.Errorf("should allow valid fingerprint: %s", dec.Reason)
	}
}

func TestEvaluatePolicy_NoMultipleDevices_RejectsNew(t *testing.T) {
	store := NewMemoryStore()
	_ = store.Upsert(nil, &Device{UserID: "u1", Fingerprint: "fp1"})

	p := Policy{AllowMultipleDevices: boolPtr(false)}
	dec := EvaluatePolicy(p, store, "u1", "fp_new")
	if dec.Allowed {
		t.Error("should reject new device when multiple not allowed")
	}
	if dec.Reason != "multiple devices not allowed" {
		t.Errorf("reason = %q", dec.Reason)
	}
}

func TestEvaluatePolicy_NoMultipleDevices_AllowsSameDevice(t *testing.T) {
	store := NewMemoryStore()
	_ = store.Upsert(nil, &Device{UserID: "u1", Fingerprint: "fp1"})

	p := Policy{AllowMultipleDevices: boolPtr(false)}
	dec := EvaluatePolicy(p, store, "u1", "fp1")
	if !dec.Allowed {
		t.Errorf("existing device should be allowed: %s", dec.Reason)
	}
}

func TestEvaluatePolicy_NilStore_Allows(t *testing.T) {
	dec := EvaluatePolicy(Policy{MaxDevicesPerUser: 1}, nil, "u1", "fp1")
	if !dec.Allowed {
		t.Error("nil store should allow")
	}
}

func TestEvaluatePolicy_IsNewDevice(t *testing.T) {
	store := NewMemoryStore()
	_ = store.Upsert(nil, &Device{UserID: "u1", Fingerprint: "fp_existing"})

	dec := EvaluatePolicy(Policy{}, store, "u1", "fp_existing")
	if dec.IsNewDevice {
		t.Error("existing device should not be new")
	}

	dec2 := EvaluatePolicy(Policy{}, store, "u1", "fp_new_device")
	if !dec2.IsNewDevice {
		t.Error("unseen device should be new")
	}
}

func TestEvaluatePolicy_DeviceCount(t *testing.T) {
	store := NewMemoryStore()
	_ = store.Upsert(nil, &Device{UserID: "u1", Fingerprint: "fp1"})
	_ = store.Upsert(nil, &Device{UserID: "u1", Fingerprint: "fp2"})

	dec := EvaluatePolicy(Policy{}, store, "u1", "fp3")
	if dec.CurrentDeviceCount != 2 {
		t.Errorf("device count = %d, want 2", dec.CurrentDeviceCount)
	}
}
