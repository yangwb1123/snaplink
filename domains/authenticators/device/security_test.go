package device

import (
	"testing"
	"time"
)

func TestBuildSecurityContext_NilStore(t *testing.T) {
	ctx := BuildSecurityContext(nil, nil, "u1", "fp1", "1.2.3.4")
	if ctx != nil {
		t.Error("nil store should return nil context")
	}
}

func TestBuildSecurityContext_NewDevice(t *testing.T) {
	store := NewMemoryStore()
	ctx := BuildSecurityContext(store, nil, "u1", "fp_new", "1.2.3.4")
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if !ctx.DeviceIsNew {
		t.Error("new fingerprint should be flagged as new device")
	}
	if ctx.ActiveDevices != 0 {
		t.Errorf("devices = %d, want 0", ctx.ActiveDevices)
	}
}

func TestBuildSecurityContext_ExistingDevice(t *testing.T) {
	store := NewMemoryStore()
	_ = store.Upsert(nil, &Device{
		UserID: "u1", Fingerprint: "fp1",
		LastIP: "10.0.0.1", LastSeenAt: time.Now().Add(-24 * time.Hour),
	})
	// Same IP.
	ctx := BuildSecurityContext(store, nil, "u1", "fp1", "10.0.0.1")
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if ctx.DeviceIsNew {
		t.Error("existing device should not be new")
	}
	if ctx.LocationIsNew {
		t.Error("same IP should not be new location")
	}
	if ctx.ActiveDevices != 1 {
		t.Errorf("devices = %d, want 1", ctx.ActiveDevices)
	}
	if ctx.PreviousLogin == nil {
		t.Fatal("expected previous login info")
	}
	if ctx.PreviousLogin.IP != "10.0.0.1" {
		t.Errorf("previous IP = %q", ctx.PreviousLogin.IP)
	}
}

func TestBuildSecurityContext_NewLocation(t *testing.T) {
	store := NewMemoryStore()
	_ = store.Upsert(nil, &Device{
		UserID: "u1", Fingerprint: "fp1",
		LastIP: "10.0.0.1",
	})
	// Different IP.
	ctx := BuildSecurityContext(store, nil, "u1", "fp1", "20.0.0.1")
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if !ctx.LocationIsNew {
		t.Error("different IP should be flagged as new location")
	}
}

func TestBuildSecurityContext_DeviceSummary(t *testing.T) {
	store := NewMemoryStore()
	_ = store.Upsert(nil, &Device{
		UserID: "u1", Fingerprint: "fp1",
		Platform: "iOS", DeviceName: "iPhone 15 Pro",
		LastIP: "10.0.0.1", LastSeenAt: time.Now(),
	})
	ctx := BuildSecurityContext(store, nil, "u1", "fp1", "10.0.0.1")
	if ctx.PreviousLogin == nil {
		t.Fatal("expected previous login")
	}
	if ctx.PreviousLogin.Device != "iOS · iPhone 15 Pro" {
		t.Errorf("device summary = %q, want iOS · iPhone 15 Pro", ctx.PreviousLogin.Device)
	}
}

func TestBuildSecurityContext_ActiveDevicesCount(t *testing.T) {
	store := NewMemoryStore()
	_ = store.Upsert(nil, &Device{UserID: "u1", Fingerprint: "fp1"})
	_ = store.Upsert(nil, &Device{UserID: "u1", Fingerprint: "fp2"})
	_ = store.Upsert(nil, &Device{UserID: "u2", Fingerprint: "fp_other"})

	ctx := BuildSecurityContext(store, nil, "u1", "fp_new", "1.2.3.4")
	if ctx.ActiveDevices != 2 {
		t.Errorf("devices = %d, want 2", ctx.ActiveDevices)
	}
}

func TestBuildSecurityContext_SessionCount(t *testing.T) {
	store := NewMemoryStore()
	mockCount := 0
	mock := func(userID string) (int, error) {
		mockCount++
		return 3, nil
	}
	ctx := BuildSecurityContext(store, mock, "u1", "fp_new", "1.2.3.4")
	if ctx.ActiveSessions != 3 {
		t.Errorf("sessions = %d, want 3", ctx.ActiveSessions)
	}
}

func TestBuildSecurityContext_FirstLogin_NoPrevious(t *testing.T) {
	store := NewMemoryStore()
	ctx := BuildSecurityContext(store, nil, "u1", "fp_first", "1.2.3.4")
	if ctx.PreviousLogin != nil {
		t.Error("first login should have no previous login")
	}
}

func TestBuildSecurityContext_NilStoreReturnsNil(t *testing.T) {
	ctx := BuildSecurityContext(nil, nil, "u1", "fp", "1.2.3.4")
	if ctx != nil {
		t.Error("expected nil for nil store")
	}
}

func TestDeviceSummary(t *testing.T) {
	tests := []struct {
		name string
		dev  Device
		want string
	}{
		{"iOS iPhone", Device{Platform: "iOS", DeviceName: "iPhone 15 Pro"}, "iOS · iPhone 15 Pro"},
		{"Mac Chrome", Device{BrowserName: "Chrome", Platform: "macOS"}, "macOS · Chrome"},
		{"Unknown", Device{Type: DeviceTypeBrowser, BrowserName: "Firefox"}, "Firefox"},
		{"Platform only", Device{Type: DeviceTypeDesktop, Platform: "Windows"}, "Windows"},
		{"Type only", Device{Type: DeviceTypeMobile}, "mobile"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deviceSummary(&tc.dev)
			if got != tc.want {
				t.Errorf("deviceSummary = %q, want %q", got, tc.want)
			}
		})
	}
}
