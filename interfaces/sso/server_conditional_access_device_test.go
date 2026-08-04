package sso_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/yangwb1123/snaplink/domains/authenticators/device"
	"github.com/yangwb1123/snaplink/domains/conditionalaccess"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func capDevicePolicyStore(t *testing.T, conditions conditionalaccess.Conditions) conditionalaccess.Store {
	t.Helper()
	store := conditionalaccess.NewMemoryStore()
	err := store.Put(context.Background(), conditionalaccess.Policy{
		Name: "deny-device-signal", Priority: 100, Enabled: true,
		Conditions: conditions,
		Actions:    conditionalaccess.Actions{Deny: true},
	})
	if err != nil {
		t.Fatalf("put policy: %v", err)
	}
	return store
}

func TestConditionalAccess_EnforcesDeviceType(t *testing.T) {
	store := capDevicePolicyStore(t, conditionalaccess.Conditions{DeviceType: "browser"})
	s := rcovNewServer(t, sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true}))
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0 Safari/537.36"

	status, out := capPostJSONWithHeader(t, s.http.URL+"/auth/login", "User-Agent", ua, capLoginBody())
	if status != http.StatusForbidden || out["error"] != "conditional_access_denied" {
		t.Fatalf("device-type policy status=%d body=%v, want 403 conditional_access_denied", status, out)
	}
}

func TestConditionalAccess_EnforcesTrackedDeviceSignals(t *testing.T) {
	t.Run("trust_level", func(t *testing.T) {
		devices := device.NewMemoryStore()
		seedCAPDevice(t, devices, "trusted-device", "", 0.9, 10)
		store := capDevicePolicyStore(t, conditionalaccess.Conditions{DeviceTrustLevel: 0.8})
		s := rcovNewServer(t, sso.WithDeviceStore(devices),
			sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true}))

		status, out := capPostJSONWithHeader(t, s.http.URL+"/auth/login", "X-Device-Id", "trusted-device", capLoginBody())
		if status != http.StatusForbidden || out["error"] != "conditional_access_denied" {
			t.Fatalf("trust-level policy status=%d body=%v, want denial", status, out)
		}
	})

	t.Run("new_device", func(t *testing.T) {
		devices := device.NewMemoryStore()
		store := capDevicePolicyStore(t, conditionalaccess.Conditions{IsNewDevice: true})
		s := rcovNewServer(t, sso.WithDeviceStore(devices),
			sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true}))

		status, out := capPostJSONWithHeader(t, s.http.URL+"/auth/login", "X-Device-Id", "first-seen", capLoginBody())
		if status != http.StatusForbidden || out["error"] != "conditional_access_denied" {
			t.Fatalf("new-device policy status=%d body=%v, want denial", status, out)
		}
	})

	t.Run("new_location", func(t *testing.T) {
		devices := device.NewMemoryStore()
		seedCAPDevice(t, devices, "moving-device", "198.51.100.8", 0.7, 3)
		store := capDevicePolicyStore(t, conditionalaccess.Conditions{IsNewLocation: true})
		s := rcovNewServer(t, sso.WithDeviceStore(devices),
			sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true}))

		status, out := capPostJSONWithHeader(t, s.http.URL+"/auth/login", "X-Device-Id", "moving-device", capLoginBody())
		if status != http.StatusForbidden || out["error"] != "conditional_access_denied" {
			t.Fatalf("new-location policy status=%d body=%v, want denial", status, out)
		}
	})
}

type capFailingDeviceStore struct{ *device.MemoryStore }

func (capFailingDeviceStore) GetByFingerprint(context.Context, string, string) (*device.Device, error) {
	return nil, errors.New("device inventory unavailable")
}

func TestConditionalAccess_DeviceTrackingOutageFailsOpen(t *testing.T) {
	devices := capFailingDeviceStore{MemoryStore: device.NewMemoryStore()}
	store := capDevicePolicyStore(t, conditionalaccess.Conditions{IsNewDevice: true})
	s := rcovNewServer(t, sso.WithDeviceStore(devices),
		sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true}))

	status, out := capPostJSONWithHeader(t, s.http.URL+"/auth/login", "X-Device-Id", "unknown", capLoginBody())
	if status != http.StatusOK || out["access_token"] == nil {
		t.Fatalf("device-store outage status=%d body=%v, want successful login", status, out)
	}
}

func seedCAPDevice(t *testing.T, store device.Store, fingerprint, lastIP string, trustScore float64, loginCount int) {
	t.Helper()
	err := store.Upsert(context.Background(), &device.Device{
		UserID: rcovUser, Fingerprint: fingerprint, LastIP: lastIP,
		TrustScore: trustScore, LoginCount: loginCount,
	})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
}
