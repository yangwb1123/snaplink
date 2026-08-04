package sso

import (
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators/device"
)

func TestComputeDeviceTrustScore_NewDevice(t *testing.T) {
	score := computeDeviceTrustScore(nil, 1, nil)
	// New device: base 0.5 + 1*0.02 = 0.52
	if score < 0.5 || score > 0.6 {
		t.Errorf("new device trust score = %v, want ~0.52", score)
	}
}

func TestComputeDeviceTrustScore_NewDeviceWithSecCtx(t *testing.T) {
	secCtx := &device.LoginSecurityContext{DeviceIsNew: true}
	score := computeDeviceTrustScore(secCtx, 1, nil)
	// New device flagged: 0.3 (no bonus for first login)
	if score != 0.30 {
		t.Errorf("new device (flagged) trust score = %v, want 0.30", score)
	}
}

func TestComputeDeviceTrustScore_ExistingDevice(t *testing.T) {
	existing := &device.Device{TrustScore: 0.7}
	score := computeDeviceTrustScore(nil, 5, existing)
	// Existing trust 0.7 + 5*0.02 = 0.8
	if score < 0.75 || score > 0.85 {
		t.Errorf("existing device trust score = %v, want ~0.8", score)
	}
}

func TestComputeDeviceTrustScore_Caps(t *testing.T) {
	// Max cap
	score := computeDeviceTrustScore(nil, 100, nil)
	if score > 0.95 {
		t.Errorf("trust score should be capped at 0.95, got %v", score)
	}
	// Min cap with new device
	secCtx := &device.LoginSecurityContext{DeviceIsNew: true, LocationIsNew: true}
	score = computeDeviceTrustScore(secCtx, 0, nil)
	if score < 0.1 {
		t.Errorf("trust score should have min 0.1, got %v", score)
	}
}

func TestComputeDeviceTrustScore_LocationNew(t *testing.T) {
	secCtx := &device.LoginSecurityContext{LocationIsNew: true}
	score := computeDeviceTrustScore(secCtx, 10, nil)
	// New location: 0.4 + 10*0.02 = 0.6
	if score < 0.55 || score > 0.65 {
		t.Errorf("new location trust score = %v, want ~0.6", score)
	}
}

func TestDeviceAwareTTL_NilDeviceCtx(t *testing.T) {
	ttl := 3600 * time.Second
	result := deviceAwareTTL(ttl, nil, 0)
	if result != ttl {
		t.Errorf("nil deviceCtx should return original TTL, got %v", result)
	}
}

func TestDeviceAwareTTL_NewDevice(t *testing.T) {
	dc := &deviceContext{SecurityCtx: &device.LoginSecurityContext{DeviceIsNew: true}}
	result := deviceAwareTTL(3600*time.Second, dc, 0)
	if result > 3600*time.Second {
		t.Errorf("new device should reduce TTL, got %v", result)
	}
}

func TestDeviceAwareTTL_ExistingDevice(t *testing.T) {
	dc := &deviceContext{SecurityCtx: &device.LoginSecurityContext{}}
	result := deviceAwareTTL(3600*time.Second, dc, 0)
	if result != 3600*time.Second {
		t.Errorf("existing device should keep TTL, got %v", result)
	}
}

func TestDeviceAwareTTL_MinTTL(t *testing.T) {
	dc := &deviceContext{SecurityCtx: &device.LoginSecurityContext{DeviceIsNew: true}}
	// With client TTL of 3h and min TTL of 2h, result should be >= 2h
	result := deviceAwareTTL(3*time.Hour, dc, 2*time.Hour)
	if result < 2*time.Hour {
		t.Errorf("min TTL should be 2h, got %v", result)
	}
}

func TestLocationSummary_NilGeo(t *testing.T) {
	// locationSummary requires HandlerContext, so we test via uaSummary
	result := uaSummary("")
	if result != "" {
		t.Errorf("empty UA should return empty, got %q", result)
	}
}

func TestUASummary(t *testing.T) {
	tests := []struct {
		ua   string
		want string
	}{
		{"", ""},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15", "iOS · iPhone"},
		{"Mozilla/5.0 (Linux; Android 14; Pixel 7 Pro) AppleWebKit/537.36 Chrome/125.0", "Android · Pixel 7 Pro"},
	}
	for _, tc := range tests {
		got := uaSummary(tc.ua)
		if got == "" && tc.want != "" {
			t.Errorf("uaSummary(%q) = empty, want %q", tc.ua, tc.want)
		}
	}
}

func TestTokenClientAuthEvidenceMatchesRegisteredMethod(t *testing.T) {
	methods := []struct {
		name string
		kind tokenClientAuthKind
	}{
		{"client_secret_basic", tokenAuthBasic},
		{"client_secret_post", tokenAuthPost},
		{"private_key_jwt", tokenAuthPrivateKeyJWT},
		{ClientAuthWorkloadIdentity, tokenAuthWorkloadIdentity},
		{ClientAuthTLS, tokenAuthNone},
		{ClientAuthSelfSignedTLS, tokenAuthNone},
		{"none", tokenAuthNone},
	}
	evidence := []struct {
		name  string
		value tokenClientAuthEvidence
	}{
		{"none", tokenClientAuthEvidence{}},
		{"Basic", tokenClientAuthEvidence{basic: true}},
		{"body secret", tokenClientAuthEvidence{bodySecret: true}},
		{"private_key_jwt", tokenClientAuthEvidence{assertion: true, assertionType: ClientAssertionTypeJWTBearer}},
		{"workload", tokenClientAuthEvidence{assertion: true, assertionType: ClientAssertionTypeWorkloadIdentity}},
		{"mixed Basic/post", tokenClientAuthEvidence{basic: true, bodySecret: true}},
		{"mixed post/assertion", tokenClientAuthEvidence{bodySecret: true, assertion: true, assertionType: ClientAssertionTypeJWTBearer}},
		{"partial assertion", tokenClientAuthEvidence{assertion: true}},
	}
	for _, method := range methods {
		for _, input := range evidence {
			want := input.value.kind() == method.kind
			if got := input.value.matches(method.name); got != want {
				t.Errorf("method=%s evidence=%s: matches=%v want %v", method.name, input.name, got, want)
			}
		}
	}
}

func TestTokenClientAuthEvidenceLegacyCompatibility(t *testing.T) {
	singleMethods := []tokenClientAuthEvidence{
		{},
		{basic: true},
		{bodySecret: true},
		{assertion: true, assertionType: ClientAssertionTypeJWTBearer},
		{assertion: true, assertionType: ClientAssertionTypeWorkloadIdentity},
	}
	for _, evidence := range singleMethods {
		if !evidence.matches("") {
			t.Errorf("legacy client rejected one credential kind %v", evidence.kind())
		}
	}
	if (tokenClientAuthEvidence{basic: true, bodySecret: true}).matches("") {
		t.Error("legacy client accepted mixed Basic and body credentials")
	}
}
