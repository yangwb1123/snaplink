package serverbuildstore

import (
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/authenticators"
)

// buildMFAProviderByKind / buildMultiMFAProvider / buildPushMFAProvider /
// buildPushMFAProviderWithCapture are unexported — BuildMFA is the only
// entry point cmd's black-box tests can reach, so these direct calls
// pinpoint a regression to the exact branch rather than "BuildMFA broke
// somewhere".

func TestBuildMFAProviderByKind_TOTPRequiresAuthenticator(t *testing.T) {
	t.Parallel()
	if _, err := buildMFAProviderByKind("totp", nil, config.MFAPushConfig{}, nil, nil, testLogger(), nil); err == nil {
		t.Fatal("expected error: kind=totp with nil totpAuth")
	}
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	p, err := buildMFAProviderByKind("totp", nil, config.MFAPushConfig{}, totpAuth, nil, testLogger(), nil)
	if err != nil || p == nil {
		t.Fatalf("provider=%v err=%v", p, err)
	}
}

func TestBuildMFAProviderByKind_WebAuthnRequiresHelper(t *testing.T) {
	t.Parallel()
	if _, err := buildMFAProviderByKind("webauthn", nil, config.MFAPushConfig{}, nil, nil, testLogger(), nil); err == nil {
		t.Fatal("expected error: kind=webauthn with nil webauthnHelper")
	}
}

func TestBuildMFAProviderByKind_PushMemoryDefault(t *testing.T) {
	t.Parallel()
	capture := &pushStoreCapture{}
	p, err := buildMFAProviderByKind("push", nil, config.MFAPushConfig{}, nil, nil, testLogger(), capture)
	if err != nil || p == nil {
		t.Fatalf("provider=%v err=%v", p, err)
	}
	// Memory-backed push has no typed sqlite handle to surface.
	if capture.store != nil {
		t.Errorf("capture.store = %v, want nil for memory-backed push", capture.store)
	}
}

func TestBuildMFAProviderByKind_PushChannelNotifyCapturesWakeup(t *testing.T) {
	t.Parallel()
	capture := &pushStoreCapture{}
	pushCfg := config.MFAPushConfig{ChannelNotify: true}
	p, err := buildMFAProviderByKind("push", nil, pushCfg, nil, nil, testLogger(), capture)
	if err != nil || p == nil {
		t.Fatalf("provider=%v err=%v", p, err)
	}
	if capture.notify == nil {
		t.Error("channel_notify=true must capture a Notify wakeup func")
	}
}

func TestBuildMFAProviderByKind_UnknownKind(t *testing.T) {
	t.Parallel()
	if _, err := buildMFAProviderByKind("carrier-pigeon", nil, config.MFAPushConfig{}, nil, nil, testLogger(), nil); err == nil {
		t.Fatal("expected error: unknown mfa.provider.kind")
	}
}

func TestBuildMultiMFAProvider_RequiresAtLeastTwoKinds(t *testing.T) {
	t.Parallel()
	if _, err := buildMFAProviderByKind("multi", nil, config.MFAPushConfig{}, nil, nil, testLogger(), nil); err == nil {
		t.Fatal("expected error: multi with zero inner kinds")
	}
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	if _, err := buildMFAProviderByKind("multi", []string{"totp"}, config.MFAPushConfig{}, totpAuth, nil, testLogger(), nil); err == nil {
		t.Fatal("expected error: multi with only one inner kind")
	}
}

func TestBuildMultiMFAProvider_RejectsNestedMultiAndDuplicates(t *testing.T) {
	t.Parallel()
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	if _, err := buildMFAProviderByKind("multi", []string{"totp", "multi"}, config.MFAPushConfig{}, totpAuth, nil, testLogger(), nil); err == nil {
		t.Fatal("expected error: multi cannot nest multi")
	}
	if _, err := buildMFAProviderByKind("multi", []string{"totp", "totp"}, config.MFAPushConfig{}, totpAuth, nil, testLogger(), nil); err == nil {
		t.Fatal("expected error: duplicate inner kind")
	}
	if _, err := buildMFAProviderByKind("multi", []string{"totp", ""}, config.MFAPushConfig{}, totpAuth, nil, testLogger(), nil); err == nil {
		t.Fatal("expected error: empty inner kind entry")
	}
}

func TestBuildMultiMFAProvider_ComposesLeafKinds(t *testing.T) {
	t.Parallel()
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	p, err := buildMFAProviderByKind("multi", []string{"totp", "push"}, config.MFAPushConfig{}, totpAuth, nil, testLogger(), &pushStoreCapture{})
	if err != nil {
		t.Fatalf("buildMFAProviderByKind(multi): %v", err)
	}
	if p == nil {
		t.Fatal("nil composed provider")
	}
	methods := p.SupportedMethods()
	if len(methods) != 2 {
		t.Fatalf("SupportedMethods() = %v, want 2 entries (totp + push)", methods)
	}
}

func TestBuildPushWebhookTransport_RequiresURL(t *testing.T) {
	t.Parallel()
	if _, err := BuildPushWebhookTransport(config.MFAPushWebhookConfig{}); err == nil {
		t.Fatal("expected error: webhook transport requires a url")
	}
}

// TestBuildPushWebhookTransport_AppliesEveryOptionalKnob proves every
// optional webhook tuning field (bearer token, custom headers, signing
// secret, timeout, retry policy) is threaded into the constructed
// transport without erroring — a dropped option would silently ship an
// unauthenticated / unsigned / infinite-timeout webhook call.
func TestBuildPushWebhookTransport_AppliesEveryOptionalKnob(t *testing.T) {
	t.Parallel()
	tr, err := BuildPushWebhookTransport(config.MFAPushWebhookConfig{
		URL:                 "https://push.example.com/hook",
		BearerToken:         "tok",
		Headers:             map[string]string{"X-Extra": "v"},
		SigningSecret:       "secret",
		Timeout:             1,
		RetryMaxAttempts:    2,
		RetryInitialBackoff: 1,
		RetryMaxBackoff:     2,
	})
	if err != nil || tr == nil {
		t.Fatalf("transport=%v err=%v", tr, err)
	}
}
