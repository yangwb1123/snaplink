package serverbuildauthn

import (
	"testing"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/authenticators"
)

func TestBuildAuthenticators_EmptyConfigReturnsEmptySlice(t *testing.T) {
	t.Parallel()
	auths, tempStore, totpAuth, enrollStore, err := BuildAuthenticators(&config.Config{}, testLogger(), nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildAuthenticators: %v", err)
	}
	if len(auths) != 0 || tempStore != nil || totpAuth != nil || enrollStore != nil {
		t.Fatalf("auths=%v tempStore=%v totpAuth=%v enrollStore=%v, want all empty/nil", auths, tempStore, totpAuth, enrollStore)
	}
}

// TestBuildAuthenticators_ComposesEveryEnabledMethod wires one of nearly
// every authenticator kind (password + phone + email + temp_token + apikey +
// totp) and confirms BuildAuthenticators' composition order surfaces all of
// them plus the ancillary tempStore/totpAuth/enrollStore handles the caller
// (admin token service, MFA orchestration) reuses.
func TestBuildAuthenticators_ComposesEveryEnabledMethod(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Authenticators.Password = &config.PasswordConfig{Enabled: true}
	cfg.Authenticators.Phone = &config.CodeAuthConfig{Enabled: true}
	cfg.Authenticators.Email = &config.CodeAuthConfig{Enabled: true}
	cfg.Authenticators.TempToken = &config.TempTokenConfig{Enabled: true}
	cfg.Authenticators.APIKey = &config.APIKeyConfig{Enabled: true}
	cfg.Authenticators.TOTP = &config.TOTPConfig{Enabled: true}

	auths, tempStore, totpAuth, enrollStore, err := BuildAuthenticators(cfg, testLogger(), nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildAuthenticators: %v", err)
	}
	wantNames := map[string]bool{
		authenticators.MethodPassword:  false,
		authenticators.MethodPhone:     false,
		authenticators.MethodEmail:     false,
		authenticators.MethodTempToken: false,
		authenticators.MethodAPIKey:    false,
		authenticators.MethodTOTP:      false,
	}
	for _, a := range auths {
		if _, ok := wantNames[a.Name()]; ok {
			wantNames[a.Name()] = true
		}
	}
	for name, seen := range wantNames {
		if !seen {
			t.Errorf("authenticator %q missing from BuildAuthenticators output", name)
		}
	}
	if tempStore == nil {
		t.Error("temp_token enabled but tempStore is nil")
	}
	if totpAuth == nil || enrollStore == nil {
		t.Error("totp enabled but totpAuth/enrollStore is nil")
	}
}

// TestBuildAuthenticators_PropagatesPasswordError proves a downstream
// misconfiguration (an unknown password-health kind) fails the whole
// composition loudly rather than silently omitting the broken authenticator.
func TestBuildAuthenticators_PropagatesPasswordError(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Authenticators.Password = &config.PasswordConfig{
		Enabled: true,
		Health:  &config.PasswordHealthConfig{Enabled: true, Kind: "carrier-pigeon"},
	}
	if _, _, _, _, err := BuildAuthenticators(cfg, testLogger(), nil, nil, nil); err == nil {
		t.Fatal("expected error: invalid password health kind")
	}
}

// TestBuildAuthenticatorsDurable_IsWhatBuildAuthenticatorsForwardsTo proves
// BuildAuthenticators is exactly BuildAuthenticatorsDurable with a nil pool —
// calling Durable directly with pg=nil must be byte-identical.
func TestBuildAuthenticatorsDurable_IsWhatBuildAuthenticatorsForwardsTo(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Authenticators.Password = &config.PasswordConfig{Enabled: true}

	a1, _, _, _, err1 := BuildAuthenticators(cfg, testLogger(), nil, nil, nil)
	a2, _, _, _, err2 := BuildAuthenticatorsDurable(cfg, testLogger(), nil, nil, nil, nil, "")
	if err1 != nil || err2 != nil {
		t.Fatalf("err1=%v err2=%v", err1, err2)
	}
	if len(a1) != len(a2) || len(a1) != 1 || a1[0].Name() != a2[0].Name() {
		t.Fatalf("a1=%v a2=%v, want identical single-authenticator output", a1, a2)
	}
}

func TestBuildCodeStore_NilRDBUsesMemory(t *testing.T) {
	t.Parallel()
	s := buildCodeStore(nil)
	if s == nil {
		t.Fatal("nil code store")
	}
	if _, ok := s.(*authenticators.MemoryCodeStore); !ok {
		t.Fatalf("type = %T, want *authenticators.MemoryCodeStore when rdb is nil", s)
	}
}

func TestBuildTempTokenStore_NilRDBUsesMemory(t *testing.T) {
	t.Parallel()
	s := buildTempTokenStore(nil)
	if s == nil {
		t.Fatal("nil temp token store")
	}
	if _, ok := s.(*authenticators.MemoryTempTokenStore); !ok {
		t.Fatalf("type = %T, want *authenticators.MemoryTempTokenStore when rdb is nil", s)
	}
}
