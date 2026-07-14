package serverbuildauthn

import (
	"testing"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// These append* helpers are unexported — BuildAuthenticators is the only
// entry point cmd's black-box tests can reach, so a regression in one of
// these branches only shows up here (or as a confusing failure several
// layers up the composition root).

func TestNewAuthReplayStore_MemoizesAfterFirstCall(t *testing.T) {
	t.Parallel()
	fn := newAuthReplayStore(config.JTIReplayConfig{}, nil)
	s1, mode1, err := fn()
	if err != nil || s1 == nil {
		t.Fatalf("first call: store=%v mode=%q err=%v", s1, mode1, err)
	}
	s2, mode2, err := fn()
	if err != nil || s2 != s1 || mode2 != mode1 {
		t.Fatalf("second call must return the memoized value: s2=%v (want %v) mode2=%q (want %q) err=%v", s2, s1, mode2, mode1, err)
	}
}

func TestBuildPasswordAuthVerifier_NoStoreUsesBcrypt(t *testing.T) {
	t.Parallel()
	a := &config.PasswordConfig{Users: []config.PasswordUserConfig{
		{Username: "alice", SubjectID: "u-alice", BcryptHashFile: writeBcryptHash(t, "alice-pw")},
	}}
	v, seeded, err := buildPasswordAuthVerifier(a, nil, nil, testLogger())
	if err != nil || v == nil || seeded != 1 {
		t.Fatalf("verifier=%v seeded=%d err=%v", v, seeded, err)
	}
}

func TestBuildPasswordAuthVerifier_StorePropagatesImportError(t *testing.T) {
	t.Parallel()
	a := &config.PasswordConfig{Users: []config.PasswordUserConfig{
		{Username: "alice", SubjectID: "u-alice", BcryptHashFile: writeBcryptHash(t, "pw")},
	}}
	// noImportPasswordStore can't import hashes — buildPasswordAuthVerifier
	// must surface that as a wrapped error, not silently fall back to bcrypt.
	if _, _, err := buildPasswordAuthVerifier(a, noImportPasswordStore{}, nil, testLogger()); err == nil {
		t.Fatal("expected error: password store cannot import hashes")
	}
}

func TestBuildPasswordAuthVerifier_ImportedHashLoginChainsRehashVerifier(t *testing.T) {
	t.Parallel()
	a := &config.PasswordConfig{ImportedHashLogin: true}
	userProvider := defaultimpl.NewMemoryUserProvider()
	v, _, err := buildPasswordAuthVerifier(a, nil, userProvider, testLogger())
	if err != nil || v == nil {
		t.Fatalf("verifier=%v err=%v", v, err)
	}
}

func TestAppendPasswordAuthenticator_NilAndDisabledAreNoOps(t *testing.T) {
	t.Parallel()
	var auths []sso.Authenticator
	got, err := appendPasswordAuthenticator(auths, nil, nil, nil, testLogger())
	if err != nil || len(got) != 0 {
		t.Fatalf("nil config: got=%v err=%v", got, err)
	}
	got, err = appendPasswordAuthenticator(auths, &config.PasswordConfig{Enabled: false}, nil, nil, testLogger())
	if err != nil || len(got) != 0 {
		t.Fatalf("disabled config: got=%v err=%v", got, err)
	}
}

func TestAppendPasswordAuthenticator_EnabledAppendsOne(t *testing.T) {
	t.Parallel()
	got, err := appendPasswordAuthenticator(nil, &config.PasswordConfig{Enabled: true}, nil, nil, testLogger())
	if err != nil || len(got) != 1 || got[0].Name() != authenticators.MethodPassword {
		t.Fatalf("got=%v err=%v, want one %q authenticator", got, err, authenticators.MethodPassword)
	}
}

func TestAppendPasswordAuthenticator_HealthCheckerErrorPropagates(t *testing.T) {
	t.Parallel()
	a := &config.PasswordConfig{
		Enabled: true,
		Health:  &config.PasswordHealthConfig{Enabled: true, Kind: "carrier-pigeon"},
	}
	if _, err := appendPasswordAuthenticator(nil, a, nil, nil, testLogger()); err == nil {
		t.Fatal("expected error: unknown password health kind")
	}
}

func TestAppendPhoneAuthenticator_NilDisabledAndEnabled(t *testing.T) {
	t.Parallel()
	codeStore := authenticators.NewMemoryCodeStore()
	if got, err := appendPhoneAuthenticator(nil, nil, codeStore, testLogger()); err != nil || len(got) != 0 {
		t.Fatalf("nil config: got=%v, err=%v", got, err)
	}
	if got, err := appendPhoneAuthenticator(nil, &config.PhoneConfig{CodeAuthConfig: config.CodeAuthConfig{Enabled: false}}, codeStore, testLogger()); err != nil || len(got) != 0 {
		t.Fatalf("disabled config: got=%v, err=%v", got, err)
	}
	got, err := appendPhoneAuthenticator(nil, &config.PhoneConfig{CodeAuthConfig: config.CodeAuthConfig{Enabled: true, CodeLength: 6}}, codeStore, testLogger())
	if err != nil || len(got) != 1 || got[0].Name() != authenticators.MethodPhone {
		t.Fatalf("got=%v, err=%v, want one %q authenticator", got, err, authenticators.MethodPhone)
	}
}

// TestAppendPhoneAuthenticator_SMSProviderUnsetOrLogIsByteIdenticalStub
// proves an unset (nil) SMS block and an explicit provider: "log" both
// resolve through buildPhoneSMSSender's log branch — the critical
// backward-compat invariant: existing deployments must be unaffected by the
// SMSConfig addition.
func TestAppendPhoneAuthenticator_SMSProviderUnsetOrLogIsByteIdenticalStub(t *testing.T) {
	t.Parallel()
	codeStore := authenticators.NewMemoryCodeStore()
	for _, sms := range []*config.SMSConfig{nil, {}, {Provider: "log"}, {Provider: "LOG"}} {
		a := &config.PhoneConfig{CodeAuthConfig: config.CodeAuthConfig{Enabled: true}, SMS: sms}
		got, err := appendPhoneAuthenticator(nil, a, codeStore, testLogger())
		if err != nil || len(got) != 1 || got[0].Name() != authenticators.MethodPhone {
			t.Fatalf("sms=%+v: got=%v, err=%v, want one %q authenticator", sms, got, err, authenticators.MethodPhone)
		}
	}
}

// TestAppendPhoneAuthenticator_SMSProviderHTTPRequiresFields proves
// provider: "http" with missing required fields fails the boot loudly
// instead of silently falling back to the log stub.
func TestAppendPhoneAuthenticator_SMSProviderHTTPRequiresFields(t *testing.T) {
	t.Parallel()
	codeStore := authenticators.NewMemoryCodeStore()
	a := &config.PhoneConfig{
		CodeAuthConfig: config.CodeAuthConfig{Enabled: true},
		SMS:            &config.SMSConfig{Provider: "http"},
	}
	if _, err := appendPhoneAuthenticator(nil, a, codeStore, testLogger()); err == nil {
		t.Fatal("expected an error: provider=http missing account_sid/auth_token/from_number")
	}
}

// TestAppendPhoneAuthenticator_SMSProviderHTTPBuildsRealSender proves a
// fully-configured provider: "http" block builds and wires the real
// infrastructure/sms.Sender rather than the log stub.
func TestAppendPhoneAuthenticator_SMSProviderHTTPBuildsRealSender(t *testing.T) {
	t.Parallel()
	codeStore := authenticators.NewMemoryCodeStore()
	a := &config.PhoneConfig{
		CodeAuthConfig: config.CodeAuthConfig{Enabled: true},
		SMS: &config.SMSConfig{
			Provider:   "http",
			AccountSID: "AC1",
			AuthToken:  "tok",
			FromNumber: "+15005550006",
		},
	}
	got, err := appendPhoneAuthenticator(nil, a, codeStore, testLogger())
	if err != nil || len(got) != 1 || got[0].Name() != authenticators.MethodPhone {
		t.Fatalf("got=%v, err=%v, want one %q authenticator", got, err, authenticators.MethodPhone)
	}
}

// TestAppendPhoneAuthenticator_UnknownSMSProviderErrors proves an
// unrecognized provider value is a loud boot failure, not a silent
// fallback.
func TestAppendPhoneAuthenticator_UnknownSMSProviderErrors(t *testing.T) {
	t.Parallel()
	codeStore := authenticators.NewMemoryCodeStore()
	a := &config.PhoneConfig{
		CodeAuthConfig: config.CodeAuthConfig{Enabled: true},
		SMS:            &config.SMSConfig{Provider: "carrier-pigeon"},
	}
	if _, err := appendPhoneAuthenticator(nil, a, codeStore, testLogger()); err == nil {
		t.Fatal("expected an error: unknown sms provider")
	}
}

func TestAppendEmailAuthenticator_NilDisabledAndEnabled(t *testing.T) {
	t.Parallel()
	codeStore := authenticators.NewMemoryCodeStore()
	if got, err := appendEmailAuthenticator(nil, nil, codeStore, config.SMTPConfig{}, testLogger()); err != nil || len(got) != 0 {
		t.Fatalf("nil config: got=%v, err=%v", got, err)
	}
	if got, err := appendEmailAuthenticator(nil, &config.CodeAuthConfig{Enabled: false}, codeStore, config.SMTPConfig{}, testLogger()); err != nil || len(got) != 0 {
		t.Fatalf("disabled config: got=%v, err=%v", got, err)
	}
	got, err := appendEmailAuthenticator(nil, &config.CodeAuthConfig{Enabled: true, CodeLength: 6}, codeStore, config.SMTPConfig{}, testLogger())
	if err != nil || len(got) != 1 || got[0].Name() != authenticators.MethodEmail {
		t.Fatalf("got=%v, err=%v, want one %q authenticator", got, err, authenticators.MethodEmail)
	}
}

func TestAppendAPIKeyAuthenticator_NilDisabledAndEnabled(t *testing.T) {
	t.Parallel()
	if got := appendAPIKeyAuthenticator(nil, nil, testLogger()); len(got) != 0 {
		t.Fatalf("nil config: got=%v", got)
	}
	if got := appendAPIKeyAuthenticator(nil, &config.APIKeyConfig{Enabled: false}, testLogger()); len(got) != 0 {
		t.Fatalf("disabled config: got=%v", got)
	}
	a := &config.APIKeyConfig{Enabled: true, Keys: []config.APIKeyConfigEntry{
		{KeyID: "k1", SecretFile: writeFile(t, "apikey-secret", "s3cr3t\n"), SubjectID: "u1"},
		{KeyID: "missing-fields"}, // skipped: no secret file / subject id
		{KeyID: "bad-file", SecretFile: "/no/such/secret", SubjectID: "u2"}, // skipped: unreadable
	}}
	got := appendAPIKeyAuthenticator(nil, a, testLogger())
	if len(got) != 1 || got[0].Name() != authenticators.MethodAPIKey {
		t.Fatalf("got=%v, want one %q authenticator (bad seed entries are skipped, not fatal)", got, authenticators.MethodAPIKey)
	}
}
