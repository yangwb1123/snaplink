package serverbuildauthn

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/authenticators"
	postgresbackend "github.com/snaplink/sso/infrastructure/postgres"
	"github.com/snaplink/sso/shared/security"
)

// noopReplay is an authReplayStoreFn stand-in for tests that don't care
// about replay-store wiring itself — the memory default from
// newAuthReplayStore, resolved once and reused.
func noopReplay() authReplayStoreFn { return newAuthReplayStore(config.JTIReplayConfig{}, nil) }

func TestAppendKeyPairAuthenticator_NilDisabledAndEnabled(t *testing.T) {
	t.Parallel()
	if got, err := appendKeyPairAuthenticator(nil, nil, noopReplay(), testLogger()); err != nil || len(got) != 0 {
		t.Fatalf("nil config: got=%v err=%v", got, err)
	}
	if got, err := appendKeyPairAuthenticator(nil, &config.KeyPairConfig{Enabled: false}, noopReplay(), testLogger()); err != nil || len(got) != 0 {
		t.Fatalf("disabled config: got=%v err=%v", got, err)
	}
	_, path := writeEd25519PubKeyFixture(t)
	a := &config.KeyPairConfig{
		Enabled: true,
		PublicKeys: []config.KeyPairPublicKeyConfig{
			{KeyID: "svc-1", PublicKeyFile: path, SubjectID: "u1"},
			{KeyID: "missing-fields"},                                           // skipped
			{KeyID: "bad-file", PublicKeyFile: "/no/such/key", SubjectID: "u2"}, // skipped
		},
	}
	got, err := appendKeyPairAuthenticator(nil, a, noopReplay(), testLogger())
	if err != nil || len(got) != 1 || got[0].Name() != authenticators.MethodKeyPair {
		t.Fatalf("got=%v err=%v, want one %q authenticator (bad seed entries skipped)", got, err, authenticators.MethodKeyPair)
	}
}

func TestAppendKeyPairAuthenticator_ReplayErrorPropagates(t *testing.T) {
	t.Parallel()
	// A replay fn that always errors proves appendKeyPairAuthenticator
	// surfaces the failure rather than silently wiring a nil nonce store.
	var errReplay authReplayStoreFn = func() (security.JTIReplayStore, string, error) {
		return nil, "", errAlwaysFails
	}
	if _, err := appendKeyPairAuthenticator(nil, &config.KeyPairConfig{Enabled: true}, errReplay, testLogger()); err == nil {
		t.Fatal("expected error: replay store resolution failed")
	}
}

func TestAppendCertificateAuthenticator_NilDisabledAndEnabled(t *testing.T) {
	t.Parallel()
	if got := appendCertificateAuthenticator(nil, nil, testLogger()); len(got) != 0 {
		t.Fatalf("nil config: got=%v", got)
	}
	if got := appendCertificateAuthenticator(nil, &config.CertificateConfig{Enabled: false}, testLogger()); len(got) != 0 {
		t.Fatalf("disabled config: got=%v", got)
	}
	caPEM, _ := makeSelfSignedCAFixture(t, "test-ca")
	caPath := writeFile(t, "ca.pem", string(caPEM))
	got := appendCertificateAuthenticator(nil, &config.CertificateConfig{Enabled: true, TrustedCAFiles: []string{caPath}}, testLogger())
	if len(got) != 1 || got[0].Name() != authenticators.MethodCertificate {
		t.Fatalf("got=%v, want one %q authenticator", got, authenticators.MethodCertificate)
	}
}

// TestAppendCertificateAuthenticator_BadTrustedCAFileIsSkippedNotFatal proves
// the "fail soft" contract documented on appendCertificateAuthenticator: a
// bad trusted_ca_files entry logs + returns auths UNCHANGED (no authenticator
// added), it does not propagate an error up to BuildAuthenticators.
func TestAppendCertificateAuthenticator_BadTrustedCAFileIsSkippedNotFatal(t *testing.T) {
	t.Parallel()
	got := appendCertificateAuthenticator(nil, &config.CertificateConfig{
		Enabled:        true,
		TrustedCAFiles: []string{"/no/such/ca.pem"},
	}, testLogger())
	if len(got) != 0 {
		t.Fatalf("got=%v, want no authenticator appended when trusted_ca_files fails to load", got)
	}
}

func TestAppendCertificateAuthenticator_BadIntermediateFileStillAddsAuthenticator(t *testing.T) {
	t.Parallel()
	caPEM, _ := makeSelfSignedCAFixture(t, "test-ca")
	caPath := writeFile(t, "ca.pem", string(caPEM))
	got := appendCertificateAuthenticator(nil, &config.CertificateConfig{
		Enabled:           true,
		TrustedCAFiles:    []string{caPath},
		IntermediateFiles: []string{"/no/such/intermediate.pem"},
	}, testLogger())
	// A bad intermediate is logged + skipped — the root CA trust is still
	// good, so the authenticator is added regardless (unlike a bad root CA).
	if len(got) != 1 {
		t.Fatalf("got=%v, want the authenticator still appended despite a bad intermediate file", got)
	}
}

func TestAppendTOTPAuthenticator_NilAndDisabledAreNoOps(t *testing.T) {
	t.Parallel()
	auths, totpAuth, store, err := appendTOTPAuthenticator(nil, nil, noopReplay(), nil, postgresbackend.Dialect(""), testLogger())
	if err != nil || len(auths) != 0 || totpAuth != nil || store != nil {
		t.Fatalf("nil config: auths=%v totpAuth=%v store=%v err=%v", auths, totpAuth, store, err)
	}
	auths, totpAuth, store, err = appendTOTPAuthenticator(nil, &config.TOTPConfig{Enabled: false}, noopReplay(), nil, postgresbackend.Dialect(""), testLogger())
	if err != nil || len(auths) != 0 || totpAuth != nil || store != nil {
		t.Fatalf("disabled config: auths=%v totpAuth=%v store=%v err=%v", auths, totpAuth, store, err)
	}
}

func TestAppendTOTPAuthenticator_MemoryDefault(t *testing.T) {
	t.Parallel()
	auths, totpAuth, store, err := appendTOTPAuthenticator(nil, &config.TOTPConfig{Enabled: true}, noopReplay(), nil, postgresbackend.Dialect(""), testLogger())
	if err != nil {
		t.Fatalf("appendTOTPAuthenticator: %v", err)
	}
	if len(auths) != 1 || auths[0].Name() != authenticators.MethodTOTP {
		t.Fatalf("auths=%v, want one %q authenticator", auths, authenticators.MethodTOTP)
	}
	if totpAuth == nil || store == nil {
		t.Fatalf("totpAuth=%v store=%v, want both non-nil", totpAuth, store)
	}
}

func TestBuildTOTPEnrollmentStore_InfersSqliteFromDSNThenMemoryThenPostgres(t *testing.T) {
	t.Parallel()
	// Empty backend + no DSN -> memory.
	auth, store, err := buildTOTPEnrollmentStore(&config.TOTPConfig{}, nil, postgresbackend.Dialect(""), nil, testLogger())
	if err != nil || auth == nil || store == nil {
		t.Fatalf("memory inference: auth=%v store=%v err=%v", auth, store, err)
	}
	// Empty backend + a DSN set -> sqlite inferred.
	dsn := "file:" + filepath.Join(t.TempDir(), "totp.db") + "?_journal=WAL"
	auth, store, err = buildTOTPEnrollmentStore(&config.TOTPConfig{SQLiteDSN: dsn}, nil, postgresbackend.Dialect(""), nil, testLogger())
	if err != nil || auth == nil || store == nil {
		t.Fatalf("sqlite inference: auth=%v store=%v err=%v", auth, store, err)
	}
	// Explicit sqlite backend without a DSN errors.
	if _, _, err := buildTOTPEnrollmentStore(&config.TOTPConfig{Backend: "sqlite"}, nil, postgresbackend.Dialect(""), nil, testLogger()); err == nil {
		t.Fatal("expected error: sqlite backend requires sqlite_dsn")
	}
	// postgres backend without a pool errors.
	if _, _, err := buildTOTPEnrollmentStore(&config.TOTPConfig{Backend: "postgres"}, nil, postgresbackend.Dialect(""), nil, testLogger()); err == nil {
		t.Fatal("expected error: postgres backend without a shared pool")
	}
	// Unknown backend errors.
	if _, _, err := buildTOTPEnrollmentStore(&config.TOTPConfig{Backend: "carrier-pigeon"}, nil, postgresbackend.Dialect(""), nil, testLogger()); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestAppendOIDCFederationAuthenticators_NilAndInvalidEntriesSkipped(t *testing.T) {
	t.Parallel()
	if got := appendOIDCFederationAuthenticators(nil, nil, testLogger()); len(got) != 0 {
		t.Fatalf("nil feds: got=%v", got)
	}
	feds := []*config.OIDCFederationAuthConfig{
		nil,                  // skipped
		{Name: "incomplete"}, // fails NewOIDCFederationAuthenticator validation -> skipped
		{
			Name: "okta", AuthorizationEndpoint: "https://okta.example.com/authorize",
			TokenEndpoint: "https://okta.example.com/token",
			ClientID:      "cid", ClientSecret: "csecret",
			RedirectURI: "https://sso.example.com/callback",
		},
	}
	got := appendOIDCFederationAuthenticators(nil, feds, testLogger())
	if len(got) != 1 || got[0].Name() != "okta" {
		t.Fatalf("got=%v, want exactly the one valid 'okta' entry", got)
	}
}

// errAlwaysFails is a sentinel for the replay-failure test above.
var errAlwaysFails = errors.New("replay store unavailable")
