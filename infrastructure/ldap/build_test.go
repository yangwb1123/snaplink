package ldapauth

import (
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/ssoext"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// TestBuild_WiresHostDepsAndConfig proves the factory adaptation: Build
// plumbs the host-API Logger into the authenticator and returns it as an
// sso.Authenticator, so a fork's factory maps `ldapauth.Build(ldapauth.Deps{
// LDAPServerDeps: d}, cfg)` straight onto ssoext.LDAPAuthenticatorSet — the
// SAML-registry pattern (no field-for-field copy; the embedding keeps the
// field names).
func TestBuild_WiresHostDepsAndConfig(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	cfg := Config{
		Name:           "corp-ad",
		URLs:           []string{"ldaps://dir.example.com:636"},
		BaseDN:         "dc=example,dc=com",
		BindDN:         dir.serviceDN,
		BindPassword:   dir.servicePassword,
		UserFilter:     "(&(objectClass=user)(uid=%s))",
		IDAttribute:    "uid",
		GroupAttribute: "memberOf",
	}
	res, err := Build(Deps{
		LDAPServerDeps: ssoext.LDAPServerDeps{Logger: spi.NopLogger{}},
	}, cfg, withDialer(&fakeDialer{dir: dir, requestTO: cfg.requestTimeout()}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(res.Authenticators) != 1 {
		t.Fatalf("Build produced %d authenticators, want 1", len(res.Authenticators))
	}
	if got := res.Authenticators[0].Name(); got != "corp-ad" {
		t.Errorf("authenticator Name = %q, want corp-ad", got)
	}
}

// TestBuild_InvalidConfigFailsClosed proves a bad config fails the operator's
// boot CLOSED through Build, exactly as through New (a directory-auth gate
// with an invalid TLS posture must not start).
func TestBuild_InvalidConfigFailsClosed(t *testing.T) {
	t.Parallel()
	// ldap:// without StartTLS/TLSConfig/AllowInsecure trips the TLS gate.
	if _, err := Build(Deps{}, Config{Name: "broken", URLs: []string{"ldap://dir.example.com:389"}, BaseDN: "dc=example,dc=com"}); err == nil {
		t.Fatal("Build succeeded with a plaintext LDAP config; want a validation error")
	}
}
