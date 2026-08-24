//go:build !no_pkcs11

package pkcs11

import (
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/ssoext"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// TestBuild_EmbedsHostDeps proves the Deps bundle carries the host-API
// seam without a vendor type crossing the module boundary: a fork's factory
// maps `pkcs11.Build(pkcs11.Deps{ExternalSignerDeps: d}, tokenCfg)` straight
// onto ssoext.ExternalSignerFactory — the ldap/radius Build pattern (no
// field-for-field copy; the embedding keeps the field names).
func TestBuild_EmbedsHostDeps(t *testing.T) {
	t.Parallel()
	deps := Deps{
		ExternalSignerDeps: ssoext.ExternalSignerDeps{Logger: spi.NopLogger{}},
	}
	if deps.Logger == nil {
		t.Fatal("embedded ExternalSignerDeps did not carry the Logger through")
	}
}

// TestBuild_RejectsBadConfigFailsClosed proves a bad config fails the
// operator's boot CLOSED through Build, exactly as through New — and BEFORE
// any token I/O (the production New opens the token, so these pure-
// validation failures must not require a live HSM / SoftHSM to trip).
func TestBuild_RejectsBadConfigFailsClosed(t *testing.T) {
	t.Parallel()
	// Empty ModulePath.
	if _, err := Build(Deps{}, Config{}); err == nil {
		t.Fatal("Build succeeded with an empty ModulePath; want a validation error")
	}
	// Neither KeyLabel nor KeyID selects a key object.
	if _, err := Build(Deps{}, Config{ModulePath: "/usr/lib/softhsm/libsofthsm2.so"}); err == nil {
		t.Fatal("Build succeeded with no KeyLabel/KeyID; want a validation error")
	}
}
