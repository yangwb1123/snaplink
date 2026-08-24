//go:build !no_kms_gcpkms

package gcpkms

import (
	"crypto"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/ssoext"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// TestBuild_WiresHostDepsAndKeyName proves the factory adaptation: Build
// validates and constructs the signer over an injected kmsClient fake (the
// vendor client a fork's factory closes over), returns it as a
// crypto.Signer with the key-version name as the kid, and embeds the
// host-API Deps bundle — so a fork's factory maps
// `gcpkms.Build(gcpkms.Deps{ExternalSignerDeps: d}, client, keyVersion)`
// straight onto ssoext.ExternalSignerFactory — the ldap/radius Build
// pattern (no field-for-field copy; the embedding keeps the field names).
func TestBuild_WiresHostDepsAndKeyName(t *testing.T) {
	t.Parallel()
	keyName := "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
	res, err := Build(Deps{
		ExternalSignerDeps: ssoext.ExternalSignerDeps{Logger: spi.NopLogger{}},
	}, newFakeECKMS(t), keyName)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if res.Signer == nil {
		t.Fatal("Build produced a nil signer")
	}
	if _, ok := res.Signer.(crypto.Signer); !ok {
		t.Errorf("BuildResult.Signer is %T, want a crypto.Signer", res.Signer)
	}
	if res.KeyID != keyName {
		t.Errorf("KeyID = %q, want the key version name %q", res.KeyID, keyName)
	}
}

// TestBuild_RejectsBadArgsFailsClosed proves a bad construction fails the
// operator's boot CLOSED through Build, exactly as through New.
func TestBuild_RejectsBadArgsFailsClosed(t *testing.T) {
	t.Parallel()
	keyName := "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
	if _, err := Build(Deps{}, nil, keyName); err == nil {
		t.Fatal("Build succeeded with a nil KMS client; want a validation error")
	}
	if _, err := Build(Deps{}, newFakeECKMS(t), ""); err == nil {
		t.Fatal("Build succeeded with an empty key version name; want a validation error")
	}
}
