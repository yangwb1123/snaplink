//go:build !no_kms_azurekeyvault

package azurekeyvault

import (
	"crypto"
	"crypto/elliptic"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/ssoext"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// TestBuild_WiresHostDepsAndKeyName proves the factory adaptation: Build
// validates and constructs the signer over an injected keyVaultAPI fake
// (the vendor client a fork's factory closes over), returns it as a
// crypto.Signer with the key name as the kid, and embeds the host-API Deps
// bundle — so a fork's factory maps
// `azurekeyvault.Build(azurekeyvault.Deps{ExternalSignerDeps: d}, client,
// "signing-key", keyVersion)` straight onto ssoext.ExternalSignerFactory —
// the ldap/radius Build pattern (no field-for-field copy; the embedding
// keeps the field names).
func TestBuild_WiresHostDepsAndKeyName(t *testing.T) {
	t.Parallel()
	res, err := Build(Deps{
		ExternalSignerDeps: ssoext.ExternalSignerDeps{Logger: spi.NopLogger{}},
	}, newFakeEC(t, elliptic.P256()), "signing-key", "v1")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if res.Signer == nil {
		t.Fatal("Build produced a nil signer")
	}
	if _, ok := res.Signer.(crypto.Signer); !ok {
		t.Errorf("BuildResult.Signer is %T, want a crypto.Signer", res.Signer)
	}
	if res.KeyID != "signing-key" {
		t.Errorf("KeyID = %q, want the key name %q", res.KeyID, "signing-key")
	}
}

// TestBuild_RejectsBadArgsFailsClosed proves a bad construction fails the
// operator's boot CLOSED through Build, exactly as through NewSigner.
func TestBuild_RejectsBadArgsFailsClosed(t *testing.T) {
	t.Parallel()
	if _, err := Build(Deps{}, nil, "signing-key", "v1"); err == nil {
		t.Fatal("Build succeeded with a nil Key Vault client; want a validation error")
	}
	if _, err := Build(Deps{}, newFakeEC(t, elliptic.P256()), "", "v1"); err == nil {
		t.Fatal("Build succeeded with an empty key name; want a validation error")
	}
}
