//go:build !no_kms_awskms

package awskms

import (
	"crypto"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/ssoext"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// TestBuild_WiresHostDepsAndKeyID proves the factory adaptation: Build
// validates and constructs the signer over an injected KMSAPI fake (the
// vendor client a fork's factory closes over), returns it as a
// crypto.Signer with the keyID as the kid, and embeds the host-API Deps
// bundle — so a fork's factory maps
// `awskms.Build(awskms.Deps{ExternalSignerDeps: d}, client, keyARN)`
// straight onto ssoext.ExternalSignerFactory — the ldap/radius Build
// pattern (no field-for-field copy; the embedding keeps the field names).
func TestBuild_WiresHostDepsAndKeyID(t *testing.T) {
	t.Parallel()
	keyID := "arn:aws:kms:us-east-1:123456789012:key/11112222-3333-4444-5555-666677778888"
	res, err := Build(Deps{
		ExternalSignerDeps: ssoext.ExternalSignerDeps{Logger: spi.NopLogger{}},
	}, newFakeECKMS(t), keyID)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if res.Signer == nil {
		t.Fatal("Build produced a nil signer")
	}
	if _, ok := res.Signer.(crypto.Signer); !ok {
		t.Errorf("BuildResult.Signer is %T, want a crypto.Signer", res.Signer)
	}
	if res.KeyID != keyID {
		t.Errorf("KeyID = %q, want the key id %q", res.KeyID, keyID)
	}
}

// TestBuild_RejectsBadArgsFailsClosed proves a bad construction fails the
// operator's boot CLOSED through Build, exactly as through New.
func TestBuild_RejectsBadArgsFailsClosed(t *testing.T) {
	t.Parallel()
	if _, err := Build(Deps{}, nil, "arn:aws:kms:us-east-1:1:key/x"); err == nil {
		t.Fatal("Build succeeded with a nil KMS client; want a validation error")
	}
	if _, err := Build(Deps{}, newFakeECKMS(t), ""); err == nil {
		t.Fatal("Build succeeded with an empty key id; want a validation error")
	}
}
