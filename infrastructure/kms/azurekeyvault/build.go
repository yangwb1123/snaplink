//go:build !no_kms_azurekeyvault

package azurekeyvault

import (
	"crypto"

	"github.com/yangwb1123/snaplink/interfaces/ssoext"
)

// Deps is the ROOT-module-typed dependency bundle Build needs. Every field
// is a stdlib type or a root-module type — there is NO cmd/sso-server
// (package main) type here, because a separate module's package cannot
// import package main. The operator's forked main (which owns the Azure SDK
// client) constructs a Deps from its own logger inside the factory closure
// (see Build's doc for the copy-pasteable wiring).
//
// Deps EMBEDS the standard host-API bundle
// (interfaces/ssoext.ExternalSignerDeps — the exact root-module-typed seam
// the KMS family shares). Embedding (not aliasing) keeps the field names: a
// fork constructs `azurekeyvault.Deps{ExternalSignerDeps: ssoext.ExternalSignerDeps{
// Logger: myLogger}}` (or simply `azurekeyvault.Deps{}` — the zero value is
// valid), mirroring ldapauth.Deps / radiusauth.Deps.
type Deps struct {
	// ExternalSignerDeps carries the operator logger across the module
	// boundary. The built-in signer performs no I/O logging (the
	// instrumentedSigner wrapper in serverbuildsign owns health + metrics
	// logging at the cmd boundary), so Build carries the bundle for shape
	// uniformity with the ldap/radius adapters; a future signer WithLogger
	// option would consume it.
	ssoext.ExternalSignerDeps
}

// BuildResult is everything Build produces: the Key Vault-backed
// crypto.Signer and the kid that names its public key in JWKS + token
// headers (the keyName argument — the stable name an operator pins in JWKS;
// an empty keyVersion signs the vault's current version, but operators
// SHOULD pin an explicit version so a vault-side rotation does not silently
// change the signing key). The operator adapts this onto the factory's
// (crypto.Signer, string, error) return.
type BuildResult struct {
	Signer crypto.Signer
	KeyID  string
}

// Build validates args and constructs the Key Vault signer, exactly as
// NewSigner does (nil client / empty key name fail the operator's boot
// CLOSED; it performs NO vault I/O — the first Public() or Sign() performs
// the lazy GetKey, so an unreachable vault does not block startup). opts
// pass straight through to NewSigner (e.g. WithContext / WithCallTimeout
// overrides in a fork that needs them). deps is the uniform module-Build
// contract (see Deps); the vendor client is constructed by the operator's
// forked main, where azure-sdk-for-go lives, and closed over in the
// factory.
//
// Operator-fork wiring (copy-pasteable):
//
//	client, err := azkeys.NewClient(vaultURL, cred, nil) // sdk/security/keyvault/azkeys; cred from azidentity
//	if err != nil { return err }
//
//	ssoext.RegisterExternalSigner("azurekeyvault", func(ctx context.Context) (crypto.Signer, string, error) {
//		res, err := azurekeyvault.Build(azurekeyvault.Deps{}, client, "signing-key", keyVersion)
//		if err != nil {
//			return nil, "", err
//		}
//		return res.Signer, res.KeyID, nil
//	})
func Build(deps Deps, client keyVaultAPI, keyName, keyVersion string, opts ...Option) (*BuildResult, error) {
	sgn, err := NewSigner(client, keyName, keyVersion, opts...)
	if err != nil {
		return nil, err
	}
	return &BuildResult{Signer: sgn, KeyID: keyName}, nil
}
