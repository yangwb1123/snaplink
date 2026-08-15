//go:build !no_kms_awskms

package awskms

import (
	"crypto"

	"github.com/yangwb1123/snaplink/interfaces/ssoext"
)

// Deps is the ROOT-module-typed dependency bundle Build needs. Every field
// is a stdlib type or a root-module type — there is NO cmd/sso-server
// (package main) type here, because a separate module's package cannot
// import package main. The operator's forked main (which owns the AWS KMS
// SDK client) constructs a Deps from its own logger inside the factory
// closure (see Build's doc for the copy-pasteable wiring).
//
// Deps EMBEDS the standard host-API bundle
// (interfaces/ssoext.ExternalSignerDeps — the exact root-module-typed seam
// the KMS family shares). Embedding (not aliasing) keeps the field names: a
// fork constructs `awskms.Deps{ExternalSignerDeps: ssoext.ExternalSignerDeps{
// Logger: myLogger}}` (or simply `awskms.Deps{}` — the zero value is valid),
// mirroring ldapauth.Deps / radiusauth.Deps.
type Deps struct {
	// ExternalSignerDeps carries the operator logger across the module
	// boundary. The built-in signer performs no I/O logging (the
	// instrumentedSigner wrapper in serverbuildsign owns health + metrics
	// logging at the cmd boundary), so Build carries the bundle for shape
	// uniformity with the ldap/radius adapters; a future signer WithLogger
	// option would consume it.
	ssoext.ExternalSignerDeps
}

// BuildResult is everything Build produces: the KMS-backed crypto.Signer
// and the kid that names its public key in JWKS + token headers (the keyID
// argument — typically the key ARN, the stable identity an operator pins in
// JWKS). The operator adapts this onto the factory's
// (crypto.Signer, string, error) return.
type BuildResult struct {
	Signer crypto.Signer
	KeyID  string
}

// Build validates args and constructs the KMS signer, exactly as New does
// (nil client / empty key id fail the operator's boot CLOSED; it performs
// NO KMS I/O — the first Public() or Sign() performs the lazy
// GetPublicKey, so an unreachable KMS does not block startup). opts pass
// straight through to New (e.g. WithContext / WithCallTimeout overrides in
// a fork that needs them). deps is the uniform module-Build contract (see
// Deps); the vendor client is constructed by the operator's forked main,
// where aws-sdk-go-v2 lives, and closed over in the factory.
//
// Operator-fork wiring (copy-pasteable):
//
//	awsCfg, err := awsconfig.LoadDefaultConfig(ctx) // aws-sdk-go-v2/config
//	if err != nil { return err }
//	kmsClient := kms.NewFromConfig(awsCfg)          // vendor SDK client, held by the closure
//
//	ssoext.RegisterExternalSigner("awskms", func(ctx context.Context) (crypto.Signer, string, error) {
//		res, err := awskms.Build(awskms.Deps{}, kmsClient, keyARN)
//		if err != nil {
//			return nil, "", err
//		}
//		return res.Signer, res.KeyID, nil
//	})
func Build(deps Deps, client KMSAPI, keyID string, opts ...Option) (*BuildResult, error) {
	sgn, err := New(client, keyID, opts...)
	if err != nil {
		return nil, err
	}
	return &BuildResult{Signer: sgn, KeyID: keyID}, nil
}
