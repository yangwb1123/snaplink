//go:build !no_pkcs11

package pkcs11

import (
	"crypto"

	"github.com/yangwb1123/snaplink/interfaces/ssoext"
)

// Deps is the ROOT-module-typed dependency bundle Build needs. Every field
// is a stdlib type or a root-module type — there is NO cmd/sso-server
// (package main) type here, because a separate module's package cannot
// import package main. The operator's forked main (which owns the PKCS#11
// config) constructs a Deps from its own logger inside the factory closure
// (see Build's doc for the copy-pasteable wiring).
//
// Deps EMBEDS the standard host-API bundle
// (interfaces/ssoext.ExternalSignerDeps — the exact root-module-typed seam
// the KMS family shares). Embedding (not aliasing) keeps the field names: a
// fork constructs `pkcs11.Deps{ExternalSignerDeps: ssoext.ExternalSignerDeps{
// Logger: myLogger}}` (or simply `pkcs11.Deps{}` — the zero value is valid),
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

// BuildResult is everything Build produces: the token-backed crypto.Signer
// and the kid that names its public key in JWKS + token headers (cfg.KeyLabel
// — the same string the production New wires onto the signer via WithKeyID;
// see New's doc). The operator adapts this onto the factory's
// (crypto.Signer, string, error) return.
type BuildResult struct {
	Signer crypto.Signer
	KeyID  string
}

// Build validates cfg and constructs the token signer, exactly as the
// production New does: it opens the token (C_Initialize, slot lookup,
// C_Login when a PIN is set, key-object location) — a token that is down at
// boot fails the operator's boot CLOSED, which is the correct posture here
// because a Session is required to sign at all (unlike the cloud KMS
// signers, whose Public()/Sign() are lazy). Call [Signer.PublicKey] once
// after Build to fail loud if the public key cannot be read, and
// [Signer.Close] on shutdown. opts pass straight through to New (e.g.
// WithKeyOrigin overrides). deps is the uniform module-Build contract (see
// Deps); the token config (module path, PIN, key labels) is the operator's
// own config, closed over in the factory.
//
// Operator-fork wiring (copy-pasteable):
//
//	tokenCfg := pkcs11.Config{
//		ModulePath: "/usr/lib/softhsm/libsofthsm2.so", // or the vendor's libCryptoki2.so
//		TokenLabel: "ssotoken",
//		PIN:        os.Getenv("PKCS11_PIN"), // from a secret store, never YAML
//		KeyLabel:   "jwt-signing-key",
//	}
//
//	ssoext.RegisterExternalSigner("pkcs11", func(ctx context.Context) (crypto.Signer, string, error) {
//		res, err := pkcs11.Build(pkcs11.Deps{}, tokenCfg)
//		if err != nil {
//			return nil, "", err
//		}
//		return res.Signer, res.KeyID, nil
//	})
func Build(deps Deps, cfg Config, opts ...Option) (*BuildResult, error) {
	sgn, err := New(cfg, opts...)
	if err != nil {
		return nil, err
	}
	return &BuildResult{Signer: sgn, KeyID: cfg.KeyLabel}, nil
}
