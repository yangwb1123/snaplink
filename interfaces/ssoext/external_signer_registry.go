package ssoext

import (
	"context"
	"crypto"

	"github.com/yangwb1123/snaplink/platform/registrar"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// ExternalSignerFactory builds a KMS/HSM-backed crypto.Signer for the JWT
// signing issuer, returning the signer and the kid that names its public
// key in JWKS and token headers. It is called once at startup (from
// serverbuildsign.resolveExternalSigner); a returned error fails boot
// closed.
//
// The factory type is EXACTLY the historical
// serverbuildsign.ExternalSignerFactory shape, by design: crypto.Signer is
// a stdlib type (so no vendor SDK type crosses this boundary — the
// zero-external-dep invariant holds), and keeping the identical shape lets
// serverbuildsign alias it (not re-declare it), so pre-existing fork
// binaries that call serverbuildsign.RegisterExternalSigner keep compiling
// unchanged while behavior stays byte-identical. The factory receives no
// Deps bundle (see ExternalSignerDeps for what the module-side Build
// adapters embed instead); the server applies its health/metrics/readiness
// wrapping AFTER the factory returns, in cmd (InstrumentSigner), so the
// factory only ever returns the raw signer + kid.
//
// The returned crypto.Signer is bridged into the issuer's signing seam by
// defaultimpl/cryptosigner, so its public key MUST match the configured
// keys.signing.alg family (Ed25519 for eddsa, P-256 ECDSA for es256, RSA
// for rs256/ps256). The kid is typically the stable KMS key id / ARN.
type ExternalSignerFactory func(ctx context.Context) (crypto.Signer, string, error)

// ExternalSignerDeps is the dependency bundle the nested KMS modules'
// build.go adapters embed (awskms.Deps / gcpkms.Deps / azurekeyvault.Deps /
// pkcs11.Deps all embed this exact struct, mirroring ldapauth.Deps). Every
// field is a stdlib type or an intra-repo root-module type — there is NO
// vendor SDK type here (no aws-sdk-go-v2, no cloud.google.com/go/kms, no
// azure-sdk-for-go, no miekg/pkcs11), so a fork can wire a KMS signer
// factory without any vendor dependency entering this module's go.mod (the
// firm zero-external-dep invariant; the vendor client is constructed in the
// fork's main, where the vendor SDK lives, and closed over in the factory).
//
// Unlike the authenticator-family bundles (LDAPServerDeps etc.), the KMS
// factory itself receives no deps — the factory shape is the historical
// serverbuildsign.ExternalSignerFactory signature (see its doc) — so a
// fork's main constructs this bundle itself (its own logger, or the zero
// value) and passes it to the module's Build. Logger is the operational-
// logging seam: the built-in KMS signers perform no I/O logging today
// (serverbuildsign's instrumentedSigner owns health + metrics + transition
// logging at the cmd boundary), so Build carries the bundle for shape
// uniformity with the ldap/radius adapters and as the typed carrier a
// future signer WithLogger option would consume.
type ExternalSignerDeps struct {
	// Logger is the operator's logger, handed across the module boundary
	// for the signer's operational failure logging. May be nil.
	Logger spi.Logger
}

// ExternalSignerRegistry holds operator-registered KMS/HSM signer
// factories. The vendor KMS SDK (AWS/GCP/Azure/PKCS#11) lives in the
// operator's forked binary, not this module — the operator calls
// RegisterExternalSigner from their main before running the server, then
// selects the factory by name via keys.signing.external. This is the
// CANONICAL registry for that config key: serverbuildsign's
// ExternalSignerRegistry is an alias to this one (the same registrar
// pointer), so there is exactly one name space and no double-registry
// drift. The generic machinery is the standard platform/registrar
// implementation (same shape as SAMLHandlerRegistry and the
// authenticator-family registries). Exported so tests can clean up between
// runs via Unregister.
//
// Registration is process-local and name-addressed by configuration
// (keys.signing.external selects the factory by name at boot). It is the
// in-process compile-time seam for forked binaries only — NOT a hot-plugin
// registry: nothing here can add entries after startup, and installable
// third-party code must run out of process over the typed authenticated
// protocol (see docs/plugin-system.md).
var ExternalSignerRegistry = registrar.New[ExternalSignerFactory]()

// RegisterExternalSigner registers a KMS/HSM signer factory under name,
// reachable via keys.signing.external. Intended to be called from an
// operator's forked main during init/startup. Panics on an empty name, a
// nil factory, or a duplicate name (all unrecoverable wiring mistakes) —
// identical to serverbuildsign.RegisterExternalSigner (which is a
// delegating alias of this function) and RegisterSAMLHandlers.
func RegisterExternalSigner(name string, f ExternalSignerFactory) {
	ExternalSignerRegistry.Register(name, f)
}

// LookupExternalSigner returns the factory registered under name.
func LookupExternalSigner(name string) (ExternalSignerFactory, bool) {
	return ExternalSignerRegistry.Lookup(name)
}

// RegisteredExternalSigners returns the sorted names of all registered
// signer factories, for the boot-time diagnostic when keys.signing.external
// names an unregistered factory.
func RegisteredExternalSigners() []string {
	return ExternalSignerRegistry.Names()
}
