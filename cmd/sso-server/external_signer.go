package main

import (
	"context"
	"crypto"
	"fmt"
	"sort"
	"sync"
)

// ExternalSignerFactory builds a KMS/HSM-backed crypto.Signer for the JWT
// signing issuer, returning the signer and the kid that names its public
// key in JWKS and token headers. It is called once at startup; a returned
// error fails boot closed.
//
// The returned crypto.Signer is bridged into the issuer's signing seam by
// defaultimpl/cryptosigner, so its public key MUST match the configured
// keys.signing.alg family (Ed25519 for eddsa, P-256 ECDSA for es256, RSA
// for rs256/ps256). The kid is typically the stable KMS key id / ARN.
type ExternalSignerFactory func(ctx context.Context) (crypto.Signer, string, error)

// externalSignerRegistry holds operator-registered KMS/HSM signer
// factories. The vendor KMS SDK (AWS/GCP/Azure/PKCS#11) lives in the
// operator's forked binary, not this module — the operator calls
// RegisterExternalSigner from their main before running the server, then
// selects the factory by name via keys.signing.external. This mirrors how
// the repo keeps etcd and push-transport SDKs out of the SPI.
var externalSignerRegistry = struct {
	mu        sync.RWMutex
	factories map[string]ExternalSignerFactory
}{factories: map[string]ExternalSignerFactory{}}

// RegisterExternalSigner registers a KMS/HSM signer factory under name,
// reachable via keys.signing.external. Intended to be called from an
// operator's forked main during init/startup. Panics on an empty name, a
// nil factory, or a duplicate name (all unrecoverable wiring mistakes).
func RegisterExternalSigner(name string, f ExternalSignerFactory) {
	if name == "" {
		panic("RegisterExternalSigner: empty name")
	}
	if f == nil {
		panic(fmt.Sprintf("RegisterExternalSigner: nil factory for %q", name))
	}
	externalSignerRegistry.mu.Lock()
	defer externalSignerRegistry.mu.Unlock()
	if _, dup := externalSignerRegistry.factories[name]; dup {
		panic(fmt.Sprintf("RegisterExternalSigner: %q already registered", name))
	}
	externalSignerRegistry.factories[name] = f
}

// lookupExternalSigner returns the factory registered under name.
func lookupExternalSigner(name string) (ExternalSignerFactory, bool) {
	externalSignerRegistry.mu.RLock()
	defer externalSignerRegistry.mu.RUnlock()
	f, ok := externalSignerRegistry.factories[name]
	return f, ok
}

// registeredExternalSigners returns the sorted names of all registered
// factories, for diagnostics.
func registeredExternalSigners() []string {
	externalSignerRegistry.mu.RLock()
	defer externalSignerRegistry.mu.RUnlock()
	names := make([]string, 0, len(externalSignerRegistry.factories))
	for n := range externalSignerRegistry.factories {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
