package main

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso/metrics"
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

// instrumentedSigner wraps a crypto.Signer to record signing latency +
// outcome at the KMS/HSM round-trip boundary. It is the same crypto.Signer
// interface, so it slots transparently between the operator's factory and
// the cryptosigner bridge.
type instrumentedSigner struct {
	inner crypto.Signer
	alg   string
	m     *metrics.Metrics
}

func (s instrumentedSigner) Public() crypto.PublicKey { return s.inner.Public() }

func (s instrumentedSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	start := time.Now()
	sig, err := s.inner.Sign(rand, digest, opts)
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	s.m.SigningOperationsTotal.WithLabelValues(s.alg, outcome).Inc()
	s.m.SigningDuration.WithLabelValues(s.alg).Observe(time.Since(start).Seconds())
	return sig, err
}

// instrumentSigner wraps s to record signing metrics under the given alg
// label. Returns s unchanged when metrics are disabled or s is nil, so
// callers can wrap unconditionally.
func instrumentSigner(s crypto.Signer, alg string, m *metrics.Metrics) crypto.Signer {
	if m == nil || s == nil {
		return s
	}
	return instrumentedSigner{inner: s, alg: alg, m: m}
}

// normalizeAlgLabel maps the configured keys.signing.alg to the bounded
// metric label set (eddsa/es256/rs256/ps256).
func normalizeAlgLabel(alg string) string {
	switch strings.ToLower(strings.TrimSpace(alg)) {
	case "", "eddsa", "ed25519":
		return "eddsa"
	case "es256", "ecdsa":
		return "es256"
	case "ps256":
		return "ps256"
	case "rs256", "rsa":
		return "rs256"
	default:
		return "unknown"
	}
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
