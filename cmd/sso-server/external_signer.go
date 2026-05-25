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

// externalSignerHealthWindow bounds how long a failed external-signing
// attempt keeps /readyz red with no fresh traffic. A failure older than
// this — with no signing since — is treated as recovered, so the probe
// doesn't latch red forever on an idle server; real /token traffic
// re-proves health. Sized for kubelet poll cadence, not tuned per
// deployment (no config surface).
const externalSignerHealthWindow = 30 * time.Second

// signerHealth tracks the most recent external-signing outcome so a
// passive /readyz probe can report KMS/HSM reachability WITHOUT spending
// a KMS round-trip per poll — production signing traffic is the probe.
type signerHealth struct {
	mu        sync.Mutex
	lastErr   error
	lastErrAt time.Time
	lastOKAt  time.Time
}

func (h *signerHealth) record(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if err != nil {
		h.lastErr = err
		h.lastErrAt = now
		return
	}
	h.lastOKAt = now
}

// check reports unhealthy only when the most recent attempt FAILED and
// that failure is recent. A success after the failure clears it; a stale
// failure (no traffic since) is assumed recovered. A fresh server with no
// traffic reads healthy — startup already proved reachability by fetching
// the public key.
func (h *signerHealth) check() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lastErrAt.After(h.lastOKAt) && time.Since(h.lastErrAt) < externalSignerHealthWindow {
		return h.lastErr
	}
	return nil
}

// instrumentedSigner wraps a crypto.Signer to (1) record signing latency +
// outcome metrics and (2) track health for the external-signer /readyz
// probe, both at the KMS/HSM round-trip boundary. It is the same
// crypto.Signer interface, so it slots transparently between the
// operator's factory and the cryptosigner bridge, and also exposes
// Ping(ctx) so appendReadyCheck wires it into /readyz.
type instrumentedSigner struct {
	inner  crypto.Signer
	alg    string
	m      *metrics.Metrics // nil when metrics are disabled
	health signerHealth
}

func (s *instrumentedSigner) Public() crypto.PublicKey { return s.inner.Public() }

func (s *instrumentedSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	start := time.Now()
	sig, err := s.inner.Sign(rand, digest, opts)
	s.health.record(err)
	if s.m != nil {
		outcome := "success"
		if err != nil {
			outcome = "error"
		}
		s.m.SigningOperationsTotal.WithLabelValues(s.alg, outcome).Inc()
		s.m.SigningDuration.WithLabelValues(s.alg).Observe(time.Since(start).Seconds())
	}
	return sig, err
}

// Ping satisfies the readycheck contract appendReadyCheck looks for. It
// reports the last recent signing failure (if any) so a wedged KMS/HSM
// trips /readyz before /token requests fail en masse.
func (s *instrumentedSigner) Ping(context.Context) error { return s.health.check() }

// instrumentSigner wraps s for metrics + health tracking under the given
// alg label. Returns nil when s is nil, so callers can wrap
// unconditionally. The wrap happens even when metrics are disabled —
// readiness must not depend on metrics being on; the metric writes alone
// are gated on m != nil.
func instrumentSigner(s crypto.Signer, alg string, m *metrics.Metrics) crypto.Signer {
	if s == nil {
		return nil
	}
	return &instrumentedSigner{inner: s, alg: alg, m: m}
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
