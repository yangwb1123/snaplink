package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/snaplink/sso"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/spi"
)

// staticSigner returns a fixed crypto.Signer — a stand-in for a KMS/HSM
// factory whose key lives out-of-process.
func staticSigner(s crypto.Signer) ExternalSignerFactory {
	return func(context.Context) (crypto.Signer, string, error) {
		return s, "kms-test-kid", nil
	}
}

func keyIDOf(t *testing.T, iss signingIssuer) string {
	t.Helper()
	k, ok := iss.(interface{ KeyID() string })
	if !ok {
		t.Fatalf("issuer %T has no KeyID()", iss)
	}
	return k.KeyID()
}

// registerExternalSignerForTest registers a signer factory and unregisters it
// when the test ends, keeping the package-global registry clean across subtests
// and -count>1 runs. RegisterExternalSigner panics on a duplicate name by design
// (a production wiring guard), so tests must clean up rather than relax it.
func registerExternalSignerForTest(t *testing.T, name string, f ExternalSignerFactory) {
	t.Helper()
	RegisterExternalSigner(name, f)
	t.Cleanup(func() {
		externalSignerRegistry.mu.Lock()
		defer externalSignerRegistry.mu.Unlock()
		delete(externalSignerRegistry.factories, name)
	})
}

func TestBuildSigningIssuer_ExternalSigner(t *testing.T) {
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)

	cases := []struct {
		alg    string
		signer crypto.Signer
	}{
		{"eddsa", edPriv},
		{"es256", ecPriv},
		{"rs256", rsaPriv},
		{"ps256", rsaPriv},
	}
	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			name := "ext-" + tc.alg
			registerExternalSignerForTest(t, name, staticSigner(tc.signer))

			iss, _, _, err := buildSigningIssuer(
				config.SigningConfig{Alg: tc.alg, External: name},
				config.ServerConfig{Issuer: "https://sso.test"},
				nil,
				spi.NopLogger{},
			)
			if err != nil {
				t.Fatalf("buildSigningIssuer: %v", err)
			}
			if kid := keyIDOf(t, iss); kid != "kms-test-kid" {
				t.Errorf("kid = %q, want kms-test-kid (external signer not wired)", kid)
			}
		})
	}
}

func TestBuildSigningIssuer_UnregisteredExternal(t *testing.T) {
	_, _, _, err := buildSigningIssuer(
		config.SigningConfig{Alg: "eddsa", External: "does-not-exist"},
		config.ServerConfig{Issuer: "https://sso.test"},
		nil,
		spi.NopLogger{},
	)
	if err == nil {
		t.Fatal("expected error for unregistered external signer")
	}
}

func TestBuildSigningIssuer_AlgKeyMismatchFailsClosed(t *testing.T) {
	// es256 alg but an Ed25519 signer — the bridge must reject it at
	// startup rather than minting tokens no verifier accepts.
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	registerExternalSignerForTest(t, "ext-mismatch", staticSigner(edPriv))
	_, _, _, err := buildSigningIssuer(
		config.SigningConfig{Alg: "es256", External: "ext-mismatch"},
		config.ServerConfig{Issuer: "https://sso.test"},
		nil,
		spi.NopLogger{},
	)
	if err == nil {
		t.Fatal("expected error wiring an Ed25519 signer into an ES256 issuer")
	}
}

func TestBuildSigningIssuer_NoExternalIsInProcess(t *testing.T) {
	// Empty External keeps the historical in-process key path.
	iss, alg, probe, err := buildSigningIssuer(
		config.SigningConfig{Alg: "eddsa"},
		config.ServerConfig{Issuer: "https://sso.test"},
		nil,
		spi.NopLogger{},
	)
	if err != nil {
		t.Fatalf("buildSigningIssuer: %v", err)
	}
	if alg != "EdDSA" {
		t.Errorf("alg = %q, want EdDSA", alg)
	}
	if kid := keyIDOf(t, iss); kid == "kms-test-kid" {
		t.Error("in-process path unexpectedly used the external kid")
	}
	if probe != nil {
		t.Error("in-process path returned a non-nil readiness probe; appendReadyCheck would register a bogus /readyz dependency")
	}
}

// TestExternalSignerMetrics proves the external-signer round-trip is
// counted: issuing a token through an externally-signed issuer increments
// sso_signing_operations_total{alg,outcome="success"}.
func TestExternalSignerMetrics(t *testing.T) {
	m := metrics.New()
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registerExternalSignerForTest(t, "ext-metrics", staticSigner(ecPriv))

	iss, _, _, err := buildSigningIssuer(
		config.SigningConfig{Alg: "es256", External: "ext-metrics"},
		config.ServerConfig{Issuer: "https://sso.test"},
		m,
		spi.NopLogger{},
	)
	if err != nil {
		t.Fatalf("buildSigningIssuer: %v", err)
	}
	if _, err := iss.Issue(context.Background(), &sso.Subject{ID: "u1", ClientID: "c1"}, []string{"read"}); err != nil {
		t.Fatalf("issue: %v", err)
	}

	scrape := scrapeMetrics(t, m)
	if !strings.Contains(scrape, `sso_signing_operations_total{alg="es256",outcome="success"} 1`) {
		t.Errorf("expected es256/success signing counter in scrape:\n%s", scrape)
	}
}

// TestSigningBackendUpGauge proves the health gauge tracks the last
// signing outcome: 1 after success, 0 after a failure.
func TestSigningBackendUpGauge(t *testing.T) {
	m := metrics.New()
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	flaky := &flakySigner{inner: ecPriv}
	wrapped := instrumentSigner(flaky, "es256", m, spi.NopLogger{})
	digest := make([]byte, 32)

	if _, err := wrapped.Sign(rand.Reader, digest, crypto.SHA256); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if s := scrapeMetrics(t, m); !strings.Contains(s, `sso_signing_backend_up{alg="es256"} 1`) {
		t.Errorf("after success want up=1, scrape:\n%s", s)
	}

	flaky.setErr(errKMSDown)
	if _, err := wrapped.Sign(rand.Reader, digest, crypto.SHA256); err == nil {
		t.Fatal("expected sign error")
	}
	if s := scrapeMetrics(t, m); !strings.Contains(s, `sso_signing_backend_up{alg="es256"} 0`) {
		t.Errorf("after failure want up=0, scrape:\n%s", s)
	}
}

// scrapeMetrics renders m's registry in the prometheus text exposition
// format, the same view /metrics serves.
func scrapeMetrics(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	srv := httptest.NewServer(promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func TestRegisterExternalSigner_RejectsBadInput(t *testing.T) {
	assertPanic(t, "empty name", func() { RegisterExternalSigner("", staticSigner(nil)) })
	assertPanic(t, "nil factory", func() { RegisterExternalSigner("ext-nilfac", nil) })

	registerExternalSignerForTest(t, "ext-dup", staticSigner(nil))
	assertPanic(t, "duplicate", func() { RegisterExternalSigner("ext-dup", staticSigner(nil)) })
}

// flakySigner is a crypto.Signer whose Sign outcome is operator-toggled,
// standing in for a KMS/HSM that goes (un)reachable at runtime.
type flakySigner struct {
	inner  crypto.Signer
	mu     sync.Mutex
	signEr error
}

func (f *flakySigner) Public() crypto.PublicKey { return f.inner.Public() }

func (f *flakySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	f.mu.Lock()
	er := f.signEr
	f.mu.Unlock()
	if er != nil {
		return nil, er
	}
	return f.inner.Sign(rand, digest, opts)
}

func (f *flakySigner) setErr(er error) {
	f.mu.Lock()
	f.signEr = er
	f.mu.Unlock()
}

func TestInstrumentSigner_ReadinessProbe(t *testing.T) {
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	flaky := &flakySigner{inner: ecPriv}

	// Wrap WITHOUT metrics — readiness must not depend on metrics.
	wrapped := instrumentSigner(flaky, "es256", nil, spi.NopLogger{})
	probe, ok := wrapped.(interface{ Ping(context.Context) error })
	if !ok {
		t.Fatal("instrumented signer does not expose Ping; appendReadyCheck would skip it")
	}

	// Fresh server, no signing yet: healthy (startup proved reachability).
	if err := probe.Ping(context.Background()); err != nil {
		t.Errorf("fresh probe = %v, want healthy", err)
	}

	digest := make([]byte, 32)

	// A successful sign keeps it green.
	if _, err := wrapped.Sign(rand.Reader, digest, crypto.SHA256); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := probe.Ping(context.Background()); err != nil {
		t.Errorf("after success probe = %v, want healthy", err)
	}

	// A failed sign trips it red.
	flaky.setErr(errKMSDown)
	if _, err := wrapped.Sign(rand.Reader, digest, crypto.SHA256); err == nil {
		t.Fatal("expected sign error from flaky signer")
	}
	if err := probe.Ping(context.Background()); err == nil {
		t.Error("after failure probe = healthy, want red")
	}

	// Recovery: a subsequent success clears the red.
	flaky.setErr(nil)
	if _, err := wrapped.Sign(rand.Reader, digest, crypto.SHA256); err != nil {
		t.Fatalf("sign after recovery: %v", err)
	}
	if err := probe.Ping(context.Background()); err != nil {
		t.Errorf("after recovery probe = %v, want healthy", err)
	}
}

// captureLogger records Error/Info messages for assertions.
type captureLogger struct {
	mu    sync.Mutex
	errs  []string
	infos []string
}

func (l *captureLogger) Info(msg string, _ ...any) {
	l.mu.Lock()
	l.infos = append(l.infos, msg)
	l.mu.Unlock()
}
func (l *captureLogger) Error(msg string, _ ...any) {
	l.mu.Lock()
	l.errs = append(l.errs, msg)
	l.mu.Unlock()
}
func (l *captureLogger) Debug(msg string, _ ...any) {}

// TestInstrumentSigner_LogsOnlyTransitions proves the down/up edges are
// logged once each — not every steady-state call.
func TestInstrumentSigner_LogsOnlyTransitions(t *testing.T) {
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	flaky := &flakySigner{inner: ecPriv}
	lg := &captureLogger{}
	wrapped := instrumentSigner(flaky, "es256", nil, lg)
	digest := make([]byte, 32)

	sign := func() { _, _ = wrapped.Sign(rand.Reader, digest, crypto.SHA256) }

	sign() // first success: no transition (no prior state)
	sign() // steady success
	flaky.setErr(errKMSDown)
	sign() // -> down
	sign() // steady down: no new log
	flaky.setErr(nil)
	sign() // -> up

	lg.mu.Lock()
	defer lg.mu.Unlock()
	if len(lg.errs) != 1 {
		t.Errorf("down logs = %d (%v), want exactly 1", len(lg.errs), lg.errs)
	}
	if len(lg.infos) != 1 {
		t.Errorf("recovery logs = %d (%v), want exactly 1", len(lg.infos), lg.infos)
	}
}

func TestSignerHealth_StaleFailureRecovers(t *testing.T) {
	var h signerHealth
	h.record(errKMSDown)
	if h.check() == nil {
		t.Fatal("recent failure should read unhealthy")
	}
	// Age the failure past the window with no traffic since: assumed
	// recovered so /readyz doesn't latch red forever on an idle server.
	h.mu.Lock()
	h.lastErrAt = time.Now().Add(-externalSignerHealthWindow - time.Second)
	h.mu.Unlock()
	if err := h.check(); err != nil {
		t.Errorf("stale failure = %v, want healthy (assumed recovered)", err)
	}
}

var errKMSDown = errKMS("kms unreachable")

type errKMS string

func (e errKMS) Error() string { return string(e) }

func assertPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s: expected panic, got none", what)
		}
	}()
	f()
}
