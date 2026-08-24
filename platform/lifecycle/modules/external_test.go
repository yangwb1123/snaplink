package modules

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

const (
	externalWorkerSocketEnv = "SNAPLINK_EXTERNAL_WORKER_SOCKET"
	externalWorkerTokenEnv  = "SNAPLINK_EXTERNAL_WORKER_TOKEN"
)

func TestMain(m *testing.M) {
	if os.Getenv(externalWorkerSocketEnv) != "" {
		os.Exit(runExternalWorkerProcess())
	}
	os.Exit(m.Run())
}

func runExternalWorkerProcess() int {
	socketPath, token := os.Getenv(externalWorkerSocketEnv), os.Getenv(externalWorkerTokenEnv)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return 1
	}
	defer listener.Close()
	conn, err := listener.Accept()
	if err != nil {
		return 1
	}
	options := ExternalServerOptions{
		ModuleID: "worker-a", AuthToken: []byte(token),
		Capabilities: []ExternalCapability{ExternalCapabilityAuditBatch},
	}
	if err := ServeExternalConnection(context.Background(), conn, options, &externalAuditCapture{}); err != nil {
		return 1
	}
	return 0
}

type externalAuditCapture struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *externalAuditCapture) DeliverAuditBatch(_ context.Context, events []audit.Event) error {
	c.mu.Lock()
	c.events = append(c.events, events...)
	c.mu.Unlock()
	return nil
}

func (c *externalAuditCapture) snapshot() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]audit.Event(nil), c.events...)
}

func TestServeExternalConnectionProtocol(t *testing.T) {
	host, worker := net.Pipe()
	t.Cleanup(func() { _ = host.Close(); _ = worker.Close() })
	capture := &externalAuditCapture{}
	var ready, heartbeat, quiesce, shutdown atomic.Int32
	options := ExternalServerOptions{
		ModuleID: "worker-a", AuthToken: []byte("secret"),
		Capabilities: []ExternalCapability{ExternalCapabilityAuditBatch},
		Ready:        func(context.Context) error { ready.Add(1); return nil },
		Heartbeat:    func(context.Context) error { heartbeat.Add(1); return nil },
		Quiesce:      func(context.Context) error { quiesce.Add(1); return nil },
		Shutdown:     func(context.Context) error { shutdown.Add(1); return nil },
	}
	done := make(chan error, 1)
	go func() { done <- ServeExternalConnection(context.Background(), worker, options, capture) }()
	reader, writer := bufio.NewReader(host), bufio.NewWriter(host)
	token := hex.EncodeToString([]byte("secret"))
	hello := externalHandshake{ProtocolVersion: ExternalProtocolVersion, ModuleID: "worker-a", RequiredCapabilities: []ExternalCapability{ExternalCapabilityAuditBatch}}
	response := externalClientRoundTrip(t, reader, writer, token, "1", externalMethodHandshake, hello)
	if !response.OK {
		t.Fatalf("handshake failed: %s", response.Error)
	}
	var accepted externalHandshake
	if err := json.Unmarshal(response.Result, &accepted); err != nil || !hasExternalCapability(accepted.Capabilities, ExternalCapabilityAuditBatch) {
		t.Fatalf("handshake result = %#v, err = %v", accepted, err)
	}
	if response := externalClientRoundTrip(t, reader, writer, token, "2", externalMethodReady, nil); !response.OK {
		t.Fatalf("ready failed: %s", response.Error)
	}
	if response := externalClientRoundTrip(t, reader, writer, token, "3", externalMethodHeartbeat, nil); !response.OK {
		t.Fatalf("heartbeat failed: %s", response.Error)
	}
	event := audit.Event{ID: "event-1", Type: audit.EventLogin}
	if response := externalClientRoundTrip(t, reader, writer, token, "4", externalMethodAuditBatch, externalAuditBatch{Events: []audit.Event{event}}); !response.OK {
		t.Fatalf("audit batch failed: %s", response.Error)
	}
	if got := capture.snapshot(); len(got) != 1 || got[0].ID != event.ID {
		t.Fatalf("captured events = %#v", got)
	}
	if response := externalClientRoundTrip(t, reader, writer, token, "5", externalMethodQuiesce, nil); !response.OK {
		t.Fatalf("quiesce failed: %s", response.Error)
	}
	if response := externalClientRoundTrip(t, reader, writer, token, "6", externalMethodAuditBatch, externalAuditBatch{Events: []audit.Event{event}}); response.OK || !strings.Contains(response.Error, "quiescing") {
		t.Fatalf("quiesced batch response = %#v", response)
	}
	if response := externalClientRoundTrip(t, reader, writer, token, "7", externalMethodShutdown, nil); !response.OK {
		t.Fatalf("shutdown failed: %s", response.Error)
	}
	if err := <-done; err != nil {
		t.Fatalf("ServeExternalConnection() error = %v", err)
	}
	if ready.Load() != 1 || heartbeat.Load() != 1 || quiesce.Load() != 1 || shutdown.Load() != 1 {
		t.Fatalf("callback counts ready=%d heartbeat=%d quiesce=%d shutdown=%d", ready.Load(), heartbeat.Load(), quiesce.Load(), shutdown.Load())
	}
}

func TestServeExternalConnectionRejectsInvalidHandshake(t *testing.T) {
	host, worker := net.Pipe()
	t.Cleanup(func() { _ = host.Close(); _ = worker.Close() })
	done := make(chan error, 1)
	go func() {
		done <- ServeExternalConnection(context.Background(), worker, ExternalServerOptions{
			ModuleID: "worker-a", AuthToken: []byte("secret"),
			Capabilities: []ExternalCapability{ExternalCapabilityAuditBatch},
		}, &externalAuditCapture{})
	}()
	reader, writer := bufio.NewReader(host), bufio.NewWriter(host)
	hello := externalHandshake{ProtocolVersion: ExternalProtocolVersion, ModuleID: "worker-a"}
	response := externalClientRoundTrip(t, reader, writer, hex.EncodeToString([]byte("wrong")), "1", externalMethodHandshake, hello)
	if response.OK || !strings.Contains(response.Error, "authentication failed") {
		t.Fatalf("invalid handshake response = %#v", response)
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("ServeExternalConnection() error = %v", err)
	}
}

func TestNewExternalSupervisorRejectsUnsafeSpec(t *testing.T) {
	_, err := NewExternalSupervisor(ExternalModuleSpec{
		ModuleID: "worker-a", Executable: "/bin/worker", SocketPath: "/tmp/worker.sock", AuthToken: []byte("secret"), ExpectedSHA256: "not-a-digest",
	})
	if err == nil || !strings.Contains(err.Error(), "expected_sha256") {
		t.Fatalf("error = %v", err)
	}
}

func TestNewExternalSupervisorRejectsIncompleteTrustPolicy(t *testing.T) {
	local, err := NewExternalSupervisor(ExternalModuleSpec{
		ModuleID: "worker-a", Executable: "/bin/worker", SocketPath: "/tmp/worker.sock",
		AuthToken: []byte("secret"), ExpectedSHA256: strings.Repeat("a", 64), SignaturePath: "/tmp/worker.sig",
	})
	if err == nil || local != nil || !strings.Contains(err.Error(), "signature path") {
		t.Fatalf("incomplete signature policy = (%v, %v)", local, err)
	}
	remote, err := NewExternalSupervisor(ExternalModuleSpec{
		ModuleID: "worker-a", RemoteAddress: "127.0.0.1:1", AuthToken: []byte("secret"), TLSConfig: &tls.Config{},
	})
	if err == nil || remote != nil || !strings.Contains(err.Error(), "mTLS") {
		t.Fatalf("insecure remote policy = (%v, %v)", remote, err)
	}
}

func TestExternalArtifactSignatureRejectsTampering(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signaturePath := filepath.Join(t.TempDir(), "worker.sig")
	signature := ed25519.Sign(privateKey, []byte("different digest"))
	if err := os.WriteFile(signaturePath, []byte(base64.StdEncoding.EncodeToString(signature)), 0o600); err != nil {
		t.Fatal(err)
	}
	err = verifyExternalExecutable(executable, hex.EncodeToString(digest[:]), signaturePath, publicKey, "", nil, "", "", "")
	if err == nil || !strings.Contains(err.Error(), "signature mismatch") {
		t.Fatalf("tampered signature error = %v", err)
	}
	provenancePublic, provenancePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statement := ExternalProvenance{SchemaVersion: 1, ModuleID: "worker-a", ArtifactSHA256: hex.EncodeToString(digest[:]), ReleaseID: "release-1", BuildProfile: "standard", SourceRevision: "revision-1"}
	payload, err := json.Marshal(struct {
		SchemaVersion  uint32 `json:"schema_version"`
		ModuleID       string `json:"module_id"`
		ArtifactSHA256 string `json:"artifact_sha256"`
		ReleaseID      string `json:"release_id"`
		BuildProfile   string `json:"build_profile"`
		SourceRevision string `json:"source_revision"`
	}{statement.SchemaVersion, statement.ModuleID, statement.ArtifactSHA256, statement.ReleaseID, statement.BuildProfile, statement.SourceRevision})
	if err != nil {
		t.Fatal(err)
	}
	statement.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(provenancePrivate, payload))
	provenancePath := filepath.Join(t.TempDir(), "worker.provenance.json")
	raw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(provenancePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyExternalExecutable(executable, hex.EncodeToString(digest[:]), "", nil, provenancePath, provenancePublic, "worker-a", "release-1", "standard"); err != nil {
		t.Fatalf("valid provenance rejected: %v", err)
	}
	if err := verifyExternalExecutable(executable, hex.EncodeToString(digest[:]), "", nil, provenancePath, provenancePublic, "worker-a", "release-2", "standard"); err == nil || !strings.Contains(err.Error(), "release mismatch") {
		t.Fatalf("provenance release mismatch error = %v", err)
	}
}

func TestNewExternalFactoryCopiesLaunchPolicy(t *testing.T) {
	provenanceKey := []byte(strings.Repeat("p", ed25519.PublicKeySize))
	spec := ExternalModuleSpec{
		ModuleID: "worker-a", Executable: "/bin/worker", SocketPath: "/tmp/worker.sock",
		Args: []string{"--safe"}, AuthToken: []byte("secret"), ExpectedSHA256: strings.Repeat("a", 64),
		ProvenancePath: "/tmp/worker.provenance.json", ProvenancePublicKey: provenanceKey,
		RequiredCapabilities: []ExternalCapability{ExternalCapabilityAuditBatch},
	}
	factory, err := NewExternalFactory(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.AuthToken[0] = 'x'
	spec.Args[0] = "--changed"
	spec.ProvenancePublicKey[0] = 'X'
	instance, err := factory.Prepare(context.Background(), PrepareRequest{ModuleID: "worker-a"})
	if err != nil {
		t.Fatal(err)
	}
	supervisor, ok := instance.(*ExternalSupervisor)
	if !ok || string(supervisor.spec.AuthToken) != "secret" || supervisor.spec.Args[0] != "--safe" || string(supervisor.spec.ProvenancePublicKey) != strings.Repeat("p", ed25519.PublicKeySize) {
		t.Fatalf("prepared instance = %#v", instance)
	}
}

func TestExternalSupervisorStartsAndStopsDigestPinnedWorker(t *testing.T) {
	spec := signedLocalExternalSpec(t)
	supervisor, err := NewExternalSupervisor(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := supervisor.Heartbeat(context.Background()); err != nil {
		t.Fatalf("Heartbeat() error = %v", err)
	}
	if err := supervisor.DeliverAuditBatch(context.Background(), []audit.Event{{ID: "event-1", Type: audit.EventLogin}}); err != nil {
		t.Fatalf("DeliverAuditBatch() error = %v", err)
	}
	if err := supervisor.Quiesce(context.Background()); err != nil {
		t.Fatalf("Quiesce() error = %v", err)
	}
	if err := supervisor.DeliverAuditBatch(context.Background(), []audit.Event{{Type: audit.EventLogin}}); err == nil {
		t.Fatal("DeliverAuditBatch() after quiesce succeeded")
	}
	if err := supervisor.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if _, err := os.Lstat(spec.SocketPath); !os.IsNotExist(err) {
		t.Fatalf("socket still exists, err = %v", err)
	}
}

func TestExternalFactoryParticipatesInGenerationLifecycle(t *testing.T) {
	factory, err := NewExternalFactory(signedLocalExternalSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := New([]Definition{{ID: "worker-a", Factory: factory}}, Options{DrainTimeout: 2 * time.Second, LifecycleTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Activate(context.Background(), "worker-a", nil); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	lease, err := manager.Acquire("worker-a", LeaseRequest)
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	retirement, err := manager.Disable("worker-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := retirement.Wait(context.Background()); err != nil {
		t.Fatalf("retirement error = %v", err)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func signedLocalExternalSpec(t *testing.T) ExternalModuleSpec {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "worker.sock")
	t.Setenv(externalWorkerSocketEnv, socketPath)
	t.Setenv(externalWorkerTokenEnv, "secret")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signaturePath := filepath.Join(t.TempDir(), "worker.sig")
	signature := ed25519.Sign(privateKey, digest[:])
	if err := os.WriteFile(signaturePath, []byte(base64.StdEncoding.EncodeToString(signature)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return ExternalModuleSpec{
		ModuleID: "worker-a", Executable: executable, Args: []string{"-test.run=^TestExternalWorker$"},
		SocketPath: socketPath, AuthToken: []byte("secret"), ExpectedSHA256: hex.EncodeToString(digest[:]),
		SignaturePath: signaturePath, SignaturePublicKey: publicKey,
		RequiredCapabilities: []ExternalCapability{ExternalCapabilityAuditBatch},
		StartupTimeout:       5 * time.Second, RequestTimeout: 2 * time.Second,
	}
}

func TestExternalSupervisorRemoteMTLSAndSPIFFE(t *testing.T) {
	serverTLS, clientTLS := externalMTLSConfigs(t)
	serverTLS, err := RequireExternalSPIFFEPeer(serverTLS, "spiffe://example.org/host")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go serveExternalTLSWorker(listener, serverTLS, done)
	supervisor, err := NewExternalSupervisor(ExternalModuleSpec{
		ModuleID: "worker-a", RemoteAddress: listener.Addr().String(), AuthToken: []byte("secret"),
		TLSConfig: clientTLS, PeerSPIFFEID: "spiffe://example.org/worker",
		RequiredCapabilities: []ExternalCapability{ExternalCapabilityAuditBatch},
		StartupTimeout:       2 * time.Second, RequestTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatalf("remote Start() error = %v", err)
	}
	if err := supervisor.Heartbeat(context.Background()); err != nil {
		t.Fatalf("remote Heartbeat() error = %v", err)
	}
	if err := supervisor.Stop(context.Background()); err != nil {
		t.Fatalf("remote Stop() error = %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("remote worker error = %v", err)
	}
}

func externalMTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	ca, caKey, roots := externalTestCA(t)
	server := externalTestCertificate(t, ca, caKey, 2, "worker.example", "spiffe://example.org/worker", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	client := externalTestCertificate(t, ca, caKey, 3, "", "spiffe://example.org/host", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	return &tls.Config{Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12}, &tls.Config{
		Certificates: []tls.Certificate{client}, RootCAs: roots, ServerName: "worker.example", MinVersion: tls.VersionTLS12,
	}
}

func externalTestCA(t *testing.T) (*x509.Certificate, ed25519.PrivateKey, *x509.CertPool) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return certificate, private, roots
}

func externalTestCertificate(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey, serial int64, dns, identity string, usages []x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	dnsNames := []string(nil)
	if dns != "" {
		dnsNames = []string{dns}
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: dnsNames, URIs: []*url.URL{uri}, ExtKeyUsage: usages, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func serveExternalTLSWorker(listener net.Listener, config *tls.Config, done chan<- error) {
	conn, err := listener.Accept()
	if err != nil {
		done <- err
		return
	}
	done <- ServeExternalConnection(context.Background(), tls.Server(conn, config), ExternalServerOptions{
		ModuleID: "worker-a", AuthToken: []byte("secret"), Capabilities: []ExternalCapability{ExternalCapabilityAuditBatch},
	}, &externalAuditCapture{})
}

func externalClientRoundTrip(t *testing.T, reader *bufio.Reader, writer *bufio.Writer, token, id, method string, params any) externalResponse {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeExternalMessage(writer, defaultExternalFrameBytes, externalRequest{ID: id, Method: method, Token: token, Params: raw}); err != nil {
		t.Fatal(err)
	}
	var response externalResponse
	if err := readExternalMessage(reader, defaultExternalFrameBytes, &response); err != nil {
		t.Fatal(err)
	}
	if response.ID != id {
		t.Fatalf("response id = %q, want %q", response.ID, id)
	}
	return response
}
