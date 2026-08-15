package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/config"
	discoveryv1 "github.com/yangwb1123/snaplink/gen/proto/discovery/v1"
	"github.com/yangwb1123/snaplink/interfaces/grpcserver"
	"github.com/yangwb1123/snaplink/platform/registry/memory"
	"github.com/yangwb1123/snaplink/shared/spi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
)

// ---------------------------------------------------------------------------
// Decision 5 matrix — decideGRPCTransport
// ---------------------------------------------------------------------------

func TestDecideGRPCTransport_Matrix(t *testing.T) {
	rows := []struct {
		name        string
		listen      string
		tlsCert     string
		tlsKey      string
		grpcCert    string
		grpcKey     string
		insecure    bool
		wantMode    grpcTransportMode
		wantErrText string // substring the error must contain ("" = no error)
	}{
		{"grpc pair -> TLS", ":8081", "", "", "c.pem", "k.pem", false, grpcTransportTLS, ""},
		{"shared pair fallback -> TLS", ":8081", "c.pem", "k.pem", "", "", false, grpcTransportTLS, ""},
		{"mixed grpc cert + shared key -> TLS", ":8081", "", "k.pem", "c.pem", "", false, grpcTransportTLS, ""},
		{"grpc cert only -> error", ":8081", "", "", "c.pem", "", false, 0, "asymmetric"},
		{"shared key only -> error", ":8081", "", "k.pem", "", "", false, 0, "asymmetric"},
		{"no material + insecure -> opt-out", ":8081", "", "", "", "", true, grpcTransportOptOutPlaintext, ""},
		{"loopback 127.0.0.1", "127.0.0.1:8081", "", "", "", "", false, grpcTransportLoopbackPlaintext, ""},
		{"loopback ::1", "[::1]:8081", "", "", "", "", false, grpcTransportLoopbackPlaintext, ""},
		{"loopback localhost", "localhost:8081", "", "", "", "", false, grpcTransportLoopbackPlaintext, ""},
		{"loopback 127.0.0.2 (127/8 pinned)", "127.0.0.2:8081", "", "", "", "", false, grpcTransportLoopbackPlaintext, ""},
		{"empty host :8081 NOT loopback", ":8081", "", "", "", "", false, 0, "plaintext"},
		{"0.0.0.0 NOT loopback", "0.0.0.0:8081", "", "", "", "", false, 0, "plaintext"},
		{"[::] NOT loopback", "[::]:8081", "", "", "", "", false, 0, "plaintext"},
		{"hostname NOT loopback", "grpc.example.com:8081", "", "", "", "", false, 0, "plaintext"},
		{"material + insecure -> error", ":8081", "c.pem", "k.pem", "", "", true, 0, "conflicts"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got, err := decideGRPCTransport(r.listen, r.tlsCert, r.tlsKey, r.grpcCert, r.grpcKey, r.insecure)
			if r.wantErrText != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got mode %v", r.wantErrText, got.mode)
				}
				if !strings.Contains(err.Error(), r.wantErrText) {
					t.Errorf("error %q does not contain %q", err, r.wantErrText)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.mode != r.wantMode {
				t.Errorf("mode = %v, want %v", got.mode, r.wantMode)
			}
			if r.wantMode == grpcTransportTLS {
				if got.cert != "c.pem" || got.key != "k.pem" {
					t.Errorf("resolved material = %q/%q, want c.pem/k.pem", got.cert, got.key)
				}
			}
		})
	}

	// The fail-closed error names all three resolutions (operators need the
	// escape hatches without reading source).
	_, err := decideGRPCTransport(":8081", "", "", "", "", false)
	if err == nil {
		t.Fatal("stock run must fail closed")
	}
	for _, hint := range []string{"-grpc-tls-cert", "-grpc-tls-key", "loopback", "-grpc-insecure"} {
		if !strings.Contains(err.Error(), hint) {
			t.Errorf("fail-closed error missing hint %q: %v", hint, err)
		}
	}
}

// ---------------------------------------------------------------------------
// startGRPCServer in-process acceptance (QA F4 — no exec harness exists)
// ---------------------------------------------------------------------------

func TestStartGRPCServer_StockRunFailsClosed(t *testing.T) {
	// The decision errors before newGRPCServer touches the app, so nil is
	// safe for the failing rows.
	errCh := make(chan error, 2)
	_, err := startGRPCServer(nil, ":8081", spi.NopLogger{}, "", "", "", "", false, errCh)
	if err == nil {
		t.Fatal("stock run (:8081, no material) must fail closed")
	}
	if !strings.Contains(err.Error(), "-grpc-insecure") {
		t.Errorf("error must list the escape hatches, got %v", err)
	}

	// Asymmetric material is an error even with -grpc-insecure.
	_, err = startGRPCServer(nil, ":8081", spi.NopLogger{}, "", "", "cert.pem", "", false, errCh)
	if err == nil || !strings.Contains(err.Error(), "asymmetric") {
		t.Errorf("asymmetric pair: err = %v, want asymmetric error", err)
	}

	// -grpc-listen '' disables the listener entirely — the decision is
	// never invoked (nil app stays safe).
	got, err := startGRPCServer(nil, "", spi.NopLogger{}, "", "", "", "", false, errCh)
	if err != nil || got != nil {
		t.Errorf("disabled listener = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestStartGRPCServer_LoopbackAndOptOutBind(t *testing.T) {
	cfg := &config.Config{}
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)

	for name, insecure := range map[string]bool{"loopback": false, "operator opt-out": true} {
		t.Run(name, func(t *testing.T) {
			errCh := make(chan error, 2)
			grpcSrv, err := startGRPCServer(a, "127.0.0.1:0", quietLogger(), "", "", "", "", insecure, errCh)
			if err != nil {
				t.Fatalf("startGRPCServer: %v", err)
			}
			if grpcSrv == nil {
				t.Fatal("nil server")
			}
			if a.grpcHealthStop == nil {
				t.Error("grpcHealthStop not wired by newGRPCServer")
			}
			a.grpcHealthStop()
			grpcSrv.Stop()
			select {
			case err := <-errCh:
				if err != nil {
					t.Errorf("serve error: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("serve did not stop")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TLS1.2 floor on the gRPC listener (Decision 5, R5b)
// ---------------------------------------------------------------------------

// writeTestCertPair generates a fresh self-signed Ed25519 cert + key as PEM
// files (tls.LoadX509KeyPair reads files) with ServerName "grpc.test".
func writeTestCertPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "grpc.test"},
		DNSNames:     []string{"grpc.test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// tlsDialer dials the bufconn listener. The TLS handshake itself is done by
// grpc's credentials (the dialer just bridges the pipe), so the per-client
// tls.Config controls the offered version / verification.
func tlsDialer(ln *bufconn.Listener) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, _ string) (net.Conn, error) {
		return ln.DialContext(ctx)
	}
}

func TestGRPCServerOptions_TLSMinVersionFloor(t *testing.T) {
	cfg := &config.Config{}
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)

	certPath, keyPath := writeTestCertPair(t)
	opts, err := grpcServerOptions(a, grpcTransport{mode: grpcTransportTLS, cert: certPath, key: keyPath}, quietLogger(), nil)
	if err != nil {
		t.Fatalf("grpcServerOptions: %v", err)
	}
	ln := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer(opts...)
	discoveryv1.RegisterDiscoveryServer(s, grpcserver.NewDiscoveryService(memory.New()))
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() {
		s.Stop()
		_ = ln.Close()
	})

	// A TLS1.0-only client must be rejected by the TLS1.2 floor.
	oldTLS := &tls.Config{ServerName: "grpc.test", InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10}
	oldConn, err := grpc.NewClient("passthrough:///tls-floor",
		grpc.WithContextDialer(tlsDialer(ln)),
		grpc.WithTransportCredentials(credentials.NewTLS(oldTLS)))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer func() { _ = oldConn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dc := discoveryv1.NewDiscoveryClient(oldConn)
	_, err = dc.Discover(ctx, &discoveryv1.DiscoverRequest{ServiceName: "svc"})
	if err == nil {
		t.Fatal("TLS1.0-only client succeeded against a TLS1.2 floor")
	}
	if !strings.Contains(err.Error(), "tls") {
		t.Errorf("TLS1.0 rejection error = %v, want a tls handshake error", err)
	}

	// A modern client succeeds end-to-end.
	newTLS := &tls.Config{ServerName: "grpc.test", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	newConn, err := grpc.NewClient("passthrough:///tls-floor-ok",
		grpc.WithContextDialer(tlsDialer(ln)),
		grpc.WithTransportCredentials(credentials.NewTLS(newTLS)))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer func() { _ = newConn.Close() }()
	// An application-level error (NotFound from the empty registry) proves
	// the TLS1.2 handshake + dispatch completed; a transport/TLS error would
	// mean the floor wiring broke.
	if _, err := discoveryv1.NewDiscoveryClient(newConn).Discover(ctx, &discoveryv1.DiscoverRequest{ServiceName: "svc"}); err == nil || strings.Contains(err.Error(), "tls") || strings.Contains(err.Error(), "connection") {
		t.Fatalf("TLS1.2 RPC = %v, want an application-level error (handshake succeeded)", err)
	}
}

// ---------------------------------------------------------------------------
// -validate-only preflight (QA F5)
// ---------------------------------------------------------------------------

func TestValidateGRPCTransportPosture_PreflightsFailClosed(t *testing.T) {
	rows := []struct {
		name    string
		flags   runtimeFlags
		wantErr bool
	}{
		{"stock run fails", runtimeFlags{grpcListen: ":8081"}, true},
		{"loopback passes", runtimeFlags{grpcListen: "127.0.0.1:8081"}, false},
		{"disabled passes", runtimeFlags{grpcListen: ""}, false},
		{"opt-out passes", runtimeFlags{grpcListen: ":8081", grpcInsecure: true}, false},
		{"material passes", runtimeFlags{grpcListen: ":8081", grpcTLSCert: "c.pem", grpcTLSKey: "k.pem"}, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			err := validateGRPCTransportPosture(r.flags)
			if r.wantErr && err == nil {
				t.Fatal("want preflight error, got nil")
			}
			if !r.wantErr && err != nil {
				t.Fatalf("unexpected preflight error: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Shutdown drain ordering (QA F9)
// ---------------------------------------------------------------------------

// TestShutdownServers_HealthStopDrainsBeforeGracefulStop — the observability
// stop runs inside shutdownServers BEFORE GracefulStop, so a Watch client
// observes the NOT_SERVING drain transition while the RPC plane is still up,
// then the shutdown completes once the stream is closed.
func TestShutdownServers_HealthStopDrainsBeforeGracefulStop(t *testing.T) {
	cfg := &config.Config{}
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)

	grpcSrv, err := newGRPCServer(a, grpcTransport{mode: grpcTransportLoopbackPlaintext}, quietLogger())
	if err != nil {
		t.Fatalf("newGRPCServer: %v", err)
	}
	if a.grpcHealthStop == nil {
		t.Fatal("grpcHealthStop not wired")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = grpcSrv.Serve(ln) }()
	t.Cleanup(func() { grpcSrv.Stop() })

	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer func() { _ = conn.Close() }()
	hc := healthpb.NewHealthClient(conn)

	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := hc.Check(context.Background(), &healthpb.HealthCheckRequest{})
		if err == nil && resp.Status == healthpb.HealthCheckResponse_SERVING {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never became SERVING (err=%v)", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	wctx, wcancel := context.WithCancel(context.Background())
	defer wcancel()
	w, err := hc.Watch(wctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if st := recvHealthStatus(t, w, time.Second); st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("initial Watch status = %v, want SERVING", st)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownServers(ctx, quietLogger(), &http.Server{Addr: "127.0.0.1:0"}, nil, grpcSrv, a.grpcHealthStop)
	}()

	// The drain transition must arrive while shutdown is in progress.
	if st := recvHealthStatus(t, w, 2*time.Second); st != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("Watch during shutdown = %v, want NOT_SERVING (drain signal)", st)
	}
	// End the Watch stream (server-streaming: CloseSend alone would not end
	// it — the handler only stops on ctx cancel) so GracefulStop can finish.
	wcancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdownServers did not return")
	}
}

// recvHealthStatus receives one health Watch message within timeout.
func recvHealthStatus(t *testing.T, w healthpb.Health_WatchClient, timeout time.Duration) healthpb.HealthCheckResponse_ServingStatus {
	t.Helper()
	ch := make(chan healthpb.HealthCheckResponse_ServingStatus, 1)
	go func() {
		resp, err := w.Recv()
		if err != nil {
			ch <- healthpb.HealthCheckResponse_UNKNOWN
			return
		}
		ch <- resp.Status
	}()
	select {
	case st := <-ch:
		return st
	case <-time.After(timeout):
		t.Fatal("timed out waiting for health Watch status")
		return healthpb.HealthCheckResponse_UNKNOWN
	}
}

// ---------------------------------------------------------------------------
// Startup banner (QA F6)
// ---------------------------------------------------------------------------

// TestLogGRPCServices_BannerListsHealthAndReflection — the enumerated banner
// matches what grpcurl list returns: both reflection versions (v1alpha is
// registered by reflection.Register for legacy clients) plus health.
func TestLogGRPCServices_BannerListsHealthAndReflection(t *testing.T) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		all, _ := io.ReadAll(r) // EOF only after w.Close below
		done <- string(all)
	}()
	logGRPCServices(&config.Config{}, ":8081")
	_ = w.Close()
	os.Stdout = old
	out := <-done

	for _, want := range []string{
		"grpc.health.v1.Health",
		"grpc.reflection.v1.ServerReflection",
		"grpc.reflection.v1alpha.ServerReflection",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("banner missing %q:\n%s", want, out)
		}
	}
}
