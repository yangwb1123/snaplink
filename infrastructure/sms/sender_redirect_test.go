package sms

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	redirectBodySentinel = "redirect-response-body-must-not-surface"
	redirectTargetPath   = "/redirect-target-must-not-be-requested"
)

type redirectMode string

const (
	redirectSameOrigin  redirectMode = "same-origin"
	redirectCrossOrigin redirectMode = "cross-origin"
	redirectHTTPSToHTTP redirectMode = "https-to-http"
)

// TestSender_Send_RejectsRedirects proves every redirect status is returned to
// Send as a terminal non-2xx response. The redirect source and destination
// counters are atomic and the owned servers are closed via t.Cleanup, so a
// failed regression cannot leave an in-flight second request behind.
func TestSender_Send_RejectsRedirects(t *testing.T) {
	t.Parallel()
	statuses := []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	}
	modes := []redirectMode{
		redirectSameOrigin,
		redirectCrossOrigin,
		redirectHTTPSToHTTP,
	}
	for _, status := range statuses {
		status := status
		for _, mode := range modes {
			mode := mode
			t.Run(fmt.Sprintf("%d/%s", status, mode), func(t *testing.T) {
				t.Parallel()
				assertRedirectRejected(t, status, mode)
			})
		}
	}
}

func assertRedirectRejected(t *testing.T, status int, mode redirectMode) {
	t.Helper()
	var sourceHits, targetHits atomic.Int64

	writeRedirect := func(w http.ResponseWriter, location string) {
		w.Header().Set("Location", location)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(redirectBodySentinel))
	}
	countTarget := func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}

	var (
		source   *httptest.Server
		location string
	)
	switch mode {
	case redirectSameOrigin:
		source = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == redirectTargetPath {
				countTarget(w, r)
				return
			}
			sourceHits.Add(1)
			writeRedirect(w, redirectTargetPath)
		}))
	case redirectCrossOrigin:
		target := httptest.NewServer(http.HandlerFunc(countTarget))
		t.Cleanup(target.Close)
		location = target.URL + redirectTargetPath
		source = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			sourceHits.Add(1)
			writeRedirect(w, location)
		}))
	case redirectHTTPSToHTTP:
		target := httptest.NewServer(http.HandlerFunc(countTarget))
		t.Cleanup(target.Close)
		location = target.URL + redirectTargetPath
		source = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			sourceHits.Add(1)
			writeRedirect(w, location)
		}))
	default:
		t.Fatalf("unknown redirect mode %q", mode)
	}
	t.Cleanup(source.Close)

	s, err := New(testConfig(source.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if mode == redirectHTTPSToHTTP {
		trustSenderTestTLS(t, s, source)
	}

	err = s.Send(context.Background(), "+15551234567", "123456")
	if err == nil {
		t.Fatal("Send succeeded on a redirect response; redirect may have been followed")
	}
	wantErr := fmt.Sprintf("sms: provider returned unexpected status %d", status)
	if err.Error() != wantErr {
		t.Fatalf("Send error = %q, want status-only mapping %q", err, wantErr)
	}
	if strings.Contains(err.Error(), redirectBodySentinel) {
		t.Fatalf("Send error exposed redirect response body: %v", err)
	}
	if strings.Contains(err.Error(), redirectTargetPath) {
		t.Fatalf("Send error exposed redirect Location: %v", err)
	}
	if got := sourceHits.Load(); got != 1 {
		t.Errorf("source requests = %d, want exactly 1", got)
	}
	if got := targetHits.Load(); got != 0 {
		t.Errorf("redirect destination requests = %d, want 0", got)
	}
}

// TestSender_Send_DirectTLSSuccessWithExplicitTrust proves a terminal 2xx
// response is unaffected and that the HTTPS fixture trusts only the owned
// test server certificate through an explicit root pool.
func TestSender_Send_DirectTLSSuccessWithExplicitTrust(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(ts.Close)

	s, err := New(testConfig(ts.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	trustSenderTestTLS(t, s, ts)
	if err := s.Send(context.Background(), "+15551234567", "123456"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("requests = %d, want exactly 1", got)
	}
}

// trustSenderTestTLS configures a test-only transport that trusts exactly the
// supplied httptest certificate. It never disables verification or mutates
// process-wide roots.
func trustSenderTestTLS(t *testing.T, s *Sender, srv *httptest.Server) {
	t.Helper()
	cert := srv.Certificate()
	if cert == nil {
		t.Fatal("httptest TLS server has no certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	}
	s.client.Transport = transport
	t.Cleanup(transport.CloseIdleConnections)
}
