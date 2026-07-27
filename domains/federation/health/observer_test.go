package health_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/federation"
	"github.com/yangwb1123/snaplink/domains/federation/health"
)

// stubFetcher is a hand-written federation.EntityStatementFetcher test double
// (no real network) — the same style as federation's own fakeFetcher
// (trust_chain_test.go), used here to drive the decorator's success/failure
// bookkeeping in isolation from any real TLS handshake.
type stubFetcher struct {
	body []byte
	err  error
}

func (s *stubFetcher) FetchEntityConfiguration(context.Context, string) ([]byte, error) {
	return s.body, s.err
}

func (s *stubFetcher) FetchSubordinateStatement(context.Context, string, string, string) ([]byte, error) {
	return s.body, s.err
}

var _ federation.EntityStatementFetcher = (*stubFetcher)(nil)

func TestNewObservingFetcher_NilHealthIsNoop(t *testing.T) {
	t.Parallel()
	base := &stubFetcher{body: []byte("x")}
	got := health.NewObservingFetcher(base, nil)
	if got != base {
		t.Fatal("NewObservingFetcher(base, nil) must return base unchanged (default-off, byte-identical)")
	}
}

func TestNewObservingFetcher_NilBaseIsNoop(t *testing.T) {
	t.Parallel()
	store := health.NewMemoryConnectionHealth()
	if got := health.NewObservingFetcher(nil, store); got != nil {
		t.Fatalf("NewObservingFetcher(nil, store) = %v, want nil", got)
	}
}

func TestObservingFetcher_RecordsSuccessAndFailure_PreservesResult(t *testing.T) {
	t.Parallel()
	store := health.NewMemoryConnectionHealth()

	okFetcher := &stubFetcher{body: []byte(`{"iss":"https://ok.test"}`)}
	wrapped := health.NewObservingFetcher(okFetcher, store)
	body, err := wrapped.FetchEntityConfiguration(context.Background(), "https://ok.test")
	if err != nil || string(body) != `{"iss":"https://ok.test"}` {
		t.Fatalf("wrapped fetch must return the SAME result as the base fetcher: body=%q err=%v", body, err)
	}
	peers := store.List()
	if len(peers) != 1 || peers[0].PeerID != "https://ok.test" || peers[0].LastSuccessAt.IsZero() {
		t.Fatalf("success not recorded: %+v", peers)
	}
	// No real TLS handshake occurred (stubFetcher does no network I/O), so the
	// observer must not fabricate a cert expiry.
	if !peers[0].CertNotAfter.IsZero() {
		t.Fatalf("CertNotAfter = %v, want zero (no TLS handshake observed)", peers[0].CertNotAfter)
	}

	failErr := errors.New("federation: fetch status 500")
	failFetcher := &stubFetcher{err: failErr}
	wrapped = health.NewObservingFetcher(failFetcher, store)
	_, err = wrapped.FetchSubordinateStatement(context.Background(), "https://superior.test/fetch", "https://superior.test", "https://ok.test")
	if !errors.Is(err, failErr) {
		t.Fatalf("wrapped fetch must return the SAME error as the base fetcher: %v", err)
	}
	peers = store.List()
	var superior health.PeerHealth
	for _, p := range peers {
		if p.PeerID == "https://superior.test" {
			superior = p
		}
	}
	if superior.ConsecutiveFailures != 1 || superior.LastError != failErr.Error() {
		t.Fatalf("failure not recorded against the issuer (peer): %+v", superior)
	}
}

// realTLSFetcher performs an ACTUAL http.Client.Do against an https URL,
// propagating ctx (and therefore any httptrace.ClientTrace the caller
// attached) exactly like the production httpFetcher does. It intentionally
// bypasses federation's SSRF gate (validateFederationURL would reject a
// loopback httptest server) — this is a test-only fetcher proving the
// observer's httptrace-based cert capture against a REAL TLS handshake, the
// same pattern federation's own fetcher_test.go uses (redirectTestFetcher)
// to test real HTTP behavior without depending on the unexported production
// fetcher.
type realTLSFetcher struct{ client *http.Client }

func (f *realTLSFetcher) FetchEntityConfiguration(ctx context.Context, entityID string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, entityID, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 0, 64)
	tmp := make([]byte, 64)
	for {
		n, rerr := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if rerr != nil {
			break
		}
	}
	return buf, nil
}

func (f *realTLSFetcher) FetchSubordinateStatement(ctx context.Context, endpoint, iss, sub string) ([]byte, error) {
	return f.FetchEntityConfiguration(ctx, endpoint)
}

func TestObservingFetcher_CapturesRealTLSLeafCertExpiry(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	store := health.NewMemoryConnectionHealth()
	wrapped := health.NewObservingFetcher(&realTLSFetcher{client: srv.Client()}, store)

	_, err := wrapped.FetchEntityConfiguration(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchEntityConfiguration: %v", err)
	}

	peers := store.List()
	if len(peers) != 1 {
		t.Fatalf("List() len = %d, want 1", len(peers))
	}
	got := peers[0].CertNotAfter
	want := srv.Certificate().NotAfter
	if !got.Equal(want) {
		t.Fatalf("CertNotAfter = %v, want %v (the httptest server's own leaf cert NotAfter)", got, want)
	}
	if peers[0].CertObservedAt.IsZero() {
		t.Fatal("CertObservedAt not stamped")
	}
}

func TestObservingFetcher_KeepAliveReuseKeepsPriorExpiry(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	store := health.NewMemoryConnectionHealth()
	client := srv.Client()
	wrapped := health.NewObservingFetcher(&realTLSFetcher{client: client}, store)

	// First call: fresh handshake, cert observed.
	if _, err := wrapped.FetchEntityConfiguration(context.Background(), srv.URL); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	first := store.List()[0]
	if first.CertNotAfter.IsZero() {
		t.Fatal("first fetch should have observed a cert expiry")
	}

	// Give the pooled connection a moment to settle, then fetch again — the
	// underlying transport is very likely to reuse the same connection (no
	// new TLSHandshakeDone), yet CertNotAfter must remain the same value
	// rather than being blanked.
	time.Sleep(20 * time.Millisecond)
	if _, err := wrapped.FetchEntityConfiguration(context.Background(), srv.URL); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	second := store.List()[0]
	if !second.CertNotAfter.Equal(first.CertNotAfter) {
		t.Fatalf("CertNotAfter changed across calls: %v -> %v", first.CertNotAfter, second.CertNotAfter)
	}
}
