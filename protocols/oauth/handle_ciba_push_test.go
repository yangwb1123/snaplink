package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/protocols/oauth/oauthspi"
)

// memPushDeadLetterStore is a small REAL in-memory oauthspi.CIBAPushDeadLetterStore
// for these tests — not a mock. protocols/oauth cannot import
// infrastructure/defaultimpl/memorystoreoauth (that package imports oauth,
// so doing so here would cycle), so this mirrors handler_harness_test.go's
// convention of hand-rolling a minimal, functioning in-memory store.
type memPushDeadLetterStore struct {
	mu      sync.Mutex
	records []memDeadLetterRecord
}

type memDeadLetterRecord struct {
	deliveryID string
	payload    oauthspi.PushPayload
	err        error
}

func (s *memPushDeadLetterStore) Record(_ context.Context, deliveryID string, payload oauthspi.PushPayload, err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, memDeadLetterRecord{deliveryID, payload, err})
	return nil
}

func (s *memPushDeadLetterStore) ListUnacknowledged(context.Context) ([]string, error) {
	return nil, nil
}
func (s *memPushDeadLetterStore) Replay(context.Context, string) (*oauthspi.PushPayload, error) {
	return nil, nil
}
func (s *memPushDeadLetterStore) Acknowledge(context.Context, string) error { return nil }

func (s *memPushDeadLetterStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

var _ oauthspi.CIBAPushDeadLetterStore = (*memPushDeadLetterStore)(nil)

// TestCIBAPushNotifier_SuccessDelivery proves NotifyPush POSTs the payload
// (as JSON) to the resolved URI, authenticated with the client_notification_token
// as a bearer credential — CIBA Core §10.3.1's exact wire shape.
func TestCIBAPushNotifier_SuccessDelivery(t *testing.T) {
	t.Parallel()
	var gotAuth string
	var gotBody oauthspi.PushPayload
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	n := NewCIBAPushNotifier(
		func(context.Context, string) (string, error) { return ts.URL, nil },
		WithCIBAPushHTTPClient(ts.Client()),
	)
	payload := oauthspi.PushPayload{AuthReqID: "areq-1", AccessToken: "AT", TokenType: "Bearer", ExpiresIn: 3600}
	if err := n.NotifyPush(context.Background(), "rp", "areq-1", "notify-tok", payload); err != nil {
		t.Fatalf("NotifyPush: %v", err)
	}
	if gotAuth != "Bearer notify-tok" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer notify-tok")
	}
	if gotBody.AuthReqID != "areq-1" || gotBody.AccessToken != "AT" || gotBody.TokenType != "Bearer" || gotBody.ExpiresIn != 3600 {
		t.Errorf("delivered payload = %+v", gotBody)
	}
}

// TestCIBAPushNotifier_FailureRecordsDeadLetter proves an always-failing
// endpoint exhausts retries and hands the payload to the wired dead-letter
// store instead of silently dropping it.
func TestCIBAPushNotifier_FailureRecordsDeadLetter(t *testing.T) {
	t.Parallel()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	dl := &memPushDeadLetterStore{}
	n := NewCIBAPushNotifier(
		func(context.Context, string) (string, error) { return ts.URL, nil },
		WithCIBAPushHTTPClient(ts.Client()),
		WithCIBAPushDeadLetterStore(dl),
		WithCIBAPushMaxRetries(0), // single attempt: fast test, no backoff
	)
	payload := oauthspi.PushPayload{AuthReqID: "areq-2", AccessToken: "AT2"}
	err := n.NotifyPush(context.Background(), "rp", "areq-2", "tok", payload)
	if err == nil {
		t.Fatal("expected delivery error after retries exhausted")
	}
	if dl.count() != 1 {
		t.Fatalf("dead-letter records = %d, want 1", dl.count())
	}
}

// TestCIBAPushNotifier_Timeout proves a hanging endpoint fails within the
// configured client timeout (rather than blocking forever) and the failure
// is dead-lettered like any other delivery failure.
func TestCIBAPushNotifier_Timeout(t *testing.T) {
	t.Parallel()
	block := make(chan struct{})
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-block // never respond before the test's client timeout
	}))
	// A single Cleanup (not two defers) so the unblock always runs BEFORE
	// ts.Close(): httptest.Server.Close waits for outstanding requests to
	// finish, so closing block after Close would deadlock the test.
	t.Cleanup(func() {
		close(block)
		ts.Close()
	})

	client := ts.Client()
	client.Timeout = 50 * time.Millisecond
	dl := &memPushDeadLetterStore{}
	n := NewCIBAPushNotifier(
		func(context.Context, string) (string, error) { return ts.URL, nil },
		WithCIBAPushHTTPClient(client),
		WithCIBAPushDeadLetterStore(dl),
		WithCIBAPushMaxRetries(0),
	)
	start := time.Now()
	err := n.NotifyPush(context.Background(), "rp", "areq-3", "tok", oauthspi.PushPayload{AuthReqID: "areq-3"})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("NotifyPush took %v, want bounded by the client timeout", elapsed)
	}
	if dl.count() != 1 {
		t.Fatalf("dead-letter records = %d, want 1", dl.count())
	}
}

// TestCIBAPushNotifier_DefaultClientBlocksRedirects proves NewCIBAPushNotifier's
// own default client (no WithCIBAPushHTTPClient override) carries a
// CheckRedirect that treats any 3xx as terminal. Without this, a compromised
// or malicious registered delivery URI could pass validatePushURI's
// https-only gate and then 302 to an internal or non-https target, and Go's
// default http.Client would silently follow it (SSRF via redirect).
func TestCIBAPushNotifier_DefaultClientBlocksRedirects(t *testing.T) {
	t.Parallel()
	n := NewCIBAPushNotifier(func(context.Context, string) (string, error) { return "https://example.test", nil })
	pn, ok := n.(*cibaPushNotifier)
	if !ok {
		t.Fatalf("NewCIBAPushNotifier returned %T, want *cibaPushNotifier", n)
	}
	if pn.client.CheckRedirect == nil {
		t.Fatal("default client has no CheckRedirect: a 3xx delivery response would be silently followed")
	}
	if err := pn.client.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect(...) = %v, want http.ErrUseLastResponse", err)
	}
}

// TestCIBAPushNotifier_DoesNotFollowRedirect proves the no-redirect policy
// holds end to end on NewCIBAPushNotifier's OWN default client (no
// WithCIBAPushHTTPClient override) — not a manually reconstructed one — so
// this actually pins the production code path: an https delivery endpoint
// that 302s to a second server must never have that second server
// contacted, and the push attempt must be treated as a failure exactly like
// any other non-2xx response (mirrors TestCIBAPushNotifier_FailureRecordsDeadLetter,
// swapping the redirect in for the 500). The redirect target is a plain
// HTTP server (not TLS) so that "never contacted" is unambiguous — it can't
// be confused with an unrelated TLS-trust failure from dialing a second
// self-signed server.
func TestCIBAPushNotifier_DoesNotFollowRedirect(t *testing.T) {
	t.Parallel()
	var redirectTargetHit bool
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectTargetHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer ts.Close()

	dl := &memPushDeadLetterStore{}
	n := NewCIBAPushNotifier(
		func(context.Context, string) (string, error) { return ts.URL, nil },
		WithCIBAPushDeadLetterStore(dl),
		WithCIBAPushMaxRetries(0), // single attempt: fast test, no backoff
	)
	// Borrow ONLY ts.Client()'s Transport (the self-signed cert trust) so the
	// request can reach ts at all; leave CheckRedirect exactly as
	// NewCIBAPushNotifier constructed it — that field is the actual thing
	// under test here.
	pn := n.(*cibaPushNotifier)
	pn.client.Transport = ts.Client().Transport
	payload := oauthspi.PushPayload{AuthReqID: "areq-7", AccessToken: "AT7"}
	err := n.NotifyPush(context.Background(), "rp", "areq-7", "tok", payload)
	if err == nil {
		t.Fatal("expected delivery error: a 3xx response must not be treated as success")
	}
	if redirectTargetHit {
		t.Fatal("redirect target received a request: CheckRedirect failed to block the follow")
	}
	if dl.count() != 1 {
		t.Fatalf("dead-letter records = %d, want 1", dl.count())
	}
}

// TestCIBAPushNotifier_NoEndpointIsNoOp proves a client with no registered
// delivery endpoint degrades silently (nil, no dead-letter) — mirroring
// CIBAPingNotifier's "client uses poll instead" contract.
func TestCIBAPushNotifier_NoEndpointIsNoOp(t *testing.T) {
	t.Parallel()
	dl := &memPushDeadLetterStore{}
	n := NewCIBAPushNotifier(
		func(context.Context, string) (string, error) { return "", nil },
		WithCIBAPushDeadLetterStore(dl),
	)
	if err := n.NotifyPush(context.Background(), "rp", "areq-4", "tok", oauthspi.PushPayload{}); err != nil {
		t.Fatalf("expected nil (no endpoint = poll fallback), got %v", err)
	}
	if dl.count() != 0 {
		t.Fatalf("dead-letter records = %d, want 0 (not a delivery failure)", dl.count())
	}
}

// TestCIBAPushNotifier_RejectsNonHTTPS locks the CIBA Core §10.3 delivery
// contract: the payload carries a live bearer token, so an http:// (or
// malformed) delivery URI is a hard configuration error, never attempted.
func TestCIBAPushNotifier_RejectsNonHTTPS(t *testing.T) {
	t.Parallel()
	n := NewCIBAPushNotifier(func(context.Context, string) (string, error) { return "http://insecure.example", nil })
	if err := n.NotifyPush(context.Background(), "rp", "areq-5", "tok", oauthspi.PushPayload{}); err == nil {
		t.Fatal("expected an error for a non-https delivery URI")
	}
}

// TestCIBAPushNotifier_ResolverErrorPropagates proves a getDeliveryURI
// error (distinct from "no endpoint") propagates rather than being
// swallowed as a no-op.
func TestCIBAPushNotifier_ResolverErrorPropagates(t *testing.T) {
	t.Parallel()
	wantErr := context.DeadlineExceeded
	n := NewCIBAPushNotifier(func(context.Context, string) (string, error) { return "", wantErr })
	if err := n.NotifyPush(context.Background(), "rp", "areq-6", "tok", oauthspi.PushPayload{}); err != wantErr {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}
