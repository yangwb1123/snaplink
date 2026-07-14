package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/protocols/oauth/oauthspi"
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
