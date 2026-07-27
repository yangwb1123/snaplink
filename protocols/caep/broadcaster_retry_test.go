package caep_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/caep"
	"github.com/yangwb1123/snaplink/shared/core"
)

// flakyReceiver answers 503 for the first `failures` POSTs (the shipped
// receiver's transient signal — receiver_receive.go maps a post-validation
// store outage to 500 so transmitters retry), then 202. It records EVERY
// request body so the test can prove each attempt carried a FRESH SET.
type flakyReceiver struct {
	mu       sync.Mutex
	failures int
	bodies   []string
	accepted int
}

func (r *flakyReceiver) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		defer r.mu.Unlock()
		r.bodies = append(r.bodies, string(body))
		if r.failures > 0 {
			r.failures--
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		r.accepted++
		w.WriteHeader(http.StatusAccepted)
	}
}

func (r *flakyReceiver) acceptedCount() int { r.mu.Lock(); defer r.mu.Unlock(); return r.accepted }
func (r *flakyReceiver) attempts() int      { r.mu.Lock(); defer r.mu.Unlock(); return len(r.bodies) }
func (r *flakyReceiver) allBodies() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.bodies...)
}

// TestTransmitter_RetryDeliversExactlyOnce: receiver fails twice with a
// retryable 503, then accepts — the SET must land EXACTLY once, and each
// attempt must carry a freshly minted SET (new jti: the receiver's
// jti-replay MarkSeen fires before its revoke action, so a byte-identical
// retransmit would be rejected as a replay).
func TestTransmitter_RetryDeliversExactlyOnce(t *testing.T) {
	t.Parallel()
	recv := &flakyReceiver{failures: 2}
	srv := httptest.NewTLSServer(recv.handler())
	defer srv.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "owner", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	metric := &capturingMetric{}
	tx := caep.NewTransmitter(iss, store,
		caep.WithHTTPClient(testHTTPClient(srv)),
		caep.WithMetric(metric.record),
		caep.WithDeliveryRetry(5),
		caep.WithDeliveryRetryBackoff(time.Millisecond, 5*time.Millisecond),
	)
	_ = tx.Record(ctx, &audit.Event{Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "u"})

	waitFor(t, func() bool { return recv.acceptedCount() == 1 }, "SET accepted after retries")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := recv.attempts(); got != 3 {
		t.Fatalf("attempts = %d, want 3 (2 x 503 + 1 x 202)", got)
	}
	if got := recv.acceptedCount(); got != 1 {
		t.Fatalf("accepted = %d, want exactly 1", got)
	}
	seen := map[string]bool{}
	for _, body := range recv.allBodies() {
		v := verifySET(t, body, iss.PublicKey())
		if seen[v.jti] {
			t.Fatalf("jti %q reused across attempts — retry must re-mint", v.jti)
		}
		seen[v.jti] = true
	}
	if metric.has(caep.OutcomeFailed) {
		t.Error("eventual success still recorded a failed outcome")
	}
	if !metric.has(caep.OutcomeSuccess) {
		t.Error("no success outcome recorded")
	}
}

// TestTransmitter_PermanentRejectionNotRetried: a 400 means the receiver
// REJECTED the SET — retrying re-sends the same rejection, so exactly one
// attempt happens even with retry enabled.
func TestTransmitter_PermanentRejectionNotRetried(t *testing.T) {
	t.Parallel()
	recv := &flakyReceiver{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.ReadAll(req.Body)
		recv.mu.Lock()
		recv.bodies = append(recv.bodies, "")
		recv.mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "owner", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	metric := &capturingMetric{}
	tx := caep.NewTransmitter(iss, store,
		caep.WithHTTPClient(testHTTPClient(srv)),
		caep.WithMetric(metric.record),
		caep.WithDeliveryRetry(5),
		caep.WithDeliveryRetryBackoff(time.Millisecond, 5*time.Millisecond),
	)
	_ = tx.Record(ctx, &audit.Event{Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "u"})
	waitFor(t, func() bool { return metric.has(caep.OutcomeFailed) }, "400 recorded as failed")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := recv.attempts(); got != 1 {
		t.Fatalf("attempts = %d, want 1 (4xx is permanent)", got)
	}
}

// TestTransmitter_CloseAbortsPendingBackoff: with a 30s initial backoff a
// retry chain would pin shutdown for minutes; Close must abort the pending
// backoff and drain promptly.
func TestTransmitter_CloseAbortsPendingBackoff(t *testing.T) {
	t.Parallel()
	srv := newTLSStatusReceiver(http.StatusServiceUnavailable)
	defer srv.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "owner", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	tx := caep.NewTransmitter(iss, store,
		caep.WithHTTPClient(testHTTPClient(srv)),
		caep.WithDeliveryRetry(3),
		caep.WithDeliveryRetryBackoff(30*time.Second, 60*time.Second),
	)
	_ = tx.Record(ctx, &audit.Event{Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "u"})
	time.Sleep(100 * time.Millisecond) // let the first attempt fail and enter the 30s backoff
	start := time.Now()
	if err := tx.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Close took %v — pending backoff was not aborted", elapsed)
	}
}
