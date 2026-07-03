package sse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// runStream starts HandleStream in a goroutine against a context that
// self-cancels after d, and returns a channel that closes when the handler
// returns. Callers MUST wait on the returned channel before reading w — the
// close(done) happens-after every write HandleStream made, so no race
// exists between the streaming goroutine and the test's later assertions
// (this is why these tests use a bounded timeout instead of an ad hoc sleep
// + concurrent body read, which would race with the writer under -race).
func runStream(b *Broker, heartbeat time.Duration, r *http.Request, w *httptest.ResponseRecorder, timeout time.Duration) <-chan struct{} {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	r = r.WithContext(ctx)
	done := make(chan struct{})
	go func() {
		defer cancel()
		defer close(done)
		HandleStream(b, heartbeat, core.NewContext(w, r))
	}()
	return done
}

func TestHandleStream_BusyReturns503(t *testing.T) {
	b := NewBroker(Options{MaxSubscribers: 1})
	blocker, err := b.Subscribe(Filter{})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer blocker.Close()

	r := httptest.NewRequest(http.MethodGet, "/stream", nil)
	w := httptest.NewRecorder()
	// The busy branch returns synchronously (before Subscribe would block on
	// anything) — no goroutine/streaming needed.
	HandleStream(b, time.Second, core.NewContext(w, r))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if !strings.Contains(w.Body.String(), ErrStreamBusy) {
		t.Fatalf("body = %q, want it to contain %q", w.Body.String(), ErrStreamBusy)
	}
}

func TestHandleStream_SetsSSEHeaders(t *testing.T) {
	b := NewBroker(Options{})
	r := httptest.NewRequest(http.MethodGet, "/stream", nil)
	w := httptest.NewRecorder()
	<-runStream(b, time.Hour, r, w, 30*time.Millisecond)

	h := w.Header()
	if got := h.Get(core.HeaderContentType); got != ContentTypeEventStream {
		t.Errorf("Content-Type = %q, want %q", got, ContentTypeEventStream)
	}
	if got := h.Get(HeaderCacheControl); got != CacheControlNoStore {
		t.Errorf("Cache-Control = %q, want %q", got, CacheControlNoStore)
	}
	if got := h.Get(HeaderPragma); got != PragmaNoCache {
		t.Errorf("Pragma = %q, want %q", got, PragmaNoCache)
	}
	if got := h.Get(HeaderAccelBuffering); got != AccelBufferingOff {
		t.Errorf("X-Accel-Buffering = %q, want %q", got, AccelBufferingOff)
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandleStream_Heartbeat(t *testing.T) {
	b := NewBroker(Options{})
	r := httptest.NewRequest(http.MethodGet, "/stream", nil)
	w := httptest.NewRecorder()
	<-runStream(b, 5*time.Millisecond, r, w, 60*time.Millisecond)

	if !strings.Contains(w.Body.String(), "keep-alive") {
		t.Fatalf("expected a keep-alive heartbeat comment, got body=%q", w.Body.String())
	}
}

func TestHandleStream_ReplayFromRingBeforeSubscribe(t *testing.T) {
	b := NewBroker(Options{ReplayBuffer: 10, SubscriberBuffer: 10})
	// Published before any subscriber connects: only reachable via the ring.
	b.Publish(Event{Type: "seed", Data: []byte(`{"n":1}`)})

	r := httptest.NewRequest(http.MethodGet, "/stream", nil)
	r.Header.Set(HeaderLastEventID, "0")
	w := httptest.NewRecorder()
	<-runStream(b, time.Hour, r, w, 60*time.Millisecond)

	body := w.Body.String()
	if !strings.Contains(body, "id: 1") || !strings.Contains(body, `"n":1`) {
		t.Fatalf("expected the ring-replayed seed event, got body=%q", body)
	}
}

func TestHandleStream_NoLastEventIDSkipsReplay(t *testing.T) {
	b := NewBroker(Options{ReplayBuffer: 10, SubscriberBuffer: 10})
	b.Publish(Event{Type: "seed", Data: []byte(`{"n":1}`)})

	// No Last-Event-ID header at all: a fresh connection must NOT replay
	// history, only what's published after it goes live.
	r := httptest.NewRequest(http.MethodGet, "/stream", nil)
	w := httptest.NewRecorder()
	done := runStream(b, time.Hour, r, w, 80*time.Millisecond)
	waitForSubscribers(t, b, 1)
	b.Publish(Event{Type: "live", Data: []byte(`{"n":2}`)})
	<-done

	body := w.Body.String()
	if strings.Contains(body, `"n":1`) {
		t.Fatalf("fresh connection (no Last-Event-ID) replayed history: body=%q", body)
	}
	if !strings.Contains(body, `"n":2`) {
		t.Fatalf("expected the live event, got body=%q", body)
	}
}

func TestHandleStream_ReplayThenLiveNoDuplicate(t *testing.T) {
	b := NewBroker(Options{ReplayBuffer: 10, SubscriberBuffer: 10})
	seedID := b.Publish(Event{Type: "seed", Data: []byte(`{"n":1}`)})

	r := httptest.NewRequest(http.MethodGet, "/stream", nil)
	r.Header.Set(HeaderLastEventID, strconv.FormatUint(seedID, 10))
	w := httptest.NewRecorder()
	done := runStream(b, time.Hour, r, w, 100*time.Millisecond)
	waitForSubscribers(t, b, 1)
	b.Publish(Event{Type: "live", Data: []byte(`{"n":2}`)})
	<-done

	body := w.Body.String()
	if strings.Contains(body, `"n":1`) {
		t.Fatalf("Last-Event-ID replay must not repeat the client's own last event: body=%q", body)
	}
	if got := strings.Count(body, `"n":2`); got != 1 {
		t.Fatalf("expected the live event exactly once (no replay/live double-delivery), got %d: body=%q", got, body)
	}
}

func TestHandleStream_FilterQueryParam(t *testing.T) {
	b := NewBroker(Options{})
	r := httptest.NewRequest(http.MethodGet, "/stream?event_types=login", nil)
	w := httptest.NewRecorder()
	done := runStream(b, time.Hour, r, w, 80*time.Millisecond)
	waitForSubscribers(t, b, 1)
	b.Publish(Event{Type: "logout", Data: []byte(`{"n":1}`)})
	b.Publish(Event{Type: "login", Data: []byte(`{"n":2}`)})
	<-done

	body := w.Body.String()
	if strings.Contains(body, `"n":1`) {
		t.Fatalf("event_types filter let a non-matching type through: body=%q", body)
	}
	if !strings.Contains(body, `"n":2`) {
		t.Fatalf("event_types filter dropped a matching type: body=%q", body)
	}
}

func TestHandleStream_TenantFilterQueryParam(t *testing.T) {
	b := NewBroker(Options{})
	r := httptest.NewRequest(http.MethodGet, "/stream?tenant_id=acme", nil)
	w := httptest.NewRecorder()
	done := runStream(b, time.Hour, r, w, 80*time.Millisecond)
	waitForSubscribers(t, b, 1)
	b.Publish(Event{Type: "x", TenantID: "other", Data: []byte(`{"n":1}`)})
	b.Publish(Event{Type: "x", TenantID: "acme", Data: []byte(`{"n":2}`)})
	<-done

	body := w.Body.String()
	if strings.Contains(body, `"n":1`) {
		t.Fatalf("tenant_id filter let another tenant's event through: body=%q", body)
	}
	if !strings.Contains(body, `"n":2`) {
		t.Fatalf("tenant_id filter dropped the matching tenant's event: body=%q", body)
	}
}

func TestFilterFromRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/stream?event_types=a,%20b,&tenant_id=acme", nil)
	f := filterFromRequest(core.NewContext(httptest.NewRecorder(), r))
	if f.TenantID != "acme" {
		t.Errorf("TenantID = %q, want acme", f.TenantID)
	}
	if len(f.Types) != 2 || f.Types[0] != "a" || f.Types[1] != "b" {
		t.Errorf("Types = %+v, want [a b]", f.Types)
	}
}

func TestLastEventID(t *testing.T) {
	cases := []struct {
		header string
		wantID uint64
		wantOK bool
	}{
		{"", 0, false},
		{"42", 42, true},
		{"not-a-number", 0, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/stream", nil)
		if c.header != "" {
			r.Header.Set(HeaderLastEventID, c.header)
		}
		id, ok := lastEventID(r)
		if id != c.wantID || ok != c.wantOK {
			t.Errorf("header=%q: got id=%d ok=%v, want id=%d ok=%v", c.header, id, ok, c.wantID, c.wantOK)
		}
	}
}
