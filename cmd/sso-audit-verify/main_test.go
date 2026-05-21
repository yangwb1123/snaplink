package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/audit"
)

// TestReadFromFile_PlainArray — the simplest input shape:
// raw [event, event, ...] in chain order.
func TestReadFromFile_PlainArray(t *testing.T) {
	events := chainedEvents(t, 3)
	raw, _ := json.Marshal(events)
	path := filepath.Join(t.TempDir(), "events.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readFromFile(path, 0)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 3 || got[0].Hash != events[0].Hash {
		t.Errorf("got %d events; first hash %q; want 3 events; first hash %q",
			len(got), got[0].Hash, events[0].Hash)
	}
	if err := audit.VerifyChain(got); err != nil {
		t.Errorf("chain verify failed: %v", err)
	}
}

// TestReadFromFile_EventsEnvelope — operators capturing the API
// response shape ({events: [...], count: N}) and feeding it back
// should "just work" without unwrapping.
func TestReadFromFile_EventsEnvelope(t *testing.T) {
	events := chainedEvents(t, 2)
	envelope := map[string]any{"events": events, "count": len(events)}
	raw, _ := json.Marshal(envelope)
	path := filepath.Join(t.TempDir(), "events.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readFromFile(path, 0)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d events; want 2", len(got))
	}
	if err := audit.VerifyChain(got); err != nil {
		t.Errorf("chain verify failed: %v", err)
	}
}

// TestReadFromFile_NewestFirstAutoReversed — when the input is
// newest-first (API order) but written to a file, the tool should
// auto-reverse so audit.VerifyChain accepts it.
func TestReadFromFile_NewestFirstAutoReversed(t *testing.T) {
	events := chainedEvents(t, 3)
	// Flip to API order (newest first).
	reversed := make([]*audit.Event, len(events))
	for i, e := range events {
		reversed[len(events)-1-i] = e
	}
	raw, _ := json.Marshal(reversed)
	path := filepath.Join(t.TempDir(), "events.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readFromFile(path, 0)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Chain should now be oldest-first again.
	if err := audit.VerifyChain(got); err != nil {
		t.Errorf("auto-reverse failed: %v", err)
	}
}

// TestReadFromURL_PagesAndReverses fires up an in-process server
// returning the API's {events: [...]} shape over multiple pages,
// then confirms the CLI reassembles the chain in oldest-first
// order.
func TestReadFromURL_PagesAndReverses(t *testing.T) {
	events := chainedEvents(t, 7) // 7 events, 3 pages of 3 + partial of 1
	// API returns newest-first by offset+limit. Build reversed
	// view once.
	newestFirst := make([]*audit.Event, len(events))
	for i, e := range events {
		newestFirst[len(events)-1-i] = e
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/events" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer t" {
			http.Error(w, "no auth", http.StatusUnauthorized)
			return
		}
		off, _ := atoi(r.URL.Query().Get("offset"))
		lim, _ := atoi(r.URL.Query().Get("limit"))
		end := min(off+lim, len(newestFirst))
		page := newestFirst[off:end]
		_ = json.NewEncoder(w).Encode(map[string]any{"events": page, "count": len(page)})
	}))
	defer srv.Close()
	got, err := readFromURL(srv.URL, "t", 0, 3, time.Second)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != len(events) {
		t.Fatalf("got %d events; want %d", len(got), len(events))
	}
	if err := audit.VerifyChain(got); err != nil {
		t.Errorf("chain verify failed: %v", err)
	}
}

// TestReadFromURL_LimitStopsPagination — the CLI's --limit flag
// caps how many events get pulled, even when the API has more.
func TestReadFromURL_LimitStopsPagination(t *testing.T) {
	events := chainedEvents(t, 10)
	newestFirst := make([]*audit.Event, len(events))
	for i, e := range events {
		newestFirst[len(events)-1-i] = e
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		off, _ := atoi(r.URL.Query().Get("offset"))
		lim, _ := atoi(r.URL.Query().Get("limit"))
		end := min(off+lim, len(newestFirst))
		_ = json.NewEncoder(w).Encode(map[string]any{"events": newestFirst[off:end]})
	}))
	defer srv.Close()
	got, err := readFromURL(srv.URL, "t", 4, 3, time.Second)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 4 {
		t.Errorf("got %d events; want 4 (limit cap)", len(got))
	}
}

// TestVerifyDetectsTamper proves the integration: a tampered event
// fails the chain check exactly the way audit.VerifyChain
// documents.
func TestVerifyDetectsTamper(t *testing.T) {
	events := chainedEvents(t, 3)
	// Corrupt the middle event's reason string.
	events[1].Reason = "tampered"
	if err := audit.VerifyChain(events); err == nil {
		t.Fatal("tampered chain verified clean; expected error")
	} else if !strings.Contains(err.Error(), "hash mismatch") {
		t.Errorf("err = %v; want hash mismatch", err)
	}
}

// chainedEvents builds n hash-chained events using the same
// audit.Recorder operators run with audit.WithHashChain(). Returns
// in CHAIN ORDER (oldest first).
func chainedEvents(t *testing.T, n int) []*audit.Event {
	t.Helper()
	sink := audit.NewMemorySink(0)
	r := audit.New(sink, audit.WithHashChain())
	for i := range n {
		r.Record(context.Background(), &audit.Event{
			ID:      "evt-" + string(rune('a'+i)),
			Type:    audit.EventLogin,
			Outcome: audit.OutcomeSuccess,
		})
	}
	// MemorySink.Query returns newest-first; reverse for chain order.
	got, _ := sink.Query(context.Background(), audit.Query{Limit: n})
	for i, j := 0, len(got)-1; i < j; i, j = i+1, j-1 {
		got[i], got[j] = got[j], got[i]
	}
	return got
}

// atoi avoids the strconv import in test code that already has
// enough imports.
func atoi(s string) (int, bool) {
	n := 0
	if s == "" {
		return 0, true
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
