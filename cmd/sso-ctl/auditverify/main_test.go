package auditverify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// TestReadFromFile_PlainArray — the simplest input shape:
// raw [event, event, ...] in chain order.
func TestReadFromFile_PlainArray(t *testing.T) {
	t.Parallel()
	events := chainedEvents(t, 3)
	raw, _ := json.Marshal(events)
	path := filepath.Join(t.TempDir(), "events.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, _, err := readFromFile(path, 0)
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
	t.Parallel()
	events := chainedEvents(t, 2)
	envelope := map[string]any{"events": events, "count": len(events)}
	raw, _ := json.Marshal(envelope)
	path := filepath.Join(t.TempDir(), "events.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, _, err := readFromFile(path, 0)
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
	t.Parallel()
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
	got, _, err := readFromFile(path, 0)
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
	t.Parallel()
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
	got, _, err := readFromURL(srv.URL, "t", 0, 3, time.Second)
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
	t.Parallel()
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
	got, _, err := readFromURL(srv.URL, "t", 4, 3, time.Second)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 4 {
		t.Errorf("got %d events; want 4 (limit cap)", len(got))
	}
}

// TestReadFromURL_NoRedirect pins the audit-verify raw-client construction
// (main.go readFromURL): the --from-url client must stop at a 307 so the
// bearer is never forwarded to the redirect target. Exercises the client
// built by readFromURL itself — a regression that drops the CheckRedirect
// pin fails here. Not parallel: keeps deterministic ordering with the
// existing stderr-adjacent tests.
func TestReadFromURL_NoRedirect(t *testing.T) {
	events := chainedEvents(t, 7)
	newestFirst := make([]*audit.Event, len(events))
	for i, e := range events {
		newestFirst[len(events)-1-i] = e
	}
	var mu sync.Mutex
	targetHits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		targetHits++
		mu.Unlock()
		off, _ := atoi(r.URL.Query().Get("offset"))
		lim, _ := atoi(r.URL.Query().Get("limit"))
		end := min(off+lim, len(newestFirst))
		_ = json.NewEncoder(w).Encode(map[string]any{"events": newestFirst[off:end]})
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = w.Write([]byte(strings.Repeat("<html>gateway moved</html>", 30)))
	}))
	defer redirector.Close()

	if _, _, err := readFromURL(redirector.URL, "tok-audit-verify", 0, 3, time.Second); err == nil {
		t.Fatal("readFromURL: expected error on 307, got nil")
	}
	mu.Lock()
	hits := targetHits
	mu.Unlock()
	if hits != 0 {
		t.Errorf("redirect target received %d requests, want 0 (bearer would have been forwarded)", hits)
	}
}

// TestReadFromURL_RedirectMessage pins the audit-verify 3xx error string:
// redirect wording, the --from-url hint, a userinfo-redacted Location, and
// the truncated-body marker. readFromURL returns the error, so no stderr
// capture is needed.
func TestReadFromURL_RedirectMessage(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"events": []any{}})
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Location with userinfo: the diagnostic must redact it.
		w.Header().Set("Location", "http://user:sekret@"+strings.TrimPrefix(target.URL, "http://"))
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = w.Write([]byte(strings.Repeat("<html>gateway moved</html>", 30)))
	}))
	defer redirector.Close()

	_, _, err := readFromURL(redirector.URL, "tok-audit-verify", 0, 3, time.Second)
	if err == nil {
		t.Fatal("readFromURL: expected error on 307, got nil")
	}
	for _, want := range []string{"fetch page (offset=0) failed", "redirect", auditRedirectHint, "..."} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "sekret") || strings.Contains(err.Error(), "tok-audit-verify") {
		t.Errorf("error leaks userinfo or bearer: %v", err)
	}
}

// TestVerifyDetectsTamper proves the integration: a tampered event
// fails the chain check exactly the way audit.VerifyChain
// documents.
func TestVerifyDetectsTamper(t *testing.T) {
	t.Parallel()
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
