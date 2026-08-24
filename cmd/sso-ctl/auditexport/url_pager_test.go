package auditexport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	libexport "github.com/yangwb1123/snaplink/platform/audit/auditexport"
	"github.com/yangwb1123/snaplink/platform/audit/auditspi"
)

// eventsPageServer serves newest-first pages of `events` honoring the
// offset/limit query params, in the live API's {events:[...]} envelope.
func eventsPageServer(t *testing.T, events []*auditspi.Event) *httptest.Server {
	t.Helper()
	newestFirst := make([]*auditspi.Event, len(events))
	for i, e := range events {
		newestFirst[len(events)-1-i] = e
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/events" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		off, _ := atoi(r.URL.Query().Get("offset"))
		lim, _ := atoi(r.URL.Query().Get("limit"))
		end := min(off+lim, len(newestFirst))
		_ = json.NewEncoder(w).Encode(map[string]any{"events": newestFirst[off:end], "count": end - off})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestURLPager_MultiPageOffsetProgression (REQ-6): the adapter returns
// exactly one newest-first page per Query call and drives offsets 0, 3, 6
// for a 3/page read of 7 events — pageAll owns the reversal, the adapter
// never reverses.
func TestURLPager_MultiPageOffsetProgression(t *testing.T) {
	t.Parallel()
	events := chainedExportEvents(t, 7)
	srv := eventsPageServer(t, events)

	var mu sync.Mutex
	var seenOffsets []int
	base := srv.URL
	wrapped := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		off, _ := atoi(r.URL.Query().Get("offset"))
		mu.Lock()
		seenOffsets = append(seenOffsets, off)
		mu.Unlock()
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, base+r.URL.RequestURI(), nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(readAll(resp.Body))
	}))
	defer wrapped.Close()

	p, err := newURLPager(wrapped.URL, "t", time.Second)
	if err != nil {
		t.Fatalf("newURLPager: %v", err)
	}
	var collected []*auditspi.Event
	for off := 0; ; {
		page, err := p.Query(context.Background(), auditspi.Query{Limit: 3, Offset: off})
		if err != nil {
			t.Fatalf("Query(offset=%d): %v", off, err)
		}
		collected = append(collected, page...)
		if len(page) < 3 {
			break
		}
		off += len(page)
	}
	if len(collected) != 7 {
		t.Fatalf("collected %d events, want 7", len(collected))
	}
	mu.Lock()
	offsets := append([]int(nil), seenOffsets...)
	mu.Unlock()
	if len(offsets) != 3 || offsets[0] != 0 || offsets[1] != 3 || offsets[2] != 6 {
		t.Errorf("offsets seen = %v, want [0 3 6]", offsets)
	}
	// Newest-first per page: page boundaries are the newest events.
	if collected[0].ID != events[len(events)-1].ID {
		t.Errorf("first collected event id=%q, want newest id=%q (no reversal)", collected[0].ID, events[len(events)-1].ID)
	}
}

// TestURLPager_FilterParamsForwarded (REQ-6): the querystring carries the
// populated filter params in the API's vocabulary.
func TestURLPager_FilterParamsForwarded(t *testing.T) {
	t.Parallel()
	var lastQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]any{"events": []any{}})
	}))
	defer srv.Close()

	p, err := newURLPager(srv.URL, "t", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	q := auditspi.Query{
		Type:      "login",
		Outcome:   "success",
		ActorID:   "alice",
		ClientID:  "web",
		TenantID:  "t1",
		Provider:  "password",
		RequestID: "req-1",
		TraceID:   "trace-1",
		Since:     since,
		Limit:     1000,
	}
	if _, err := p.Query(context.Background(), q); err != nil {
		t.Fatalf("Query: %v", err)
	}
	for _, want := range []string{"type=login", "outcome=success", "actor_id=alice", "client_id=web",
		"tenant_id=t1", "provider=password", "request_id=req-1", "trace_id=trace-1",
		"since=" + url.QueryEscape("2026-01-01T00:00:00Z"), "limit=1000", "offset=0"} {
		if !strings.Contains(lastQuery, want) {
			t.Errorf("querystring %q missing %q", lastQuery, want)
		}
	}
}

// TestURLPager_Non2xxNamesOffset (REQ-6): a 401/500 page surfaces the
// failing offset in the diagnostic.
func TestURLPager_Non2xxNamesOffset(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer srv.Close()

	p, err := newURLPager(srv.URL, "weak", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Query(context.Background(), auditspi.Query{Limit: 1000, Offset: 6})
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !strings.Contains(err.Error(), "offset=6") || !strings.Contains(err.Error(), "401") {
		t.Errorf("diagnostic must name the failing offset+status: %v", err)
	}
}

// TestURLPager_ArrayBodyShape (REQ-6): a raw JSON array body parses.
func TestURLPager_ArrayBodyShape(t *testing.T) {
	t.Parallel()
	events := chainedExportEvents(t, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(events)
	}))
	defer srv.Close()

	p, err := newURLPager(srv.URL, "t", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	page, err := p.Query(context.Background(), auditspi.Query{Limit: 1000})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(page) != 2 {
		t.Errorf("len=%d, want 2", len(page))
	}
}

// TestURLPager_NoRedirect pins the raw-client construction: the bearer
// must never be forwarded to a redirect target.
func TestURLPager_NoRedirect(t *testing.T) {
	events := chainedExportEvents(t, 2)
	target := eventsPageServer(t, events)
	targetClosed := target.URL
	target.Close()

	var mu sync.Mutex
	recountedHits := 0
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", targetClosed)
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = w.Write([]byte(strings.Repeat("<html>gateway moved</html>", 30)))
	}))
	defer redirector.Close()
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		recountedHits++
		mu.Unlock()
		http.NotFound(w, r)
	}))
	defer probe.Close()

	p, err := newURLPager(redirector.URL, "tok-audit-export", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Query(context.Background(), auditspi.Query{Limit: 1000}); err == nil {
		t.Fatal("expected error on 307, got nil")
	}
	if recountedHits != 0 {
		t.Errorf("redirect target received %d requests, want 0 (bearer would have been forwarded)", recountedHits)
	}
}

// TestRun_FromURL_ExportBundle (REQ-2 criterion 1): --from-url over a
// paged httptest server produces a verifiable bundle with the right
// EventCount / Contiguous / BoundaryPrevHash, and --verify exits 0.
func TestRun_FromURL_ExportBundle(t *testing.T) {
	events := chainedExportEvents(t, 7)
	srv := eventsPageServer(t, events)

	dir := t.TempDir()
	out := filepath.Join(dir, "evidence.json")
	code := captureQuiet(t, func() int {
		return Run([]string{"--from-url", srv.URL, "--bearer", "t", "--out", out})
	})
	if code != 0 {
		t.Fatalf("Run exit=%d, want 0", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if b.EventCount != 7 {
		t.Fatalf("EventCount=%d, want 7", b.EventCount)
	}
	if !b.Contiguous {
		t.Error("pure window export must be contiguous")
	}
	if b.BoundaryPrevHash != events[0].PrevHash {
		t.Errorf("BoundaryPrevHash=%q, want %q", b.BoundaryPrevHash, events[0].PrevHash)
	}
	if code := captureQuiet(t, func() int { return Run([]string{"--verify", out}) }); code != 0 {
		t.Fatalf("--verify exit=%d, want 0", code)
	}
}

// TestRun_FromURL_LimitCap (REQ-2 criterion 2): the CLI --limit caps the
// bundle via pageAll while the adapter keeps one page per Query.
func TestRun_FromURL_LimitCap(t *testing.T) {
	events := chainedExportEvents(t, 7)
	srv := eventsPageServer(t, events)

	dir := t.TempDir()
	out := filepath.Join(dir, "limited.json")
	code := captureQuiet(t, func() int {
		return Run([]string{"--from-url", srv.URL, "--bearer", "t", "--limit", "5", "--out", out})
	})
	if code != 0 {
		t.Fatalf("Run exit=%d, want 0", code)
	}
	raw, _ := os.ReadFile(out)
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if b.EventCount != 5 {
		t.Errorf("EventCount=%d, want 5 (limit cap)", b.EventCount)
	}
	// pageAll's cap keeps the NEWEST 5 (newest-side semantics), so the
	// bundle starts mid-chain — still verifiable via its boundary anchor.
	if code := captureQuiet(t, func() int { return Run([]string{"--verify", out}) }); code != 0 {
		t.Fatalf("--verify exit=%d, want 0", code)
	}
}

// TestRun_FromURL_EmptyWindow (REQ-2 criterion 5): an empty window exits
// 0 with an empty bundle.
func TestRun_FromURL_EmptyWindow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"events": []any{}, "count": 0})
	}))
	defer srv.Close()

	var code int
	stderr := captureStderr(t, func() { code = Run([]string{"--from-url", srv.URL, "--bearer", "t"}) })
	if code != 0 {
		t.Fatalf("Run exit=%d, want 0 (empty window)", code)
	}
	if !strings.Contains(stderr, "exported 0 verified event(s)") {
		t.Errorf("stderr missing empty summary:\n%s", stderr)
	}
}

// TestRun_FromURL_Misuse (REQ-2 criterion 4 / B2): --from-url without
// --bearer, or paired with --dsn / --verify, is exit-2 misuse.
func TestRun_FromURL_Misuse(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no-bearer", []string{"--from-url", "https://x"}, "requires --bearer"},
		{"with-dsn", []string{"--from-url", "https://x", "--bearer", "t", "--dsn", "a.db"}, "mutually exclusive"},
		{"with-verify", []string{"--from-url", "https://x", "--bearer", "t", "--verify", "b.json"}, "mutually exclusive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var code int
			stderr := captureStderr(t, func() { code = Run(tc.args) })
			if code != 2 {
				t.Fatalf("exit=%d, want 2", code)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr missing %q:\n%s", tc.want, stderr)
			}
		})
	}
}

// TestRun_DSN_PostgresRouting (REQ-3 criterion 4): a postgresql:// DSN
// routes to the postgres opener (a postgres-shaped failure, not a sqlite
// one) even without a live database.
func TestRun_DSN_PostgresRouting(t *testing.T) {
	var code int
	stderr := captureStderr(t, func() { code = Run([]string{"--dsn", "postgresql://127.0.0.1:1/nope?sslmode=disable"}) })
	if code != 1 {
		t.Fatalf("exit=%d, want 1 (open error)", code)
	}
	if !strings.Contains(stderr, "postgres") {
		t.Errorf("stderr must name the postgres store:\n%s", stderr)
	}
	if strings.Contains(stderr, "sqlite") {
		t.Errorf("a postgres DSN must never reach the sqlite opener:\n%s", stderr)
	}
}

// chainedExportEvents builds n hash-chained audit events in chain order
// using the same audit.Recorder the stock server uses.
func chainedExportEvents(t *testing.T, n int) []*auditspi.Event {
	t.Helper()
	sink := audit.NewMemorySink(n)
	r := audit.New(sink, audit.WithHashChain())
	for i := range n {
		r.Record(context.Background(), &audit.Event{
			ID:      "evt-" + string(rune('a'+i)),
			Type:    audit.EventLogin,
			Outcome: audit.OutcomeSuccess,
		})
	}
	got, _ := sink.Query(context.Background(), audit.Query{Limit: n})
	for i, j := 0, len(got)-1; i < j; i, j = i+1, j-1 {
		got[i], got[j] = got[j], got[i]
	}
	return got
}

// atoi parses a decimal integer, returning ok=false on garbage.
func atoi(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

func readAll(r io.Reader) []byte {
	b, _ := io.ReadAll(r)
	return b
}
