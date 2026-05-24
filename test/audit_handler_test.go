package ssotest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
)

// auditHarness stands up a Server with the audit API enabled and seeds
// the sink with three events at known timestamps + types so tests can
// exercise the filter and pagination logic against real data.
type auditHarness struct {
	srv   *httptest.Server
	sink  *audit.MemorySink
	rec   *audit.Recorder
	stamp time.Time // base time for seeded events
}

func newAuditHarness(t *testing.T, withAPI bool) *auditHarness {
	t.Helper()
	sink := audit.NewMemorySink(100)
	rec := audit.New(sink)

	opts := []sso.Option{sso.WithAuditRecorder(rec)}
	if withAPI {
		opts = append(opts, sso.WithAuditAPI())
	}

	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	base := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	for i, ev := range []*audit.Event{
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "alice", ClientID: "web", Provider: "password", Timestamp: base},
		{Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure, ActorID: "bob", ClientID: "web", Provider: "password", Timestamp: base.Add(time.Minute)},
		{Type: audit.EventLogout, Outcome: audit.OutcomeSuccess, ActorID: "alice", ClientID: "web", Timestamp: base.Add(2 * time.Minute)},
	} {
		_ = i
		rec.Record(context.Background(), ev)
	}

	return &auditHarness{srv: httpSrv, sink: sink, rec: rec, stamp: base}
}

func auditGET(t *testing.T, h *auditHarness, path string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(h.srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	return resp.StatusCode, out
}

func TestAuditAPI_ListReturnsAllEvents(t *testing.T) {
	h := newAuditHarness(t, true)
	code, body := auditGET(t, h, "/api/v1/audit/events")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	count, _ := body["count"].(float64)
	if int(count) != 3 {
		t.Errorf("count = %v, want 3", count)
	}
}

func TestAuditAPI_FilterByType(t *testing.T) {
	h := newAuditHarness(t, true)
	code, body := auditGET(t, h, "/api/v1/audit/events?type=login")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if int(body["count"].(float64)) != 1 {
		t.Errorf("count = %v, want 1 (only login)", body["count"])
	}
}

func TestAuditAPI_FilterByActor(t *testing.T) {
	h := newAuditHarness(t, true)
	_, body := auditGET(t, h, "/api/v1/audit/events?actor_id=alice")
	if int(body["count"].(float64)) != 2 {
		t.Errorf("alice events = %v, want 2", body["count"])
	}
}

func TestAuditAPI_FilterByOutcome(t *testing.T) {
	h := newAuditHarness(t, true)
	_, body := auditGET(t, h, "/api/v1/audit/events?outcome=failure")
	if int(body["count"].(float64)) != 1 {
		t.Errorf("failure events = %v, want 1", body["count"])
	}
}

func TestAuditAPI_SinceUntilRFC3339(t *testing.T) {
	h := newAuditHarness(t, true)
	// Window covers only the middle event (minute 1).
	since := h.stamp.Add(30 * time.Second).Format(time.RFC3339)
	until := h.stamp.Add(90 * time.Second).Format(time.RFC3339)
	_, body := auditGET(t, h, "/api/v1/audit/events?since="+since+"&until="+until)
	if int(body["count"].(float64)) != 1 {
		t.Errorf("windowed count = %v, want 1", body["count"])
	}
}

func TestAuditAPI_SinceUntilUnixSeconds(t *testing.T) {
	h := newAuditHarness(t, true)
	// Same window, expressed in unix seconds — parseAuditTime accepts both.
	since := h.stamp.Add(30 * time.Second).Unix()
	_, body := auditGET(t, h, "/api/v1/audit/events?since="+strings.TrimSpace(itoa(since)))
	if int(body["count"].(float64)) != 2 {
		t.Errorf("since-unix count = %v, want 2", body["count"])
	}
}

func TestAuditAPI_LimitClampsAndOffsetAdvances(t *testing.T) {
	h := newAuditHarness(t, true)
	_, body := auditGET(t, h, "/api/v1/audit/events?limit=2")
	if int(body["count"].(float64)) != 2 {
		t.Errorf("limit=2 count = %v", body["count"])
	}
	_, body = auditGET(t, h, "/api/v1/audit/events?limit=2&offset=2")
	if int(body["count"].(float64)) != 1 {
		t.Errorf("offset=2 count = %v, want 1", body["count"])
	}
}

func TestAuditAPI_BadSince(t *testing.T) {
	h := newAuditHarness(t, true)
	code, body := auditGET(t, h, "/api/v1/audit/events?since=not-a-time")
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if e, _ := body["error"].(string); e != "invalid_request" {
		t.Errorf("error = %v", e)
	}
}

func TestAuditAPI_BadUntil(t *testing.T) {
	h := newAuditHarness(t, true)
	code, _ := auditGET(t, h, "/api/v1/audit/events?until=not-a-time")
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", code)
	}
}

func TestAuditAPI_BadLimit(t *testing.T) {
	h := newAuditHarness(t, true)
	code, _ := auditGET(t, h, "/api/v1/audit/events?limit=NaN")
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", code)
	}
}

func TestAuditAPI_BadOffset(t *testing.T) {
	h := newAuditHarness(t, true)
	code, _ := auditGET(t, h, "/api/v1/audit/events?offset=NaN")
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", code)
	}
}

func TestAuditAPI_GetByID(t *testing.T) {
	h := newAuditHarness(t, true)
	// Pull one ID from the sink.
	events, _ := h.sink.Query(context.Background(), audit.Query{})
	if len(events) == 0 {
		t.Fatal("no events in sink")
	}
	id := events[0].ID
	if id == "" {
		t.Fatal("sink did not assign IDs")
	}
	code, body := auditGET(t, h, "/api/v1/audit/events/"+id)
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	if body["id"] != id {
		t.Errorf("returned id = %v, want %v", body["id"], id)
	}
}

func TestAuditAPI_GetByID_NotFound(t *testing.T) {
	h := newAuditHarness(t, true)
	code, body := auditGET(t, h, "/api/v1/audit/events/no-such-id")
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", code)
	}
	if e, _ := body["error"].(string); e != "audit_event_not_found" {
		t.Errorf("error = %v", e)
	}
}

func TestAuditAPI_DisabledWhenNotMounted(t *testing.T) {
	// withAPI=false → /api/v1/audit/events isn't registered. The router
	// falls through to http.NotFound (404).
	h := newAuditHarness(t, false)
	code, _ := auditGET(t, h, "/api/v1/audit/events")
	if code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (route not mounted)", code)
	}
}

// itoa is a tiny strconv.Itoa shim used by tests that build query strings
// from integers without importing strconv just for that.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = digits[n%10]
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
