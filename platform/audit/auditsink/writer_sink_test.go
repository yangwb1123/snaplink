package auditsink

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/snaplink/sso/platform/audit/auditspi"
)

func TestWriterSink_Record_AssignsIDAndWritesJSONLine(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := NewWriterSink(&buf)

	e := &auditspi.Event{Type: auditspi.EventLogin}
	if err := w.Record(t.Context(), e); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if e.ID == "" {
		t.Fatal("Record must assign an ID when the caller left it empty")
	}
	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("output %q must be newline-terminated", out)
	}
	var decoded auditspi.Event
	if err := json.Unmarshal([]byte(strings.TrimSuffix(out, "\n")), &decoded); err != nil {
		t.Fatalf("line did not decode as an Event: %v", err)
	}
	if decoded.ID != e.ID {
		t.Errorf("decoded.ID = %q, want %q", decoded.ID, e.ID)
	}
}

func TestWriterSink_Record_PreservesCallerSuppliedID(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := NewWriterSink(&buf)

	if err := w.Record(t.Context(), &auditspi.Event{ID: "caller-id"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	var decoded auditspi.Event
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.ID != "caller-id" {
		t.Errorf("decoded.ID = %q, want caller-id to be preserved, not overwritten", decoded.ID)
	}
}

func TestWriterSink_Record_MultipleEventsOneLineEach(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := NewWriterSink(&buf)

	for i := 0; i < 5; i++ {
		if err := w.Record(t.Context(), &auditspi.Event{Type: auditspi.EventLogin}); err != nil {
			t.Fatalf("Record #%d: %v", i, err)
		}
	}
	scanner := bufio.NewScanner(&buf)
	lines := 0
	for scanner.Scan() {
		var decoded auditspi.Event
		if err := json.Unmarshal(scanner.Bytes(), &decoded); err != nil {
			t.Fatalf("line %d did not decode: %v", lines, err)
		}
		lines++
	}
	if lines != 5 {
		t.Fatalf("got %d lines, want 5", lines)
	}
}

// TestWriterSink_Record_ConcurrentSafe proves the mutex actually serializes
// writes: N goroutines racing Record must produce exactly N complete,
// individually-decodable JSON lines — no torn/interleaved writes. Run with
// -race to also catch a missing lock.
func TestWriterSink_Record_ConcurrentSafe(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := NewWriterSink(&buf)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_ = w.Record(t.Context(), &auditspi.Event{Type: auditspi.EventLogin})
		}()
	}
	wg.Wait()

	scanner := bufio.NewScanner(&buf)
	lines := 0
	for scanner.Scan() {
		var decoded auditspi.Event
		if err := json.Unmarshal(scanner.Bytes(), &decoded); err != nil {
			t.Fatalf("line %d is not valid JSON (torn write?): %v\nline: %s", lines, err, scanner.Text())
		}
		lines++
	}
	if lines != n {
		t.Fatalf("got %d lines, want %d", lines, n)
	}
}

func TestWriterSink_GetAndQuery_AreWriteOnly(t *testing.T) {
	t.Parallel()
	w := NewWriterSink(&bytes.Buffer{})
	if _, err := w.Get(t.Context(), "any"); err != ErrSinkWriteOnly {
		t.Errorf("Get() err = %v, want ErrSinkWriteOnly", err)
	}
	if _, err := w.Query(t.Context(), auditspi.Query{}); err != ErrSinkWriteOnly {
		t.Errorf("Query() err = %v, want ErrSinkWriteOnly", err)
	}
}
