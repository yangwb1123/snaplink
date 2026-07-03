//go:build chaos

package chaostest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// recordingLogger is a tiny real spi.Logger (not a mock framework) that
// records Error() calls so a test can assert the panic-recovery middleware
// actually observed the panic, mirroring the audit.MemorySink /
// erroring*Store convention: a real, minimal implementation of the
// production interface rather than a generated stub.
type recordingLogger struct {
	spi.NopLogger
	mu       sync.Mutex
	errCalls int
}

func (r *recordingLogger) Error(msg string, keysAndValues ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errCalls++
}

func (r *recordingLogger) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.errCalls
}

var _ spi.Logger = (*recordingLogger)(nil)

// TestChaos_PanicRecovery_ReturnsFiveHundred proves middleware.Recover — the
// outermost wrapper installed over every route (interfaces/sso/server_routes.go)
// — turns a panicking handler into a clean 500 core.ErrInternal instead of
// crashing the listener, and that the panic is observed via the logger (the
// only fault-visibility seam Recover currently wires; it does not itself emit
// an audit event, so this test does not assert one — see chaos-tests notes).
func TestChaos_PanicRecovery_ReturnsFiveHundred(t *testing.T) {
	logger := &recordingLogger{}
	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom: simulated handler panic")
	})
	srv := httptest.NewServer(middleware.Recover(logger)(panicking))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/anything")
	if err != nil {
		t.Fatalf("request against a panicking handler should still get an HTTP response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d want %d, body=%s", resp.StatusCode, http.StatusInternalServerError, raw)
	}
	var body map[string]string
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode body %q: %v", raw, err)
	}
	if body["error"] != core.ErrInternal {
		t.Errorf("error=%q want %q", body["error"], core.ErrInternal)
	}
	if logger.calls() != 1 {
		t.Errorf("logger.Error calls=%d want 1 (the recovered panic)", logger.calls())
	}
}

// TestChaos_PanicRecovery_ConcurrentPanicsAllRecovered fires many concurrent
// panicking requests through ONE shared Recover-wrapped handler (run with
// `-race -count=2` via `make chaos-test`): the deferred recover() must never
// leak a panic across goroutines, and the shared logger must observe exactly
// one Error() per request with no data race on its counter.
func TestChaos_PanicRecovery_ConcurrentPanicsAllRecovered(t *testing.T) {
	logger := &recordingLogger{}
	var served int64
	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		atomic.AddInt64(&served, 1)
		panic("boom: concurrent simulated panic")
	})
	srv := httptest.NewServer(middleware.Recover(logger)(panicking))
	defer srv.Close()

	const n = 32
	var wg sync.WaitGroup
	statuses := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := http.Get(srv.URL + "/anything")
			if err != nil {
				t.Errorf("goroutine %d: request failed: %v", i, err)
				return
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.ReadAll(resp.Body)
			statuses[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	for i, status := range statuses {
		if status != http.StatusInternalServerError {
			t.Errorf("goroutine %d: status=%d want %d", i, status, http.StatusInternalServerError)
		}
	}
	if got := atomic.LoadInt64(&served); got != n {
		t.Errorf("handler invocations=%d want %d", got, n)
	}
	if logger.calls() != n {
		t.Errorf("logger.Error calls=%d want %d (one per recovered panic)", logger.calls(), n)
	}
}
