package defaultrisk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// captureLogger records Error calls so the WithHIBPLogger fail-open path can be
// asserted.
type captureLogger struct {
	mu     sync.Mutex
	errors int
}

func (l *captureLogger) Info(string, ...any)  {}
func (l *captureLogger) Debug(string, ...any) {}
func (l *captureLogger) Error(string, ...any) {
	l.mu.Lock()
	l.errors++
	l.mu.Unlock()
}

func TestHIBP_WithUserAgent(t *testing.T) {
	t.Parallel()
	const pw = "ua-test-password"
	_, _, suffix := hibpHashParts(pw)
	fake := &fakeHIBP{body: suffix + ":3\r\n"}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c := newHIBPTestChecker(t, srv, WithHIBPUserAgent("custom-agent/9"))
	if _, err := c.Check(context.Background(), pw); err != nil {
		t.Fatalf("Check: %v", err)
	}
	fake.mu.Lock()
	ua := fake.gotUA[0]
	fake.mu.Unlock()
	if ua != "custom-agent/9" {
		t.Errorf("User-Agent = %q, want custom-agent/9", ua)
	}
	// Empty UA is ignored (default kept).
	if c2 := newHIBPTestChecker(t, srv, WithHIBPUserAgent("")); c2.userAgent != defaultHIBPUserAgent {
		t.Errorf("empty UA override changed userAgent to %q", c2.userAgent)
	}
}

func TestHIBP_WithLoggerOnFailOpen(t *testing.T) {
	t.Parallel()
	fake := &fakeHIBP{status: http.StatusInternalServerError}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	lg := &captureLogger{}
	c := newHIBPTestChecker(t, srv, WithHIBPLogger(lg))
	// Non-200 → fail-open: returns (nil, nil) but logs the outage.
	sig, err := c.Check(context.Background(), "anything")
	if err != nil || sig != nil {
		t.Fatalf("fail-open expected (nil, nil), got (%v, %v)", sig, err)
	}
	lg.mu.Lock()
	n := lg.errors
	lg.mu.Unlock()
	if n == 0 {
		t.Error("WithHIBPLogger should have logged the fail-open outage")
	}
}

func TestHIBP_WithHTTPClient(t *testing.T) {
	t.Parallel()
	const pw = "client-opt-test"
	_, _, suffix := hibpHashParts(pw)
	fake := &fakeHIBP{body: suffix + ":7\r\n"}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	custom := &http.Client{}
	c, err := NewHIBPPasswordHealthChecker(
		WithHIBPBaseURL(srv.URL+"/range/"),
		WithHIBPHTTPClient(custom),
	)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	if c.client != custom {
		t.Error("WithHIBPHTTPClient did not install the supplied client")
	}
	sig, err := c.Check(context.Background(), pw)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if sig == nil || !sig.Compromised {
		t.Errorf("expected compromised signal via custom client, got %+v", sig)
	}

	// nil client is ignored (default kept).
	c2, _ := NewHIBPPasswordHealthChecker(WithHIBPHTTPClient(nil))
	if c2.client == nil {
		t.Error("nil client override wiped the default client")
	}
}
