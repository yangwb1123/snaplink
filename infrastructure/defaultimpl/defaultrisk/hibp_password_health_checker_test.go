package defaultrisk

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// hibpHashParts returns the upper-hex SHA-1 of password split into the
// 5-char range prefix and the remaining suffix — the same split the
// checker performs. Tests use it to (a) build fake range responses and
// (b) assert k-anonymity (only the prefix should ever be requested).
func hibpHashParts(password string) (full, prefix, suffix string) {
	sum := sha1.Sum([]byte(password))
	full = strings.ToUpper(hex.EncodeToString(sum[:]))
	return full, full[:5], full[5:]
}

// fakeHIBP is an httptest range API that records every requested path so a
// test can prove the suffix/full-hash never left the process, and serves a
// caller-supplied body + status.
type fakeHIBP struct {
	mu        sync.Mutex
	gotPaths  []string
	gotPadHdr []string
	gotUA     []string
	body      string
	status    int
	delay     time.Duration
}

func (f *fakeHIBP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.gotPaths = append(f.gotPaths, r.URL.Path)
	f.gotPadHdr = append(f.gotPadHdr, r.Header.Get("Add-Padding"))
	f.gotUA = append(f.gotUA, r.Header.Get("User-Agent"))
	delay, status, body := f.delay, f.status, f.body
	f.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (f *fakeHIBP) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.gotPaths))
	copy(out, f.gotPaths)
	return out
}

// newHIBPTestChecker wires a checker at the fake server's URL with a short
// timeout. The base URL keeps the /range/ suffix + trailing slash the real
// API uses, so the asserted request path is /range/<prefix>.
func newHIBPTestChecker(t *testing.T, srv *httptest.Server, opts ...HIBPOption) *HIBPPasswordHealthChecker {
	t.Helper()
	base := append([]HIBPOption{
		WithHIBPBaseURL(srv.URL + "/range/"),
		WithHIBPTimeout(2 * time.Second),
	}, opts...)
	c, err := NewHIBPPasswordHealthChecker(base...)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	return c
}

func TestHIBP_CompromisedAndKAnonymity(t *testing.T) {
	t.Parallel()
	const pw = "P@ssw0rd-compromised-test"
	full, prefix, suffix := hibpHashParts(pw)

	fake := &fakeHIBP{
		// The matching suffix with a real count, plus an unrelated entry so
		// the scanner has to actually match rather than take the first line.
		body: "0000000000000000000000000000000000A:5\r\n" +
			suffix + ":42\r\n",
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c := newHIBPTestChecker(t, srv)
	sig, err := c.Check(context.Background(), pw)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if sig == nil || !sig.Compromised {
		t.Fatalf("expected Compromised signal, got %+v", sig)
	}
	if sig.Weak {
		t.Errorf("Weak = true, want false (HIBP is a breach, not a dictionary, signal)")
	}
	if !strings.Contains(sig.Reason, "42") {
		t.Errorf("Reason %q missing breach count 42", sig.Reason)
	}

	// k-anonymity: the server must have seen ONLY /range/<prefix> — never
	// the suffix, never the full hash.
	paths := fake.paths()
	if len(paths) != 1 {
		t.Fatalf("expected exactly 1 request, got %d (%v)", len(paths), paths)
	}
	if want := "/range/" + prefix; paths[0] != want {
		t.Fatalf("requested path %q, want %q (only the 5-char prefix may leave)", paths[0], want)
	}
	if strings.Contains(paths[0], suffix) {
		t.Fatalf("suffix leaked into request path %q", paths[0])
	}
	if strings.Contains(paths[0], full) {
		t.Fatalf("full hash leaked into request path %q", paths[0])
	}
	if len(prefix) != 5 {
		t.Fatalf("prefix length %d, want 5", len(prefix))
	}

	// Add-Padding + User-Agent must be set on the request.
	fake.mu.Lock()
	pad, ua := fake.gotPadHdr[0], fake.gotUA[0]
	fake.mu.Unlock()
	if pad != "true" {
		t.Errorf("Add-Padding header = %q, want \"true\"", pad)
	}
	if ua == "" {
		t.Errorf("User-Agent header empty, want a descriptive UA")
	}
}

func TestHIBP_CleanPasswordNotCompromised(t *testing.T) {
	t.Parallel()
	const pw = "correct-horse-battery-staple-9x!Q-clean"
	_, _, suffix := hibpHashParts(pw)

	// Range answer that does NOT contain our suffix (other prefixes' tails).
	fake := &fakeHIBP{body: "111111111111111111111111111111111AA:9\r\n" +
		"222222222222222222222222222222222BB:3\r\n"}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c := newHIBPTestChecker(t, srv)
	sig, err := c.Check(context.Background(), pw)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if sig != nil {
		t.Fatalf("expected nil signal for clean password, got %+v", sig)
	}
	// Sanity: our suffix really was absent from what we returned.
	if strings.Contains(fake.body, suffix) {
		t.Fatalf("test fixture bug: suffix present in clean body")
	}
}

func TestHIBP_MinCountBelowThresholdNotFlagged(t *testing.T) {
	t.Parallel()
	const pw = "rare-breach-low-count-pw"
	_, _, suffix := hibpHashParts(pw)

	// Present, but count 2 — below a MinCount of 5.
	fake := &fakeHIBP{body: suffix + ":2\r\n"}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c := newHIBPTestChecker(t, srv, WithHIBPMinCount(5))
	sig, err := c.Check(context.Background(), pw)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if sig != nil {
		t.Fatalf("count 2 < MinCount 5 should not flag, got %+v", sig)
	}

	// Same body, default MinCount (1) → flagged.
	c2 := newHIBPTestChecker(t, srv)
	sig2, err := c2.Check(context.Background(), pw)
	if err != nil {
		t.Fatalf("Check (default mincount): %v", err)
	}
	if sig2 == nil || !sig2.Compromised {
		t.Fatalf("count 2 >= default MinCount 1 should flag, got %+v", sig2)
	}
}

func TestHIBP_PaddingCountZeroIgnored(t *testing.T) {
	t.Parallel()
	const pw = "P@ssw0rd-compromised-test"
	_, _, suffix := hibpHashParts(pw)

	// Add-Padding response: our suffix appears but with count 0 (padding),
	// surrounded by other count-0 padding lines. Must NOT be flagged.
	fake := &fakeHIBP{body: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\r\n" +
		suffix + ":0\r\n" +
		"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:0\r\n"}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c := newHIBPTestChecker(t, srv)
	sig, err := c.Check(context.Background(), pw)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if sig != nil {
		t.Fatalf("count-0 padding line must not flag, got %+v", sig)
	}
}

func TestHIBP_CRLFAndCaseInsensitiveSuffix(t *testing.T) {
	t.Parallel()
	const pw = "P@ssw0rd-compromised-test"
	_, _, suffix := hibpHashParts(pw)

	// Lower-case suffix + CRLF line endings + a leading padding line.
	fake := &fakeHIBP{body: "0000000000000000000000000000000000B:0\r\n" +
		strings.ToLower(suffix) + ":7\r\n"}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c := newHIBPTestChecker(t, srv)
	sig, err := c.Check(context.Background(), pw)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if sig == nil || !sig.Compromised {
		t.Fatalf("lower-case CRLF suffix should match, got %+v", sig)
	}
	if !strings.Contains(sig.Reason, "7") {
		t.Errorf("Reason %q missing count 7", sig.Reason)
	}
}

func TestHIBP_FailOpenOnServerError(t *testing.T) {
	t.Parallel()
	const pw = "P@ssw0rd-compromised-test"
	fake := &fakeHIBP{status: http.StatusInternalServerError, body: "boom"}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c := newHIBPTestChecker(t, srv)
	sig, err := c.Check(context.Background(), pw)
	// Fail-open: no signal AND no error (login must not be blocked).
	if err != nil {
		t.Fatalf("fail-open contract: Check returned error %v, want nil", err)
	}
	if sig != nil {
		t.Fatalf("fail-open contract: expected nil signal on 500, got %+v", sig)
	}
}

func TestHIBP_FailOpenOnConnectionRefused(t *testing.T) {
	t.Parallel()
	const pw = "P@ssw0rd-compromised-test"
	// Stand up then immediately close a server to get a refused/unreachable
	// address without sleeping.
	srv := httptest.NewServer(&fakeHIBP{})
	url := srv.URL
	srv.Close()

	c, err := NewHIBPPasswordHealthChecker(
		WithHIBPBaseURL(url+"/range/"),
		WithHIBPTimeout(500*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	sig, cerr := c.Check(context.Background(), pw)
	if cerr != nil {
		t.Fatalf("fail-open contract: Check returned error %v, want nil", cerr)
	}
	if sig != nil {
		t.Fatalf("fail-open contract: expected nil signal on refused conn, got %+v", sig)
	}
}

func TestHIBP_FailOpenOnTimeout(t *testing.T) {
	t.Parallel()
	const pw = "P@ssw0rd-compromised-test"
	_, _, suffix := hibpHashParts(pw)
	// Server delays well past the client timeout; the request must abort
	// and fail-open rather than hang the login.
	fake := &fakeHIBP{body: suffix + ":99\r\n", delay: 2 * time.Second}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c := newHIBPTestChecker(t, srv, WithHIBPTimeout(150*time.Millisecond))
	start := time.Now()
	sig, err := c.Check(context.Background(), pw)
	if err != nil {
		t.Fatalf("fail-open contract: Check returned error %v, want nil", err)
	}
	if sig != nil {
		t.Fatalf("fail-open contract: expected nil signal on timeout, got %+v", sig)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("timeout not honored: Check took %v, want < 1s", elapsed)
	}
}

func TestHIBP_ContextCancellationFailsOpen(t *testing.T) {
	t.Parallel()
	const pw = "P@ssw0rd-compromised-test"
	fake := &fakeHIBP{body: "X:1\r\n", delay: 2 * time.Second}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c := newHIBPTestChecker(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	sig, err := c.Check(ctx, pw)
	if err != nil {
		t.Fatalf("fail-open contract: cancelled ctx returned error %v, want nil", err)
	}
	if sig != nil {
		t.Fatalf("fail-open contract: cancelled ctx should yield nil signal, got %+v", sig)
	}
}

// TestHIBP_SignalShapeMatchesDictionary asserts the HIBP hit produces the
// same CredentialHealth shape contract the orchestrator consumes: a
// Compromised signal with a non-empty operator-facing Reason and no Weak
// flag, mirroring how DictionaryPasswordHealthChecker returns a Weak hit.
func TestHIBP_SignalShapeMatchesDictionary(t *testing.T) {
	t.Parallel()
	const pw = "P@ssw0rd-compromised-test"
	_, _, suffix := hibpHashParts(pw)
	fake := &fakeHIBP{body: suffix + ":3\r\n"}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c := newHIBPTestChecker(t, srv)
	sig, err := c.Check(context.Background(), pw)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if sig == nil {
		t.Fatal("expected a signal")
	}
	if !sig.Compromised || sig.Weak {
		t.Errorf("shape: Compromised=%v Weak=%v, want true/false", sig.Compromised, sig.Weak)
	}
	if sig.Reason == "" {
		t.Error("Reason empty; the orchestrator stamps it into audit metadata")
	}
}

// TestHIBP_ConcurrentChecks exercises the checker under -race: many
// goroutines hitting the same checker/server with distinct passwords. The
// checker holds no mutable per-call state, so this must be race-free.
func TestHIBP_ConcurrentChecks(t *testing.T) {
	t.Parallel()
	// A server that, for any prefix, returns a body containing the suffix
	// of THAT request's password with a count, so every goroutine that
	// queried a "breached" password gets flagged. We derive the suffix the
	// fake should echo from the requested prefix by precomputing a table.
	table := map[string]string{} // prefix -> suffix (count 8)
	passwords := make([]string, 64)
	for i := range passwords {
		pw := fmt.Sprintf("breached-concurrent-%d", i)
		passwords[i] = pw
		_, pfx, sfx := hibpHashParts(pw)
		table[pfx] = sfx
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := strings.TrimPrefix(r.URL.Path, "/range/")
		if sfx, ok := table[prefix]; ok {
			// Pad with a count-0 noise line + the real hit.
			_, _ = fmt.Fprintf(w, "00000000000000000000000000000000000:0\r\n%s:8\r\n", sfx)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newHIBPTestChecker(t, srv)
	var wg sync.WaitGroup
	for _, pw := range passwords {
		wg.Add(1)
		go func(pw string) {
			defer wg.Done()
			sig, err := c.Check(context.Background(), pw)
			if err != nil {
				t.Errorf("Check(%q): %v", pw, err)
				return
			}
			if sig == nil || !sig.Compromised {
				t.Errorf("Check(%q): expected Compromised, got %+v", pw, sig)
			}
		}(pw)
	}
	wg.Wait()
}
