package main

import (
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestReadFromFile_MissingFile — a path that doesn't exist surfaces the
// os.ReadFile error rather than a panic or empty result.
func TestReadFromFile_MissingFile(t *testing.T) {
	if _, err := readFromFile(filepath.Join(t.TempDir(), "nope.json"), 0); err == nil {
		t.Fatal("expected error reading a missing file")
	}
}

// TestReadFromFile_BadJSON — neither a JSON array nor an {events:[...]}
// object → parseEventList's terminal error.
func TestReadFromFile_BadJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"not_events": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFromFile(path, 0); err == nil {
		t.Fatal("expected parse error for non-array/non-envelope JSON")
	}
}

// TestReadFromFile_LimitTruncates — the --limit cap is honored on file
// input, slicing the chain down to the first N events.
func TestReadFromFile_LimitTruncates(t *testing.T) {
	events := chainedEvents(t, 5)
	raw, _ := json.Marshal(events)
	path := filepath.Join(t.TempDir(), "events.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readFromFile(path, 2)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d events; want 2 (limit cap)", len(got))
	}
}

// TestReadFromURL_BadBaseURL — an unparseable base URL is rejected up
// front.
func TestReadFromURL_BadBaseURL(t *testing.T) {
	if _, err := readFromURL("://not a url", "t", 0, 10, time.Second); err == nil {
		t.Fatal("expected parse error for malformed base URL")
	}
}

// TestReadFromURL_HTTPError — a non-2xx page response is surfaced with
// the status code + body, not silently swallowed.
func TestReadFromURL_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := readFromURL(srv.URL, "t", 0, 10, time.Second); err == nil {
		t.Fatal("expected error for 500 response")
	}
}

// TestReadFromURL_BadPageBody — a 200 with a body that isn't a valid
// event list fails at parseEventList.
func TestReadFromURL_BadPageBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"garbage": true}`))
	}))
	defer srv.Close()
	if _, err := readFromURL(srv.URL, "t", 0, 10, time.Second); err == nil {
		t.Fatal("expected parse error for non-event-list body")
	}
}

// TestReadFromURL_RequestError — a connection-refused base URL surfaces
// the transport error from client.Do.
func TestReadFromURL_RequestError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // close immediately so the next request fails to connect
	if _, err := readFromURL(url, "t", 0, 10, 200*time.Millisecond); err == nil {
		t.Fatal("expected transport error against a closed server")
	}
}

// TestReadFromURL_PageSizeClampedToMax — a page size above
// audit.MaxQueryLimit is clamped; the server sees at most the cap.
func TestReadFromURL_PageSizeClamped(t *testing.T) {
	events := chainedEvents(t, 1)
	var seenLimit string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenLimit = r.URL.Query().Get("limit")
		_ = json.NewEncoder(w).Encode(map[string]any{"events": events})
	}))
	defer srv.Close()
	// Pass an absurd page size; the tool must clamp to MaxQueryLimit (1000).
	if _, err := readFromURL(srv.URL, "t", 0, 999999, time.Second); err != nil {
		t.Fatalf("read: %v", err)
	}
	if seenLimit != "1000" {
		t.Errorf("server saw limit=%q; want clamped 1000", seenLimit)
	}
}

// TestReadFromURL_NonPositivePageSizeDefaults — page size <= 0 falls
// back to the 500 default.
func TestReadFromURL_NonPositivePageSizeDefaults(t *testing.T) {
	var seenLimit string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenLimit = r.URL.Query().Get("limit")
		_ = json.NewEncoder(w).Encode(map[string]any{"events": []any{}})
	}))
	defer srv.Close()
	if _, err := readFromURL(srv.URL, "t", 0, 0, time.Second); err != nil {
		t.Fatalf("read: %v", err)
	}
	if seenLimit != "500" {
		t.Errorf("server saw limit=%q; want default 500", seenLimit)
	}
}

// TestMain_VerifyHappyPath drives main() end to end on the happy verify
// path (file mode → readFromFile → VerifyChain → success print), which
// returns normally without calling os.Exit. main() registers its flags
// on the global flag set, so this runs exactly once in the package.
func TestMain_VerifyHappyPath(t *testing.T) {
	events := chainedEvents(t, 3)
	raw, _ := json.Marshal(events)
	path := filepath.Join(t.TempDir(), "events.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Restore os.Args + the global flag set so the test framework's own
	// flags aren't disturbed for sibling tests.
	origArgs := os.Args
	origFlags := flag.CommandLine
	t.Cleanup(func() {
		os.Args = origArgs
		flag.CommandLine = origFlags
	})
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	os.Args = []string{progName, "--from-file", path}

	out := captureStdout(t, main)
	if !strings.Contains(out, "chain verified") {
		t.Errorf("main happy path missing 'chain verified' line; got:\n%s", out)
	}
}

// captureStdout redirects os.Stdout while fn runs and returns the
// trimmed captured output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		var b strings.Builder
		buf := make([]byte, 1024)
		for {
			n, e := r.Read(buf)
			b.Write(buf[:n])
			if e != nil {
				break
			}
		}
		done <- b.String()
	}()
	fn()
	_ = w.Close()
	out := <-done
	os.Stdout = orig
	return strings.TrimSpace(out)
}

// TestUsage_PrintsBanner — the usage banner names the program and both
// input modes so -h / parse errors are actionable.
func TestUsage_PrintsBanner(t *testing.T) {
	out := captureStderr(t, usage)
	for _, want := range []string{progName, "--from-file", "--from-url"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage output missing %q:\n%s", want, out)
		}
	}
}

// captureStderr redirects os.Stderr while fn runs and returns the
// captured bytes as a string.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	done := make(chan []byte)
	go func() {
		b := make([]byte, 0, 4096)
		buf := make([]byte, 1024)
		for {
			n, e := r.Read(buf)
			b = append(b, buf[:n]...)
			if e != nil {
				break
			}
		}
		done <- b
	}()
	fn()
	_ = w.Close()
	out := <-done
	os.Stderr = orig
	return string(out)
}
