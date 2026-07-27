package tokenscmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/cmd/sso-ctl/apiclient"
)

// captureStderr redirects os.Stderr for the duration of fn and returns
// everything written to it.
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
		b, _ := io.ReadAll(r)
		done <- b
	}()
	defer func() { os.Stderr = orig }()
	fn()
	_ = w.Close()
	os.Stderr = orig
	return string(<-done)
}

// TestRunIssueTemp_TTLNotSentAndWarned pins the fix for a silently-inert
// flag: adminv1.IssueTempTokenRequest (proto/admin/v1/tokens.proto) has no
// ttl field, and the gRPC-gateway's protojson unmarshaler discards unknown
// JSON fields (DiscardUnknown: true), so a "ttl" in the POST body was
// accepted, validated, and then thrown away server-side without a trace.
// This test asserts the request body no longer carries the dead field and
// that the user is warned instead of being misled into thinking --ttl took
// effect.
func TestRunIssueTemp_TTLNotSentAndWarned(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/tokens/temp" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"tmp_abc","expiresAtUnix":"1700003600"}`))
	}))
	defer srv.Close()
	t.Setenv(apiclient.EnvAddr, srv.URL)
	t.Setenv(apiclient.EnvToken, "test-token")

	stderr := captureStderr(t, func() {
		if code := runIssueTemp([]string{"--user=user-42", "--ttl=15m"}); code != 0 {
			t.Fatalf("runIssueTemp exit code = %d, want 0", code)
		}
	})

	if _, ok := gotBody["ttl"]; ok {
		t.Errorf("request body still sends a \"ttl\" field the server silently discards: %v", gotBody)
	}
	if gotBody["user_id"] != "user-42" {
		t.Errorf("user_id = %v, want user-42", gotBody["user_id"])
	}
	if !strings.Contains(stderr, "not enforced") {
		t.Errorf("expected a warning that --ttl is not enforced, got stderr: %q", stderr)
	}
}

// TestRunIssueTemp_NoTTLNoWarning confirms the common case (no --ttl at
// all) stays quiet — the warning is only for a flag the caller actually
// tried to use.
func TestRunIssueTemp_NoTTLNoWarning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"tmp_abc","expiresAtUnix":"1700003600"}`))
	}))
	defer srv.Close()
	t.Setenv(apiclient.EnvAddr, srv.URL)
	t.Setenv(apiclient.EnvToken, "test-token")

	stderr := captureStderr(t, func() {
		if code := runIssueTemp([]string{"--user=user-42"}); code != 0 {
			t.Fatalf("runIssueTemp exit code = %d, want 0", code)
		}
	})

	if strings.Contains(stderr, "not enforced") {
		t.Errorf("unexpected warning with no --ttl given: %q", stderr)
	}
}

// TestRunIssueTemp_InvalidTTLRejected keeps the existing input validation:
// garbage --ttl values are still a hard usage error.
func TestRunIssueTemp_InvalidTTLRejected(t *testing.T) {
	if code := runIssueTemp([]string{"--user=user-42", "--ttl=not-a-duration"}); code != 2 {
		t.Fatalf("runIssueTemp exit code = %d, want 2", code)
	}
}
