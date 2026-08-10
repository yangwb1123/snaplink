package sessionscmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/yangwb1123/snaplink/cmd/sso-ctl/apiclient"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it. Mirrors the helper used elsewhere in
// cmd/sso-ctl (e.g. importcmd/main_test.go).
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	defer func() { os.Stdout = orig }()
	fn()
	_ = w.Close()
	os.Stdout = orig
	return string(<-done)
}

// captureStderr redirects os.Stderr for the duration of fn and returns
// everything written to it. The no-redirect tests swap stderr to pin the
// redirect diagnostic, so they must NOT call t.Parallel.
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

// noRedirectRig is the two-server 307 rig every no-redirect test uses: a
// redirector answers the admin path with 307 + Location pointing at a target
// that counts requests and would serve a valid body (so a pre-fix run
// completes instead of failing on a later parse step). Post-fix the target
// must observe ZERO requests — no forwarded bearer, no 307-replayed body.
func noRedirectRig(t *testing.T, targetBody string) (redirectorURL string, hits func() int) {
	t.Helper()
	var mu sync.Mutex
	n := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(targetBody))
	}))
	t.Cleanup(target.Close)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = w.Write([]byte(strings.Repeat("<html>gateway moved</html>", 30)))
	}))
	t.Cleanup(redirector.Close)
	return redirector.URL, func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

// TestRunSessions_List_NoRedirect pins site 8 (sessions fetchList): a 307
// from the admin API must fail the command with the redirect diagnostic;
// the target never sees the bearer.
func TestRunSessions_List_NoRedirect(t *testing.T) {
	url, hits := noRedirectRig(t, `{"sessions":[]}`)
	t.Setenv(apiclient.EnvAddr, url)
	t.Setenv(apiclient.EnvToken, "tok-sessions-list")

	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			if code := Run([]string{"list"}); code != 1 {
				t.Fatalf("Run(list) = %d, want 1", code)
			}
		})
	})
	if got := hits(); got != 0 {
		t.Errorf("redirect target received %d requests, want 0 (bearer would have been forwarded)", got)
	}
	for _, want := range []string{"list failed", "redirect", apiclient.RedirectHintAdmin, "..."} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q: %q", want, stderr)
		}
	}
	if strings.Contains(stderr, "tok-sessions-list") {
		t.Errorf("bearer token leaked to stderr: %q", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout not empty on the 3xx path: %q", stdout)
	}
}

// TestRunSessions_Revoke_NoRedirect pins site 9 (sessions runRevoke): a 307
// on the revoke POST must fail the command; the target never sees the bearer
// or the replayed {"session_id":...} body.
func TestRunSessions_Revoke_NoRedirect(t *testing.T) {
	url, hits := noRedirectRig(t, `{}`)
	t.Setenv(apiclient.EnvAddr, url)
	t.Setenv(apiclient.EnvToken, "tok-sessions-revoke")

	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			if code := Run([]string{"revoke", "s1"}); code != 1 {
				t.Fatalf("Run(revoke) = %d, want 1", code)
			}
		})
	})
	if got := hits(); got != 0 {
		t.Errorf("redirect target received %d requests, want 0 (bearer and body would have been forwarded)", got)
	}
	for _, want := range []string{"revoke failed", "redirect", apiclient.RedirectHintAdmin, "..."} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q: %q", want, stderr)
		}
	}
	if strings.Contains(stderr, "tok-sessions-revoke") {
		t.Errorf("bearer token leaked to stderr: %q", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout not empty on the 3xx path: %q", stdout)
	}
}

// TestRunList_DecodesGatewayCamelCaseShape pins the admin gRPC-gateway's
// ACTUAL wire shape: protojson's default marshaler (no UseProtoNames) emits
// camelCase field names AND renders int64 fields as JSON strings (to avoid
// JS precision loss). A struct tagged with the proto's snake_case int
// field names used to silently decode every session's UserID as blank and
// CreatedAt/ExpiresAt as 0 ("never"). Regression test for that bug.
func TestRunList_DecodesGatewayCamelCaseShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/tokens/sessions" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Real shape produced by protojson.MarshalOptions{EmitUnpopulated:true}
		// for a ListSessionsResponse (verified against the generated adminv1
		// types): userId/createdAtUnix/expiresAtUnix, int64 as JSON strings.
		_, _ = w.Write([]byte(`{"nextPageToken":"","totalSize":1,"sessions":[` +
			`{"id":"sess1","userId":"user-42","createdAtUnix":"1700000000","expiresAtUnix":"1700003600"}]}`))
	}))
	defer srv.Close()
	t.Setenv(apiclient.EnvAddr, srv.URL)
	t.Setenv(apiclient.EnvToken, "test-token")

	out := captureStdout(t, func() {
		if code := runList(nil); code != 0 {
			t.Fatalf("runList exit code = %d, want 0", code)
		}
	})

	var got []struct {
		ID            string `json:"id"`
		UserID        string `json:"userId"`
		CreatedAtUnix int64  `json:"createdAtUnix,string"`
		ExpiresAtUnix int64  `json:"expiresAtUnix,string"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, out)
	}
	if len(got) != 1 {
		t.Fatalf("got %d sessions, want 1", len(got))
	}
	s := got[0]
	if s.UserID != "user-42" {
		t.Errorf("UserID = %q, want %q (was silently dropped before the fix)", s.UserID, "user-42")
	}
	if s.CreatedAtUnix != 1700000000 {
		t.Errorf("CreatedAtUnix = %d, want 1700000000 (was silently 0 before the fix)", s.CreatedAtUnix)
	}
	if s.ExpiresAtUnix != 1700003600 {
		t.Errorf("ExpiresAtUnix = %d, want 1700003600 (was silently 0/\"never\" before the fix)", s.ExpiresAtUnix)
	}
}

// TestRunList_TableFormat confirms the table view no longer prints "never"
// for a session that actually has a real expiry.
func TestRunList_TableFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sessions":[` +
			`{"id":"sess1","userId":"user-42","createdAtUnix":"1700000000","expiresAtUnix":"1700003600"}]}`))
	}))
	defer srv.Close()
	t.Setenv(apiclient.EnvAddr, srv.URL)
	t.Setenv(apiclient.EnvToken, "test-token")

	out := captureStdout(t, func() {
		if code := runList([]string{"--format=table"}); code != 0 {
			t.Fatalf("runList exit code = %d, want 0", code)
		}
	})

	if strings.Contains(out, "never") {
		t.Errorf("table output shows \"never\" for a session with a real expiry:\n%s", out)
	}
	if !strings.Contains(out, "user-42") || !strings.Contains(out, "1700003600") {
		t.Errorf("table output missing decoded fields:\n%s", out)
	}
}
