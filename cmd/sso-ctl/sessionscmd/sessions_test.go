package sessionscmd

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
