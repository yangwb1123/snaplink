package clientscmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/snaplink/sso/cmd/sso-ctl/apiclient"
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
// camelCase field names, and the Client proto message has no tenant_id /
// grant_types field at all (see proto/admin/v1/clients.proto). A struct
// tagged with the proto's snake_case names used to silently decode every
// client's RedirectURIs/TenantID/GrantTypes as blank. Regression test for
// that bug.
func TestRunList_DecodesGatewayCamelCaseShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/clients" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// This is the real shape produced by protojson.MarshalOptions{EmitUnpopulated:true}
		// for a ListClientsResponse — verified directly against the generated
		// adminv1 types, not hand-guessed.
		_, _ = w.Write([]byte(`{"nextPageToken":"","totalSize":1,"clients":[` +
			`{"id":"abc123","secret":"","name":"Test Client","redirectUris":["https://example.com/cb"],` +
			`"allowedScopes":["openid","profile"],"allowedAuthenticators":[],"tokenStrategy":"jwt","active":true}]}`))
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
		ID            string   `json:"id"`
		Name          string   `json:"name"`
		TokenStrategy string   `json:"tokenStrategy"`
		RedirectURIs  []string `json:"redirectUris"`
		Active        bool     `json:"active"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, out)
	}
	if len(got) != 1 {
		t.Fatalf("got %d clients, want 1", len(got))
	}
	c := got[0]
	if c.ID != "abc123" || c.Name != "Test Client" {
		t.Errorf("got id=%q name=%q", c.ID, c.Name)
	}
	if c.TokenStrategy != "jwt" {
		t.Errorf("TokenStrategy = %q, want %q (was silently dropped before the fix)", c.TokenStrategy, "jwt")
	}
	if len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "https://example.com/cb" {
		t.Errorf("RedirectURIs = %v, want [https://example.com/cb] (was silently dropped before the fix)", c.RedirectURIs)
	}
	if !c.Active {
		t.Errorf("Active = false, want true")
	}
}

// TestRunList_TableFormat exercises the --format=table path with the same
// gateway response shape, confirming the table shows real data instead of
// permanently-blank TenantID/GrantTypes columns.
func TestRunList_TableFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"clients":[` +
			`{"id":"c1","name":"Client One","redirectUris":["https://a.example/cb","https://b.example/cb"],` +
			`"tokenStrategy":"opaque","active":true}]}`))
	}))
	defer srv.Close()
	t.Setenv(apiclient.EnvAddr, srv.URL)
	t.Setenv(apiclient.EnvToken, "test-token")

	out := captureStdout(t, func() {
		if code := runList([]string{"--format=table"}); code != 0 {
			t.Fatalf("runList exit code = %d, want 0", code)
		}
	})

	if !strings.Contains(out, "opaque") {
		t.Errorf("table output missing token strategy %q:\n%s", "opaque", out)
	}
	if !strings.Contains(out, "https://a.example/cb,https://b.example/cb") {
		t.Errorf("table output missing joined redirect URIs:\n%s", out)
	}
}
