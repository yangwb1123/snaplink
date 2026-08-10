package clientscmd

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
// redirector answers every admin path with 307 + Location pointing at a
// target that counts requests and would serve a valid body (so a pre-fix run
// completes instead of failing on a later parse step). Post-fix the target
// must observe ZERO requests.
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

// TestRunClients_List_NoRedirect pins site 4 (clients fetchList): a 307
// from the admin API must fail the command with the redirect diagnostic;
// the target never sees the bearer.
func TestRunClients_List_NoRedirect(t *testing.T) {
	url, hits := noRedirectRig(t, `{"clients":[]}`)
	t.Setenv(apiclient.EnvAddr, url)
	t.Setenv(apiclient.EnvToken, "tok-clients-list")

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
	if lines := strings.Split(strings.TrimRight(stderr, "\n"), "\n"); len(lines) != 1 {
		t.Fatalf("expected one stderr line, got %d: %q", len(lines), stderr)
	}
	for _, want := range []string{"list failed", "redirect", apiclient.RedirectHintAdmin, "..."} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q: %q", want, stderr)
		}
	}
	if strings.Contains(stderr, "tok-clients-list") {
		t.Errorf("bearer token leaked to stderr: %q", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout not empty on the 3xx path: %q", stdout)
	}
}

// TestRunClients_Get_NoRedirect pins site 5 (clients runGet).
func TestRunClients_Get_NoRedirect(t *testing.T) {
	url, hits := noRedirectRig(t, `{"client":{"id":"c1"}}`)
	t.Setenv(apiclient.EnvAddr, url)
	t.Setenv(apiclient.EnvToken, "tok-clients-get")

	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			if code := Run([]string{"get", "c1"}); code != 1 {
				t.Fatalf("Run(get) = %d, want 1", code)
			}
		})
	})
	if got := hits(); got != 0 {
		t.Errorf("redirect target received %d requests, want 0", got)
	}
	for _, want := range []string{"get failed", "redirect", apiclient.RedirectHintAdmin} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q: %q", want, stderr)
		}
	}
	if strings.Contains(stderr, "tok-clients-get") {
		t.Errorf("bearer token leaked to stderr: %q", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout not empty on the 3xx path: %q", stdout)
	}
}

// TestRunList_DecodesGatewayCamelCaseShape pins the admin gRPC-gateway's
// ACTUAL wire shape: protojson's default marshaler (no UseProtoNames) emits
// camelCase field names, including the read-only tenantId/grantTypes keys
// added to the Client proto message (fields 11/12). A struct tagged with
// the proto's snake_case names used to silently decode every client's
// RedirectURIs/TenantID/GrantTypes as blank. Regression test for that bug;
// the fixture is extended whenever a read-only field lands on Client.
func TestRunList_DecodesGatewayCamelCaseShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/clients" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// This mirrors the real shape produced by protojson.MarshalOptions{EmitUnpopulated:true}
		// for a ListClientsResponse — verified directly against the generated
		// adminv1 types, not hand-guessed. Unpopulated keys (clientSecretExpiresAt,
		// loginPageUri, ...) are omitted for readability; decoding does not
		// depend on them.
		_, _ = w.Write([]byte(`{"nextPageToken":"","totalSize":1,"clients":[` +
			`{"id":"abc123","secret":"","name":"Test Client","redirectUris":["https://example.com/cb"],` +
			`"allowedScopes":["openid","profile"],"allowedAuthenticators":[],"tokenStrategy":"jwt",` +
			`"tenantId":"tenant-acme","grantTypes":["authorization_code","refresh_token"],"active":true}]}`))
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
		TenantID      string   `json:"tenantId"`
		GrantTypes    []string `json:"grantTypes"`
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
	if c.TenantID != "tenant-acme" {
		t.Errorf("TenantID = %q, want %q", c.TenantID, "tenant-acme")
	}
	if len(c.GrantTypes) != 2 || c.GrantTypes[0] != "authorization_code" || c.GrantTypes[1] != "refresh_token" {
		t.Errorf("GrantTypes = %v, want [authorization_code refresh_token]", c.GrantTypes)
	}
	if !c.Active {
		t.Errorf("Active = false, want true")
	}
	// The rendered JSON must carry the camelCase keys and values (decode AND
	// render), not just decode them into the struct.
	for _, want := range []string{"tenantId", "tenant-acme", "grantTypes", "authorization_code", "refresh_token"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output missing %q:\n%s", want, out)
		}
	}
}

// TestRunList_TableFormat exercises the --format=table path with the same
// gateway response shape, confirming the table shows real data including the
// tenant binding and grant-type allowlist columns.
func TestRunList_TableFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"clients":[` +
			`{"id":"c1","name":"Client One","redirectUris":["https://a.example/cb","https://b.example/cb"],` +
			`"tokenStrategy":"opaque","tenantId":"tenant-acme",` +
			`"grantTypes":["authorization_code","refresh_token"],"active":true}]}`))
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
	for _, want := range []string{"TenantID", "tenant-acme", "GrantTypes", "authorization_code,refresh_token"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q:\n%s", want, out)
		}
	}
}

// TestRunList_UnboundClientOmitsReadOnlyKeys pins the cross-version and
// single-tenant shapes: an unbound client (no tenantId/grantTypes keys on
// the wire — either an old server or an empty binding) must render WITHOUT
// the read-only keys thanks to omitempty, instead of leaking "tenantId":""
// / "grantTypes":[] that EmitUnpopulated would produce server-side.
func TestRunList_UnboundClientOmitsReadOnlyKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"clients":[` +
			`{"id":"c2","name":"Unbound","tokenStrategy":"jwt","active":true}]}`))
	}))
	defer srv.Close()
	t.Setenv(apiclient.EnvAddr, srv.URL)
	t.Setenv(apiclient.EnvToken, "test-token")

	out := captureStdout(t, func() {
		if code := runList(nil); code != 0 {
			t.Fatalf("runList exit code = %d, want 0", code)
		}
	})

	if strings.Contains(out, "tenantId") || strings.Contains(out, "grantTypes") {
		t.Errorf("unbound client output leaks read-only keys:\n%s", out)
	}
}
