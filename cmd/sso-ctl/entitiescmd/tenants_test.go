package entitiescmd

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

// withMockAdmin points apiclient (and therefore RunTenants/RunUsers) at a
// local httptest server for the duration of the test.
func withMockAdmin(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv(apiclient.EnvAddr, srv.URL)
	return srv
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

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it.
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

// noRedirectRig is the two-server 307 rig every no-redirect test uses: a
// redirector answers every admin path with 307 + Location pointing at a
// target that counts requests and would serve the given valid body (so a
// pre-fix run completes instead of failing on a later parse step). Post-fix
// the target must observe ZERO requests — no forwarded bearer, no
// 307/308-replayed body. The redirector sends an oversized HTML body so the
// truncation marker shows up in the pinned stderr diagnostic.
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
		// Single-line oversized HTML body: the echo must stay one stderr
		// line, truncated at bodyEchoLimit with the "..." marker.
		_, _ = w.Write([]byte(strings.Repeat("<html>gateway moved</html>", 30)))
	}))
	t.Cleanup(redirector.Close)
	return redirector.URL, func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

// assertRedirectDiagnostic pins the A3 stderr contract on the 3xx path:
// exactly one line, the redirect wording, the SSO_ADMIN_ADDR hint, the
// truncation marker, and never the bearer token.
func assertRedirectDiagnostic(t *testing.T, stderr, verb, bearer string) {
	t.Helper()
	lines := strings.Split(strings.TrimRight(stderr, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly one stderr line, got %d: %q", len(lines), stderr)
	}
	for _, want := range []string{verb + " failed", "redirect", apiclient.RedirectHintAdmin, "..."} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("stderr missing %q: %q", want, lines[0])
		}
	}
	if strings.Contains(stderr, bearer) {
		t.Errorf("bearer token leaked to stderr: %q", stderr)
	}
}

// TestRunTenants_List_NoRedirect pins sites 1 (fetchList): a 307 from the
// admin API must fail the command with the redirect diagnostic; the target
// never sees the bearer.
func TestRunTenants_List_NoRedirect(t *testing.T) {
	url, hits := noRedirectRig(t, `{"tenants":[]}`)
	t.Setenv(apiclient.EnvAddr, url)
	t.Setenv(apiclient.EnvToken, "tok-list-noredirect")

	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			if code := RunTenants([]string{"list"}); code != 1 {
				t.Fatalf("RunTenants(list) = %d, want 1", code)
			}
		})
	})
	if got := hits(); got != 0 {
		t.Errorf("redirect target received %d requests, want 0 (bearer would have been forwarded)", got)
	}
	assertRedirectDiagnostic(t, stderr, "list", "tok-list-noredirect")
	if stdout != "" {
		t.Errorf("stdout not empty on the 3xx path: %q", stdout)
	}
}

// TestRunTenants_Get_NoRedirect pins site 2 (fetchOne).
func TestRunTenants_Get_NoRedirect(t *testing.T) {
	url, hits := noRedirectRig(t, `{"tenant":{"id":"acme"}}`)
	t.Setenv(apiclient.EnvAddr, url)
	t.Setenv(apiclient.EnvToken, "tok-get-noredirect")

	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			if code := RunTenants([]string{"get", "acme"}); code != 1 {
				t.Fatalf("RunTenants(get) = %d, want 1", code)
			}
		})
	})
	if got := hits(); got != 0 {
		t.Errorf("redirect target received %d requests, want 0", got)
	}
	assertRedirectDiagnostic(t, stderr, "get", "tok-get-noredirect")
	if stdout != "" {
		t.Errorf("stdout not empty on the 3xx path: %q", stdout)
	}
}

// TestRunTenants_SetStatus_NoRedirect pins site 3 (doWrite) with a 307
// WRITE: pre-fix Go replays method + body to the target, so this is the full
// F1 vector (bearer AND body forwarding).
func TestRunTenants_SetStatus_NoRedirect(t *testing.T) {
	url, hits := noRedirectRig(t, `{"tenant":{"id":"acme","status":"suspended"}}`)
	t.Setenv(apiclient.EnvAddr, url)
	t.Setenv(apiclient.EnvToken, "tok-write-noredirect")

	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			if code := RunTenants([]string{"set-status", "acme", "suspended"}); code != 1 {
				t.Fatalf("RunTenants(set-status) = %d, want 1", code)
			}
		})
	})
	if got := hits(); got != 0 {
		t.Errorf("redirect target received %d requests, want 0 (bearer and body would have been forwarded)", got)
	}
	assertRedirectDiagnostic(t, stderr, "set-status", "tok-write-noredirect")
	if stdout != "" {
		t.Errorf("stdout not empty on the 3xx path: %q", stdout)
	}
}

// TestRunUsers_List_NoRedirect pins the users boundary: users.go constructs
// no client of its own, so a regression that reintroduces a following client
// in the shared helpers fails here.
func TestRunUsers_List_NoRedirect(t *testing.T) {
	url, hits := noRedirectRig(t, `{"users":[]}`)
	t.Setenv(apiclient.EnvAddr, url)
	t.Setenv(apiclient.EnvToken, "tok-users-noredirect")

	stderr := captureStderr(t, func() {
		if code := RunUsers([]string{"list"}); code != 1 {
			t.Fatalf("RunUsers(list) = %d, want 1", code)
		}
	})
	if got := hits(); got != 0 {
		t.Errorf("redirect target received %d requests, want 0", got)
	}
	assertRedirectDiagnostic(t, stderr, "list", "tok-users-noredirect")
}

func TestRunTenants_ListSuccess(t *testing.T) {
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/admin/tenants" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenants": []Tenant{{ID: "acme", Name: "Acme", Slug: "acme", Status: "active"}},
		})
	})

	if code := RunTenants([]string{"list"}); code != 0 {
		t.Fatalf("RunTenants(list) = %d, want 0", code)
	}
}

func TestRunTenants_GetNotFound(t *testing.T) {
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "tenant_not_found"})
	})

	if code := RunTenants([]string{"get", "missing"}); code != 1 {
		t.Fatalf("RunTenants(get missing) = %d, want 1", code)
	}
}

func TestRunTenants_Create(t *testing.T) {
	var gotBody Tenant
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/admin/tenants" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tenant": gotBody})
	})

	code := RunTenants([]string{"create", "--id=acme", "--status=active", "--name=Acme Inc", "--slug=acme"})
	if code != 0 {
		t.Fatalf("RunTenants(create) = %d, want 0", code)
	}
	if gotBody.ID != "acme" || gotBody.Status != "active" || gotBody.Name != "Acme Inc" || gotBody.Slug != "acme" {
		t.Errorf("unexpected request body: %+v", gotBody)
	}
}

func TestRunTenants_CreateRejectsInvalidStatus(t *testing.T) {
	// No server needed: validation happens before any request is sent.
	t.Setenv(apiclient.EnvAddr, "http://127.0.0.1:0")

	code := RunTenants([]string{"create", "--id=acme", "--status=bogus"})
	if code != 2 {
		t.Fatalf("RunTenants(create bad status) = %d, want 2", code)
	}
}

func TestRunTenants_Delete(t *testing.T) {
	var called bool
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodDelete || r.URL.Path != "/api/v1/admin/tenants/acme" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{})
	})

	if code := RunTenants([]string{"delete", "acme", "--yes"}); code != 0 {
		t.Fatalf("RunTenants(delete --yes) = %d, want 0", code)
	}
	if !called {
		t.Error("expected DELETE request to be sent")
	}
}

func TestRunTenants_DeleteRefusesWithoutYes(t *testing.T) {
	var called bool
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	if code := RunTenants([]string{"delete", "acme"}); code != 2 {
		t.Fatalf("RunTenants(delete without --yes) = %d, want 2", code)
	}
	if called {
		t.Error("expected no request to be sent without --yes")
	}
}

// TestRunTenants_UpdateOmitsStatus is a regression test for the documented
// admin-API footgun: the update request body must never carry a "status"
// key, since the server's PUT handler ignores/preserves status and status
// transitions must go through set-status instead.
func TestRunTenants_UpdateOmitsStatus(t *testing.T) {
	var raw map[string]any
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/admin/tenants/acme" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tenant": raw})
	})

	code := RunTenants([]string{"update", "acme", "--name=Renamed"})
	if code != 0 {
		t.Fatalf("RunTenants(update) = %d, want 0", code)
	}
	if _, present := raw["status"]; present {
		t.Errorf("update request body must not contain \"status\", got: %v", raw)
	}
	if raw["name"] != "Renamed" {
		t.Errorf("update request body name = %v, want Renamed", raw["name"])
	}
}

func TestRunTenants_SetStatus(t *testing.T) {
	var gotBody map[string]string
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/admin/tenants/acme:set-status" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tenant": map[string]string{"id": "acme", "status": gotBody["status"]}})
	})

	code := RunTenants([]string{"set-status", "acme", "suspended"})
	if code != 0 {
		t.Fatalf("RunTenants(set-status) = %d, want 0", code)
	}
	if gotBody["status"] != "suspended" {
		t.Errorf("set-status request body = %v, want status=suspended", gotBody)
	}
}
