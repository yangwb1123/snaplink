package tui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/yangwb1123/snaplink/cmd/sso-ctl/apiclient"
)

// noRedirectRig is the two-server 307 rig every no-redirect test uses: a
// redirector answers every admin path with 307 + Location pointing at a
// target that counts requests and would serve a valid envelope (so a pre-fix
// run completes instead of failing on a later parse step). Post-fix the
// target must observe ZERO requests.
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

// TestFetchItems_200 is the tui non-3xx baseline: a valid list envelope
// decodes without error through the shared no-redirect client.
func TestFetchItems_200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tenants":[{"id":"acme","name":"Acme","slug":"acme","status":"active"}]}`))
	}))
	defer srv.Close()
	t.Setenv(apiclient.EnvAddr, srv.URL)
	t.Setenv(apiclient.EnvToken, "tok-tui-200")

	items, err := fetchItems(newClient(), tenantDescriptor)
	if err != nil {
		t.Fatalf("fetchItems: %v", err)
	}
	if len(items) != 1 || items[0].id != "acme" || items[0].title != "Acme" {
		t.Errorf("items = %+v, want one Acme tenant", items)
	}
}

// TestApiErrorMessage_Non3xx pins tui's non-3xx status-line shape for the
// first time: "HTTP <code>: <decoded message>" (grpc-gateway google.rpc
// shape) and the raw-body fallback.
func TestApiErrorMessage_Non3xx(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}}
	got := apiErrorMessage("fetch", resp, []byte(`{"code":5,"message":"tenant_not_found"}`))
	if got != "HTTP 404: tenant_not_found" {
		t.Errorf("apiErrorMessage(decoded) = %q, want %q", got, "HTTP 404: tenant_not_found")
	}
	got = apiErrorMessage("delete", resp, []byte("raw boom"))
	if got != "HTTP 404: raw boom" {
		t.Errorf("apiErrorMessage(raw) = %q, want %q", got, "HTTP 404: raw boom")
	}
}

// TestFetchItems_NoRedirect pins site 10 GET: newClient() must stop at the
// 307; the target never sees the bearer.
func TestFetchItems_NoRedirect(t *testing.T) {
	url, hits := noRedirectRig(t, `{"tenants":[]}`)
	t.Setenv(apiclient.EnvAddr, url)
	t.Setenv(apiclient.EnvToken, "tok-tui-fetch")

	_, err := fetchItems(newClient(), tenantDescriptor)
	if err == nil {
		t.Fatal("fetchItems: expected error on 307, got nil")
	}
	if got := hits(); got != 0 {
		t.Errorf("redirect target received %d requests, want 0", got)
	}
	for _, want := range []string{"fetch failed", "redirect", apiclient.RedirectHintAdmin} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "tok-tui-fetch") {
		t.Errorf("bearer token leaked into error: %v", err)
	}
}

// TestCreateItem_NoRedirect pins site 10 POST: a 307 write must surface an
// error; the target never sees the bearer or the replayed body.
func TestCreateItem_NoRedirect(t *testing.T) {
	url, hits := noRedirectRig(t, `{"tenant":{"id":"acme","name":"Acme"}}`)
	t.Setenv(apiclient.EnvAddr, url)
	t.Setenv(apiclient.EnvToken, "tok-tui-create")

	_, err := createItem(newClient(), tenantDescriptor, map[string]any{"id": "acme"})
	if err == nil {
		t.Fatal("createItem: expected error on 307, got nil")
	}
	if got := hits(); got != 0 {
		t.Errorf("redirect target received %d requests, want 0", got)
	}
	for _, want := range []string{"create failed", "redirect", apiclient.RedirectHintAdmin} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
}

// TestUpdateItem_NoRedirect pins site 10 PUT: a 307 write must surface an
// error; the target never sees the bearer or the replayed body.
func TestUpdateItem_NoRedirect(t *testing.T) {
	url, hits := noRedirectRig(t, `{"tenant":{"id":"acme","name":"Renamed"}}`)
	t.Setenv(apiclient.EnvAddr, url)
	t.Setenv(apiclient.EnvToken, "tok-tui-update")

	_, err := updateItem(newClient(), tenantDescriptor, "acme", map[string]any{"name": "Renamed"})
	if err == nil {
		t.Fatal("updateItem: expected error on 307, got nil")
	}
	if got := hits(); got != 0 {
		t.Errorf("redirect target received %d requests, want 0", got)
	}
	for _, want := range []string{"update failed", "redirect", apiclient.RedirectHintAdmin} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
}

// TestDeleteItem_NoRedirect pins site 10 DELETE: a 307 write must surface an
// error; the target never sees the bearer.
func TestDeleteItem_NoRedirect(t *testing.T) {
	url, hits := noRedirectRig(t, `{}`)
	t.Setenv(apiclient.EnvAddr, url)
	t.Setenv(apiclient.EnvToken, "tok-tui-delete")

	_, err := deleteItem(newClient(), tenantDescriptor, "acme", "Acme")
	if err == nil {
		t.Fatal("deleteItem: expected error on 307, got nil")
	}
	if got := hits(); got != 0 {
		t.Errorf("redirect target received %d requests, want 0", got)
	}
	for _, want := range []string{"delete failed", "redirect", apiclient.RedirectHintAdmin} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
}
