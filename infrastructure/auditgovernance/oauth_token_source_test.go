package auditgovernance

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOAuthTokenSourceUsesBasicAndCachesAcrossTenants(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		assertTokenRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"signed-token","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()
	source := newTestOAuthSource(t, server.URL, nil)
	for _, tenantID := range []string{"tenant-a", "tenant-b"} {
		token, err := source.AccessToken(t.Context(), testSourceBinding(t, tenantID))
		if err != nil || token != "signed-token" {
			t.Fatalf("AccessToken(%s) = (%q, %v)", tenantID, token, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("token endpoint calls = %d, want 1", calls.Load())
	}
}

func TestOAuthTokenSourceCollapsesConcurrentRefresh(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"shared","token_type":"bearer","expires_in":60}`))
	}))
	defer server.Close()
	source := newTestOAuthSource(t, server.URL, nil)
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			token, err := source.AccessToken(context.Background(), testSourceBinding(t, "tenant-a"))
			if err != nil || token != "shared" {
				t.Errorf("AccessToken = (%q, %v)", token, err)
			}
		}()
	}
	group.Wait()
	if calls.Load() != 1 {
		t.Fatalf("token endpoint calls = %d, want 1", calls.Load())
	}
}

func TestOAuthTokenSourceRefreshesBeforeExpiry(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"token-%d","token_type":"Bearer","expires_in":100}`, call)
	}))
	defer server.Close()
	source := newTestOAuthSource(t, server.URL, []OAuthTokenOption{
		WithOAuthTokenClock(func() time.Time { return now }),
	})
	binding := testSourceBinding(t, "tenant-a")
	first, err := source.AccessToken(t.Context(), binding)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(69 * time.Second)
	cached, _ := source.AccessToken(t.Context(), binding)
	now = now.Add(2 * time.Second)
	refreshed, _ := source.AccessToken(t.Context(), binding)
	if first != "token-1" || cached != first || refreshed != "token-2" || calls.Load() != 2 {
		t.Fatalf("tokens = %q, %q, %q; calls=%d", first, cached, refreshed, calls.Load())
	}
}

func TestOAuthTokenSourceRejectsUnsafeConfigAndBinding(t *testing.T) {
	config := testOAuthTokenConfig("http://audit.example/token")
	if _, err := NewOAuthTokenSource(config, nil); err == nil {
		t.Fatal("non-loopback HTTP token endpoint accepted")
	}
	config.TokenURL = "http://127.0.0.1/token"
	if _, err := NewOAuthTokenSource(config, nil); err == nil {
		t.Fatal("loopback HTTP token endpoint accepted without opt-in")
	}
	config.AllowInsecureLoopback = true
	source, err := NewOAuthTokenSource(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, binding := range []SourceBinding{
		{SourceSystem: "billing"},
		{TenantID: "tenant-a", SourceSystem: "other"},
	} {
		if _, err := source.AccessToken(t.Context(), binding); err == nil {
			t.Fatalf("binding %+v accepted", binding)
		}
	}
}

func TestOAuthTokenSourceDoesNotFollowRedirect(t *testing.T) {
	var targetCalls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalls.Add(1)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	source := newTestOAuthSource(t, redirect.URL, nil)
	_, err := source.AccessToken(t.Context(), testSourceBinding(t, "tenant-a"))
	if err == nil || targetCalls.Load() != 0 {
		t.Fatalf("redirect result err=%v target calls=%d", err, targetCalls.Load())
	}
}

func newTestOAuthSource(t *testing.T, endpoint string, options []OAuthTokenOption) *OAuthTokenSource {
	t.Helper()
	config := testOAuthTokenConfig(endpoint)
	config.AllowInsecureLoopback = true
	source, err := NewOAuthTokenSource(config, nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func testOAuthTokenConfig(endpoint string) OAuthTokenConfig {
	return OAuthTokenConfig{
		TokenURL: endpoint, ClientID: "relay-client", ClientSecret: "relay-secret",
		SourcePrefix: "billing", Scope: "audit:event:write", Resources: []string{"audit-governance"},
	}
}

func testSourceBinding(t *testing.T, tenantID string) SourceBinding {
	t.Helper()
	sourceID, err := TenantSourceID("billing", tenantID)
	if err != nil {
		t.Fatal(err)
	}
	return SourceBinding{TenantID: tenantID, SourceSystem: sourceID}
}

func assertTokenRequest(t *testing.T, request *http.Request) {
	t.Helper()
	id, secret, ok := request.BasicAuth()
	if !ok || id != "relay-client" || secret != "relay-secret" {
		t.Errorf("Basic credentials = (%q, %q, %v)", id, secret, ok)
	}
	if err := request.ParseForm(); err != nil {
		t.Fatal(err)
	}
	want := url.Values{
		"grant_type": {"client_credentials"}, "scope": {"audit:event:write"},
		"resource": {"audit-governance"},
	}
	if request.Form.Encode() != want.Encode() || request.Form.Has("client_id") || request.Form.Has("client_secret") {
		t.Errorf("token form = %v, want %v without body credentials", request.Form, want)
	}
}
