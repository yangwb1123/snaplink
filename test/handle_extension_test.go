package ssotest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

func TestServer_HandleMountsExtensionRoute(t *testing.T) {
	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
	)

	// Force Mount via Handler() so the router is initialized before
	// Handle is called — same lifecycle a cmd embedder would follow.
	h := srv.Handler()
	if err := srv.Handle(http.MethodPost, "/ext/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	}); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	httpSrv := httptest.NewServer(h)
	defer httpSrv.Close()

	resp, err := http.Post(httpSrv.URL+"/ext/echo", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Fatalf("echo body: got %q want hello", body)
	}
}

func TestServer_HandleRejectsUnknownMethod(t *testing.T) {
	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
	)
	_ = srv.Handler()

	err := srv.Handle("WEIRD", "/x", func(http.ResponseWriter, *http.Request) {})
	if err == nil {
		t.Fatal("Handle: expected error for unknown method")
	}
}

func TestServer_HandleBeforeMountErrors(t *testing.T) {
	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
	)

	err := srv.Handle(http.MethodGet, "/x", func(http.ResponseWriter, *http.Request) {})
	if err == nil {
		t.Fatal("Handle: expected error when called before Mount/Handler")
	}
}

func TestServer_HandleCaseInsensitiveMethod(t *testing.T) {
	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
	)
	_ = srv.Handler()

	for _, method := range []string{"get", "Get", "GET", "post", "PUT", "delete"} {
		if err := srv.Handle(method, "/ext/"+method, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}); err != nil {
			t.Fatalf("Handle %q: %v", method, err)
		}
	}
}
