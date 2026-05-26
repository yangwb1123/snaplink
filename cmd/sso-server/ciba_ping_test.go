package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/spi"
)

func TestHTTPCIBAPingNotifier_PostsToEndpoint(t *testing.T) {
	var gotAuth, gotBody atomic.Value
	gotAuth.Store("")
	gotBody.Store("")
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		raw, _ := io.ReadAll(r.Body)
		gotBody.Store(string(raw))
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	n := newHTTPCIBAPingNotifier(config.CIBAPingConfig{
		Endpoints: map[string]string{"client-a": backend.URL},
	}, spi.NopLogger{})

	if err := n.Notify(context.Background(), "client-a", "areq-1", "tok-xyz"); err != nil {
		t.Fatalf("notify: %v", err)
	}
	if got := gotAuth.Load().(string); got != "Bearer tok-xyz" {
		t.Errorf("Authorization = %q, want Bearer tok-xyz", got)
	}
	var body map[string]string
	_ = json.Unmarshal([]byte(gotBody.Load().(string)), &body)
	if body["auth_req_id"] != "areq-1" {
		t.Errorf("body auth_req_id = %q, want areq-1", body["auth_req_id"])
	}
}

func TestHTTPCIBAPingNotifier_UnknownClientDegradesToPoll(t *testing.T) {
	n := newHTTPCIBAPingNotifier(config.CIBAPingConfig{
		Endpoints: map[string]string{"client-a": "http://unused"},
	}, spi.NopLogger{})
	// A client with no registered endpoint must NOT error (it polls).
	if err := n.Notify(context.Background(), "client-unknown", "areq-1", "tok"); err != nil {
		t.Errorf("unknown client returned error %v, want nil (degrade to poll)", err)
	}
}

func TestHTTPCIBAPingNotifier_Non2xxIsError(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()
	n := newHTTPCIBAPingNotifier(config.CIBAPingConfig{
		Endpoints: map[string]string{"client-a": backend.URL},
	}, spi.NopLogger{})
	if err := n.Notify(context.Background(), "client-a", "areq-1", "tok"); err == nil {
		t.Error("expected error on 5xx ping response")
	}
}
