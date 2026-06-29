package http_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/platform/releases"
	probehttp "github.com/snaplink/sso/platform/releases/probehttp"
)

func TestProbe_2xxIsHealthy(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	p := probehttp.New(srv.URL + "/-/health")
	if err := p.Probe(context.Background(), &releases.Release{ID: "rel-1"}); err != nil {
		t.Errorf("Probe: %v", err)
	}
}

func TestProbe_5xxIsUnhealthy(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	p := probehttp.New(srv.URL)
	if err := p.Probe(context.Background(), &releases.Release{ID: "rel-1"}); err == nil {
		t.Error("expected error on 500")
	}
}

func TestProbe_404IsUnhealthy(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	p := probehttp.New(srv.URL)
	if err := p.Probe(context.Background(), &releases.Release{ID: "rel-1"}); err == nil {
		t.Error("expected error on 404")
	}
}

func TestProbe_EmptyURLIsError(t *testing.T) {
	t.Parallel()
	p := probehttp.New("")
	if err := p.Probe(context.Background(), &releases.Release{ID: "rel-1"}); err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestProbe_UnreachableHostIsError(t *testing.T) {
	t.Parallel()
	p := probehttp.New("http://127.0.0.1:1/should-not-bind")
	if err := p.Probe(context.Background(), &releases.Release{ID: "rel-1"}); err == nil {
		t.Error("expected error for unreachable host")
	}
}
