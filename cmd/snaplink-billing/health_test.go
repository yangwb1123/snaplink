package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHealthRoutesKeepLivenessIndependentFromDependencies(t *testing.T) {
	var calls atomic.Int64
	health := healthHandler{timeout: time.Second, checks: []readyCheck{{
		name: "postgres", check: func(context.Context) error {
			calls.Add(1)
			return errors.New("dsn contains secret-do-not-return")
		},
	}}}
	mux := http.NewServeMux()
	registerHealthRoutes(mux, health)
	livez := httptest.NewRecorder()
	mux.ServeHTTP(livez, httptest.NewRequest(http.MethodGet, pathLivez, nil))
	if livez.Code != http.StatusOK || calls.Load() != 0 {
		t.Fatalf("livez status=%d dependency calls=%d", livez.Code, calls.Load())
	}
	readyz := httptest.NewRecorder()
	mux.ServeHTTP(readyz, httptest.NewRequest(http.MethodGet, pathReadyz, nil))
	if readyz.Code != http.StatusServiceUnavailable || calls.Load() != 1 {
		t.Fatalf("readyz status=%d dependency calls=%d", readyz.Code, calls.Load())
	}
	if strings.Contains(readyz.Body.String(), "secret-do-not-return") {
		t.Fatalf("readyz leaked dependency error: %s", readyz.Body.String())
	}
}

func TestHealthRoutesRejectNonGETWithoutAuthentication(t *testing.T) {
	mux := http.NewServeMux()
	registerHealthRoutes(mux, healthHandler{timeout: time.Second})
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, pathLivez, nil))
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("status=%d headers=%v", response.Code, response.Header())
	}
}

func TestJWKSReadinessDoesNotFollowRedirects(t *testing.T) {
	var targetCalls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalls.Add(1)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	check := jwksReadyCheck(redirect.URL, newUpstreamHTTPClient(time.Second))
	if err := check(t.Context()); err == nil || targetCalls.Load() != 0 {
		t.Fatalf("redirect check err=%v target calls=%d", err, targetCalls.Load())
	}
}
