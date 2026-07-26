package security

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewUpstreamClient_Defaults(t *testing.T) {
	client := NewUpstreamClient(UpstreamClientConfig{})
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Timeout != DefaultUpstreamTimeout {
		t.Errorf("expected timeout %v, got %v", DefaultUpstreamTimeout, client.Timeout)
	}
}

func TestNewUpstreamClient_CustomTimeout(t *testing.T) {
	client := NewUpstreamClient(UpstreamClientConfig{Timeout: 30 * time.Second})
	if client.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", client.Timeout)
	}
}

func TestUpstreamDo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := http.DefaultClient
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := UpstreamDo(context.Background(), client, req)
	if err != nil {
		t.Fatalf("UpstreamDo: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestUpstreamDo_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	client := http.DefaultClient
	req, _ := http.NewRequest("GET", server.URL, nil)

	_, err := UpstreamDo(ctx, client, req)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestNewUpstreamClient_TransportConfigured(t *testing.T) {
	client := NewUpstreamClient(UpstreamClientConfig{})
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if transport.MaxIdleConns < 1 {
		t.Errorf("expected MaxIdleConns >= 1, got %d", transport.MaxIdleConns)
	}
}
