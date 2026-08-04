package auditgovernance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

var clientTestNow = time.Unix(1_700_000_000, 0).UTC()

type tokenSourceFunc func(context.Context, SourceBinding) (string, error)

func (f tokenSourceFunc) AccessToken(ctx context.Context, binding SourceBinding) (string, error) {
	return f(ctx, binding)
}

func validCommerceEvent() *commerce.OutboxEvent {
	return &commerce.OutboxEvent{
		ID: "evt-1", TenantID: "tenant-a", Type: commerce.EventSubscriptionCreated,
		AggregateType: "subscription", AggregateID: "sub-1", AggregateVersion: 2,
		IdempotencyKey: "subscription:sub-1:2", OccurredAt: clientTestNow,
		Payload:       map[string]string{"plan_id": "full", "status": "active"},
		PayloadDigest: "digest-1", Status: commerce.OutboxLeased, Attempts: 1,
	}
}

func TestHTTPClientUsesTrustedBindingAndValidatesReceipt(t *testing.T) {
	var body map[string]any
	sourceID, err := TenantSourceID("snaplink-commerce", "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/events" || request.URL.Query().Get("wait_for") != "ledgered" ||
			request.Header.Get("Authorization") != "Bearer opaque-token" {
			t.Errorf("unexpected request path or authorization")
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusAccepted)
		_, _ = fmt.Fprintf(w, `{"receipt":{"event_id":"evt-1","tenant_id":"tenant-a","status":"ledgered","accepted_at":%q}}`, clientTestNow.Format(time.RFC3339))
	}))
	defer server.Close()
	tokens := tokenSourceFunc(func(_ context.Context, binding SourceBinding) (string, error) {
		if binding != (SourceBinding{TenantID: "tenant-a", SourceSystem: sourceID}) {
			t.Fatalf("unexpected binding: %+v", binding)
		}
		return "opaque-token", nil
	})
	client, err := NewHTTPClient(HTTPConfig{
		BaseURL: server.URL, SourcePrefix: "snaplink-commerce", AllowInsecureLoopback: true,
	}, tokens, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := client.Publish(context.Background(), validCommerceEvent())
	if err != nil || receipt.EventID != "evt-1" || receipt.TenantID != "tenant-a" {
		t.Fatalf("unexpected receipt: %+v err=%v", receipt, err)
	}
	if _, exists := body["tenant_id"]; exists {
		t.Fatal("tenant_id must be derived from the bearer, not sent in the body")
	}
	if body["source_system"] != sourceID {
		t.Fatalf("source_system = %v", body["source_system"])
	}
	if body["data_classification"] != "financial" || body["retention_class"] != "billing_7y" {
		t.Fatalf("unexpected governance defaults: %+v", body)
	}
}

func TestHTTPClientNeverFollowsRedirects(t *testing.T) {
	var redirected atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirected" {
			redirected.Add(1)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		http.Redirect(w, request, "/redirected", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := newTestHTTPClient(t, server)
	_, err := client.Publish(context.Background(), validCommerceEvent())
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("expected un-followed 307, got %v", err)
	}
	if redirected.Load() != 0 {
		t.Fatal("redirect target received a request")
	}
}

func TestHTTPClientRejectsMismatchedReceipt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = fmt.Fprintf(w, `{"receipt":{"event_id":"evt-1","tenant_id":"tenant-b","status":"ledgered","accepted_at":%q}}`, clientTestNow.Format(time.RFC3339))
	}))
	defer server.Close()
	_, err := newTestHTTPClient(t, server).Publish(context.Background(), validCommerceEvent())
	if !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("expected invalid receipt, got %v", err)
	}
}

func TestHTTPClientDoesNotCompleteAcceptedOrUnexpected2xx(t *testing.T) {
	tests := []struct {
		name   string
		status int
		state  string
		want   error
	}{
		{name: "accepted receipt", status: http.StatusAccepted, state: "accepted", want: ErrInvalidReceipt},
		{name: "unexpected 200", status: http.StatusOK, state: "ledgered", want: ErrProtocolConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := receiptServer(test.status, "tenant-a", test.state)
			defer server.Close()
			_, err := newTestHTTPClient(t, server).Publish(context.Background(), validCommerceEvent())
			if !errors.Is(err, test.want) {
				t.Fatalf("expected %v, got %v", test.want, err)
			}
		})
	}
}

func TestHTTPClientRequiresHTTPSUnlessLoopbackIsExplicit(t *testing.T) {
	tokens := tokenSourceFunc(func(context.Context, SourceBinding) (string, error) {
		return "opaque-token", nil
	})
	if _, err := NewHTTPClient(HTTPConfig{
		BaseURL: "http://127.0.0.1:8089", SourcePrefix: "snaplink-commerce",
	}, tokens, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("default loopback HTTP should fail: %v", err)
	}
	if _, err := NewHTTPClient(HTTPConfig{
		BaseURL: "http://audit.example", SourcePrefix: "snaplink-commerce", AllowInsecureLoopback: true,
	}, tokens, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("remote HTTP should fail: %v", err)
	}
}

func TestHTTPClientDoesNotExposeResponseBodyOrBearer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"client_secret":"server-secret"}`))
	}))
	defer server.Close()
	client := newTestHTTPClient(t, server)
	_, err := client.Publish(context.Background(), validCommerceEvent())
	if err == nil || strings.Contains(err.Error(), "server-secret") || strings.Contains(err.Error(), "opaque-token") {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestHTTPClientRejectsCredentialFieldsBeforeSending(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	event := validCommerceEvent()
	event.Payload["client_secret"] = "must-not-leave-process"
	_, err := newTestHTTPClient(t, server).Publish(context.Background(), event)
	if !errors.Is(err, ErrInvalidEvent) || requests.Load() != 0 {
		t.Fatalf("expected local rejection, err=%v requests=%d", err, requests.Load())
	}
}

func newTestHTTPClient(t *testing.T, server *httptest.Server) *HTTPClient {
	t.Helper()
	tokens := tokenSourceFunc(func(context.Context, SourceBinding) (string, error) {
		return "opaque-token", nil
	})
	client, err := NewHTTPClient(HTTPConfig{
		BaseURL: server.URL, SourcePrefix: "snaplink-commerce", AllowInsecureLoopback: true,
	}, tokens, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func receiptServer(status int, tenantID, receiptStatus string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"receipt":{"event_id":"evt-1","tenant_id":%q,"status":%q,"accepted_at":%q}}`,
			tenantID, receiptStatus, clientTestNow.Format(time.RFC3339))
	}))
}
