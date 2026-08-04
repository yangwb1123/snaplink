package quotaprojection

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestHTTPClientPublishesExactTenantBindingAndProjection(t *testing.T) {
	projection := testProjection(7)
	event := testEntitlementEvent(6)
	var received projectionRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != core.PathTenantQuotaProjection {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer machine-token" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tenant_id":"tenant-a","revision":7,"applied":true}`))
	}))
	defer server.Close()

	client := newTestHTTPClient(t, server.URL, AuthorizerFunc(func(
		context.Context, string,
	) (Authorization, error) {
		return Authorization{
			TenantID: "tenant-a", SourceSystem: "snaplink-billing:tenant-a", BearerToken: "machine-token",
		}, nil
	}))
	receipt, err := client.Publish(context.Background(), event, projection)
	if err != nil || receipt.TenantID != "tenant-a" || receipt.Revision != 7 || !receipt.Applied {
		t.Fatalf("Publish() = %+v, %v", receipt, err)
	}
	if received.TenantID != "tenant-a" || received.SourceSystem != "snaplink-billing:tenant-a" ||
		received.Projection != projection {
		t.Fatalf("request = %+v", received)
	}
}

func TestHTTPClientRejectsUnboundAuthorizationBeforeNetwork(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer server.Close()
	client := newTestHTTPClient(t, server.URL, AuthorizerFunc(func(
		context.Context, string,
	) (Authorization, error) {
		return Authorization{TenantID: "tenant-b", SourceSystem: "source", BearerToken: "token"}, nil
	}))
	_, err := client.Publish(context.Background(), testEntitlementEvent(1), testProjection(1))
	if !errors.Is(err, ErrTokenUnavailable) || calls != 0 {
		t.Fatalf("Publish() error = %v, calls = %d", err, calls)
	}
}

func TestHTTPClientClassifiesAuthorizationWithoutExposingBodyOrToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("machine-token secret-response"))
	}))
	defer server.Close()
	client := newTestHTTPClient(t, server.URL, fixedAuthorizer())
	_, err := client.Publish(context.Background(), testEntitlementEvent(1), testProjection(1))
	if !errors.Is(err, ErrAuthorizationRejected) {
		t.Fatalf("Publish() error = %v", err)
	}
	if strings.Contains(err.Error(), "machine-token") || strings.Contains(err.Error(), "secret-response") {
		t.Fatalf("error leaked sensitive data: %v", err)
	}
}

func TestHTTPClientRejectsInvalidReceiptAndInsecureRemote(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tenant_id":"tenant-b","revision":1,"applied":true}`))
	}))
	defer server.Close()
	client := newTestHTTPClient(t, server.URL, fixedAuthorizer())
	if _, err := client.Publish(
		context.Background(), testEntitlementEvent(1), testProjection(1),
	); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("invalid receipt error = %v", err)
	}
	if _, err := NewHTTPClient(HTTPConfig{
		BaseURL: "http://sso.example", AllowInsecureLoopback: true,
	}, fixedAuthorizer(), nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("insecure endpoint error = %v", err)
	}
}

func newTestHTTPClient(t *testing.T, baseURL string, authorizer Authorizer) *HTTPClient {
	t.Helper()
	client, err := NewHTTPClient(HTTPConfig{
		BaseURL: baseURL, AllowInsecureLoopback: true,
	}, authorizer, nil)
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	return client
}

func fixedAuthorizer() Authorizer {
	return AuthorizerFunc(func(context.Context, string) (Authorization, error) {
		return Authorization{
			TenantID: "tenant-a", SourceSystem: "snaplink-billing:tenant-a", BearerToken: "machine-token",
		}, nil
	})
}

func testEntitlementEvent(revision uint64) *commerce.OutboxEvent {
	return &commerce.OutboxEvent{
		ID: "evt-1", TenantID: "tenant-a", Type: commerce.EventEntitlementPublished,
		AggregateVersion: revision,
	}
}

func testProjection(revision uint64) core.TenantQuotaProjection {
	return core.TenantQuotaProjection{
		Revision: revision,
		Quota:    core.TenantQuota{MaxClients: 2, ClientsLimited: true},
	}
}
