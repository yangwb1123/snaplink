package auditgovernance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type platformTokenFunc func(context.Context) (string, error)

func (function platformTokenFunc) PlatformToken(ctx context.Context) (string, error) {
	return function(ctx)
}

func TestControlClientUsesPlatformTokenTenantQueryAndBoundedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer platform-token" {
			t.Error("missing platform bearer")
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/v1/tenants":
			_, _ = writer.Write([]byte(`{"items":[{"id":"tenant-a","name":"Tenant A","active":true}],"count":1}`))
		case "/api/v1/sources":
			if request.URL.Query().Get("tenant_id") != "tenant-a" {
				t.Errorf("tenant query=%q", request.URL.RawQuery)
			}
			_, _ = writer.Write([]byte(`{"items":[],"count":0}`))
		case "/api/v1/schemas":
			if request.URL.Query().Get("tenant_id") != "tenant-a" {
				t.Errorf("tenant query=%q", request.URL.RawQuery)
			}
			_, _ = writer.Write([]byte(`{"items":[],"count":0}`))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := newControlTestClient(t, server)
	tenants, err := client.ListTenants(t.Context())
	if err != nil || len(tenants) != 1 || tenants[0].ID != "tenant-a" {
		t.Fatalf("tenants=%+v error=%v", tenants, err)
	}
	if _, err := client.ListSources(t.Context(), "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListSchemas(t.Context(), "tenant-a"); err != nil {
		t.Fatal(err)
	}
}

func TestControlClientDoesNotFollowRedirectOrExposeResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirected" {
			t.Fatal("redirect was followed")
		}
		writer.Header().Set("Location", "/redirected")
		writer.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = writer.Write([]byte(`{"client_secret":"remote-secret"}`))
	}))
	defer server.Close()
	_, err := newControlTestClient(t, server).ListTenants(t.Context())
	var statusErr *ControlStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("error=%v", err)
	}
	if strings.Contains(fmt.Sprint(err), "remote-secret") || strings.Contains(fmt.Sprint(err), "platform-token") {
		t.Fatalf("unsafe error=%v", err)
	}
}

func TestControlClientRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"items":["` + strings.Repeat("x", 1024) + `"]}`))
	}))
	defer server.Close()
	client, err := NewControlClient(ControlConfig{
		BaseURL: server.URL, MaxBodyBytes: 64, AllowInsecureLoopback: true,
	}, platformTokenFunc(func(context.Context) (string, error) { return "platform-token", nil }), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListTenants(t.Context()); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("error=%v", err)
	}
}

func TestControlClientSetsExactRetentionPolicy(t *testing.T) {
	want := RetentionPolicyRecord{
		TenantID: "tenant-a", HotDays: 7, WarmDays: 30, ArchiveDays: 365,
		RetentionClass: "commercial_365d",
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut || request.URL.Path != "/api/v1/policies/retention" {
			t.Errorf("request=%s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer platform-token" {
			t.Error("missing platform bearer")
		}
		var received RetentionPolicyRecord
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil || received != want {
			t.Errorf("policy=%+v error=%v", received, err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(want)
	}))
	defer server.Close()
	applied, err := newControlTestClient(t, server).SetRetentionPolicy(t.Context(), want)
	if err != nil || applied != want {
		t.Fatalf("applied=%+v error=%v", applied, err)
	}
}

func TestControlClientRejectsInvalidOrMismatchedRetentionPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"tenant_id":"other","hot_days":1,"warm_days":2,"archive_days":3,"retention_class":"commercial"}`))
	}))
	defer server.Close()
	client := newControlTestClient(t, server)
	invalid := RetentionPolicyRecord{TenantID: "tenant-a", HotDays: 2, WarmDays: 1, ArchiveDays: 3, RetentionClass: "commercial"}
	if _, err := client.SetRetentionPolicy(t.Context(), invalid); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid error=%v", err)
	}
	valid := RetentionPolicyRecord{TenantID: "tenant-a", HotDays: 1, WarmDays: 2, ArchiveDays: 3, RetentionClass: "commercial"}
	if _, err := client.SetRetentionPolicy(t.Context(), valid); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("mismatch error=%v", err)
	}
}

func newControlTestClient(t *testing.T, server *httptest.Server) *ControlClient {
	t.Helper()
	client, err := NewControlClient(ControlConfig{
		BaseURL: server.URL, AllowInsecureLoopback: true,
	}, platformTokenFunc(func(context.Context) (string, error) { return "platform-token", nil }), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client
}
