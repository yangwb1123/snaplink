package auditgovernance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestPlatformTokenSourceUsesFixedLeastPrivilegeScopeAndCaches(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		clientID, secret, ok := request.BasicAuth()
		if !ok || clientID != "provisioner-client" || secret != "provisioner-secret" {
			t.Error("unexpected client authentication")
		}
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		if request.Form.Get("scope") != PlatformProvisioningScope || request.Form.Get("resource") != "audit-control" {
			t.Errorf("unexpected token form: %v", request.Form)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"access_token": "platform-token", "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	defer server.Close()
	source, err := NewPlatformTokenSource(PlatformTokenConfig{
		TokenURL: server.URL, ClientID: "provisioner-client", ClientSecret: "provisioner-secret",
		Resource: "audit-control", AllowInsecureLoopback: true,
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		token, tokenErr := source.PlatformToken(t.Context())
		if tokenErr != nil || token != "platform-token" {
			t.Fatalf("token=%q error=%v", token, tokenErr)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("token calls=%d", calls.Load())
	}
}

func TestPlatformTokenSourceRejectsRemoteHTTPAndSecretNewlines(t *testing.T) {
	for _, config := range []PlatformTokenConfig{
		{TokenURL: "http://audit.example/token", ClientID: "client", ClientSecret: "secret", Resource: "audit"},
		{TokenURL: "https://audit.example/token", ClientID: "client", ClientSecret: "secret\n", Resource: "audit"},
	} {
		if _, err := NewPlatformTokenSource(config, nil); err == nil {
			t.Fatalf("unsafe config accepted: %+v", config)
		}
	}
}

func TestPlatformTokenSourceUsesExactRetentionScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if request.Form.Get("scope") != PlatformRetentionScope {
			t.Errorf("scope=%q", request.Form.Get("scope"))
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"access_token":"retention-token","token_type":"Bearer","expires_in":300}`))
	}))
	defer server.Close()
	source, err := NewPlatformTokenSource(PlatformTokenConfig{
		TokenURL: server.URL, ClientID: "retention-client", ClientSecret: "retention-secret",
		Resource: "audit-control", Scope: PlatformRetentionScope, AllowInsecureLoopback: true,
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if token, tokenErr := source.PlatformToken(t.Context()); tokenErr != nil || token != "retention-token" {
		t.Fatalf("token=%q error=%v", token, tokenErr)
	}
}
