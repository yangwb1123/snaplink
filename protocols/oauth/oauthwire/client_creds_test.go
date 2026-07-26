package oauthwire

import (
	"encoding/base64"
	"net/http/httptest"
	"testing"
)

func TestBasicClientCreds(t *testing.T) {
	t.Run("valid basic auth", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/token", nil)
		r.SetBasicAuth("client-1", "secret-1")
		id, secret, ok := BasicClientCreds(r)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if id != "client-1" {
			t.Errorf("expected 'client-1', got %q", id)
		}
		if secret != "secret-1" {
			t.Errorf("expected 'secret-1', got %q", secret)
		}
	})

	t.Run("no auth header", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/token", nil)
		_, _, ok := BasicClientCreds(r)
		if ok {
			t.Error("expected ok=false for no auth header")
		}
	})

	t.Run("bearer auth not basic", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/token", nil)
		r.Header.Set("Authorization", "Bearer my-token")
		_, _, ok := BasicClientCreds(r)
		if ok {
			t.Error("expected ok=false for bearer auth")
		}
	})

	t.Run("malformed basic auth", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/token", nil)
		encoded := base64.StdEncoding.EncodeToString([]byte("no-colon"))
		r.Header.Set("Authorization", "Basic "+encoded)
		_, _, ok := BasicClientCreds(r)
		if ok {
			t.Error("expected ok=false for malformed basic auth")
		}
	})

	t.Run("empty credentials", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/token", nil)
		encoded := base64.StdEncoding.EncodeToString([]byte(":"))
		r.Header.Set("Authorization", "Basic "+encoded)
		id, secret, ok := BasicClientCreds(r)
		if !ok {
			t.Fatal("expected ok=true even with empty fields")
		}
		if id != "" {
			t.Errorf("expected empty id, got %q", id)
		}
		if secret != "" {
			t.Errorf("expected empty secret, got %q", secret)
		}
	})
}
