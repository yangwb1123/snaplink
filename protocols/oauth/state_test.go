package oauth

import (
	"testing"
)

func TestEchoStateConditionally(t *testing.T) {
	t.Run("non-empty state is echoed", func(t *testing.T) {
		resp := map[string]any{}
		EchoStateConditionally(resp, "test-state")
		if resp["state"] != "test-state" {
			t.Errorf("expected 'test-state', got %v", resp["state"])
		}
	})

	t.Run("empty state is not echoed", func(t *testing.T) {
		resp := map[string]any{}
		EchoStateConditionally(resp, "")
		if _, ok := resp["state"]; ok {
			t.Error("expected no state key for empty state")
		}
	})

	t.Run("nil map does not panic", func(t *testing.T) {
		EchoStateConditionally(nil, "test-state")
	})
}

func TestEchoStateError(t *testing.T) {
	t.Run("with state", func(t *testing.T) {
		body := EchoStateError("test-state")
		if body["state"] != "test-state" {
			t.Errorf("expected 'test-state', got %v", body["state"])
		}
		if body["error"] != "access_denied" {
			t.Errorf("expected 'access_denied', got %v", body["error"])
		}
	})

	t.Run("without state", func(t *testing.T) {
		body := EchoStateError("")
		if _, ok := body["state"]; ok {
			t.Error("expected no state key")
		}
		if body["error"] != "access_denied" {
			t.Errorf("expected 'access_denied', got %v", body["error"])
		}
	})
}

func TestEchoStateRedirect(t *testing.T) {
	t.Run("with state appends to URL without query", func(t *testing.T) {
		url := EchoStateRedirect("https://example.com/cb", "test-state")
		if url != "https://example.com/cb?state=test-state" {
			t.Errorf("unexpected URL: %q", url)
		}
	})

	t.Run("with state appends to URL with existing query", func(t *testing.T) {
		url := EchoStateRedirect("https://example.com/cb?code=abc", "test-state")
		if url != "https://example.com/cb?code=abc&state=test-state" {
			t.Errorf("unexpected URL: %q", url)
		}
	})

	t.Run("empty state returns base URL unchanged", func(t *testing.T) {
		url := EchoStateRedirect("https://example.com/cb", "")
		if url != "https://example.com/cb" {
			t.Errorf("unexpected URL: %q", url)
		}
	})

	t.Run("with state and fragment in URL", func(t *testing.T) {
		url := EchoStateRedirect("https://example.com/cb#fragment", "s")
		// State should be added before fragment
		if url != "https://example.com/cb?state=s#fragment" {
			t.Errorf("unexpected URL: %q", url)
		}
	})

	t.Run("state is query escaped", func(t *testing.T) {
		url := EchoStateRedirect("https://example.com/cb", "a b&c/+")
		if url != "https://example.com/cb?state=a+b%26c%2F%2B" {
			t.Errorf("unexpected URL: %q", url)
		}
	})

	t.Run("existing state is replaced", func(t *testing.T) {
		url := EchoStateRedirect("https://example.com/cb?code=abc&state=old#fragment", "new value")
		if url != "https://example.com/cb?code=abc&state=new+value#fragment" {
			t.Errorf("unexpected URL: %q", url)
		}
	})
}
