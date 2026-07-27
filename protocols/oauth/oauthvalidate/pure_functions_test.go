package oauthvalidate

import (
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestSplitScope(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		result := SplitScope("")
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("single scope", func(t *testing.T) {
		result := SplitScope("openid")
		if len(result) != 1 || result[0] != "openid" {
			t.Errorf("expected ['openid'], got %v", result)
		}
	})

	t.Run("multiple scopes", func(t *testing.T) {
		result := SplitScope("openid profile email")
		if len(result) != 3 {
			t.Errorf("expected 3 scopes, got %d: %v", len(result), result)
		}
	})

	t.Run("leading/trailing spaces", func(t *testing.T) {
		// SplitScope uses strings.Split which preserves empty strings
		result := SplitScope("  openid  profile  ")
		// Just verify no panic and the function handles it
		if result == nil {
			t.Error("expected non-nil")
		}
	})
}

func TestJoinScope(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if JoinScope(nil) != "" {
			t.Errorf("expected empty, got %q", JoinScope(nil))
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		if JoinScope([]string{}) != "" {
			t.Errorf("expected empty, got %q", JoinScope([]string{}))
		}
	})

	t.Run("multiple scopes", func(t *testing.T) {
		result := JoinScope([]string{"openid", "profile", "email"})
		if result != "openid profile email" {
			t.Errorf("expected 'openid profile email', got %q", result)
		}
	})
}

func TestIsValidResponseMode(t *testing.T) {
	valid := []string{"query", "fragment", "form_post"}
	invalid := []string{"", "invalid", "QUERY", "Fragment", "jwt"}

	for _, mode := range valid {
		if !IsValidResponseMode(mode) {
			t.Errorf("expected valid: %q", mode)
		}
	}
	for _, mode := range invalid {
		if IsValidResponseMode(mode) {
			t.Errorf("expected invalid: %q", mode)
		}
	}
}

func TestGrantedScopes(t *testing.T) {
	t.Run("nil client allowed scopes", func(t *testing.T) {
		client := &core.Client{} // empty AllowedScopes = unrestricted
		scopes, err := GrantedScopes([]string{"openid", "profile"}, client)
		if err != nil {
			t.Fatalf("GrantedScopes: %v", err)
		}
		if len(scopes) != 2 {
			t.Errorf("expected 2 scopes, got %d", len(scopes))
		}
	})

	t.Run("client restricts scopes", func(t *testing.T) {
		client := &core.Client{AllowedScopes: []string{"openid"}}
		_, err := GrantedScopes([]string{"openid", "profile"}, client)
		if err == nil {
			t.Error("expected error for scope not in allowlist")
		}
	})

	t.Run("subset allowed", func(t *testing.T) {
		client := &core.Client{AllowedScopes: []string{"openid", "profile", "email"}}
		scopes, err := GrantedScopes([]string{"openid", "email"}, client)
		if err != nil {
			t.Fatalf("GrantedScopes: %v", err)
		}
		if len(scopes) != 2 {
			t.Errorf("expected 2 scopes, got %d", len(scopes))
		}
	})

	t.Run("requested is subset of allowed", func(t *testing.T) {
		client := &core.Client{AllowedScopes: []string{"openid", "profile"}}
		scopes, err := GrantedScopes([]string{"openid"}, client)
		if err != nil {
			t.Fatalf("GrantedScopes: %v", err)
		}
		if len(scopes) != 1 || scopes[0] != "openid" {
			t.Errorf("expected ['openid'], got %v", scopes)
		}
	})
}

func TestGenerateClientID(t *testing.T) {
	id1, err := GenerateClientID()
	if err != nil {
		t.Fatalf("GenerateClientID: %v", err)
	}
	if id1 == "" {
		t.Fatal("expected non-empty ID")
	}

	id2, _ := GenerateClientID()
	if id1 == id2 {
		t.Error("expected different IDs on successive calls")
	}
}

func TestGenerateClientSecret(t *testing.T) {
	secret1, err := GenerateClientSecret()
	if err != nil {
		t.Fatalf("GenerateClientSecret: %v", err)
	}
	if secret1 == "" {
		t.Fatal("expected non-empty secret")
	}

	secret2, _ := GenerateClientSecret()
	if secret1 == secret2 {
		t.Error("expected different secrets on successive calls")
	}
}

func TestCloneRawJSON(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := CloneRawJSON(nil)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("valid JSON", func(t *testing.T) {
		input := []byte(`{"key": "value"}`)
		result := CloneRawJSON(input)
		if string(result) != string(input) {
			t.Errorf("expected %q, got %q", string(input), string(result))
		}

		// Verify independence
		result[0] = ' '
		if string(input) == string(result) {
			t.Error("clone should be independent")
		}
	})
}
