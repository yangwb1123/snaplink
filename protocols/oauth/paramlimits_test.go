package oauth

import (
	"testing"
)

func TestCheckAuthParamLengths(t *testing.T) {
	t.Run("empty params pass", func(t *testing.T) {
		if code := CheckAuthParamLengths("", "", "", "", nil); code != "" {
			t.Errorf("expected empty, got %q", code)
		}
	})

	t.Run("valid params pass", func(t *testing.T) {
		code := CheckAuthParamLengths("state-123", "https://example.com/cb", "openid profile", "nonce-abc", nil)
		if code != "" {
			t.Errorf("expected empty, got %q", code)
		}
	})

	t.Run("overly long state fails", func(t *testing.T) {
		longState := string(make([]byte, MaxStateLen+1))
		if code := CheckAuthParamLengths(longState, "", "", "", nil); code == "" {
			t.Error("expected error for long state")
		}
	})

	t.Run("overly long redirect_uri fails", func(t *testing.T) {
		longURI := "https://example.com/" + string(make([]byte, MaxRedirectURILen))
		if code := CheckAuthParamLengths("", longURI, "", "", nil); code == "" {
			t.Error("expected error for long redirect_uri")
		}
	})

	t.Run("overly long scope fails", func(t *testing.T) {
		longScope := string(make([]byte, MaxScopeLen+1))
		if code := CheckAuthParamLengths("", "", longScope, "", nil); code == "" {
			t.Error("expected error for long scope")
		}
	})

	t.Run("overly long nonce fails", func(t *testing.T) {
		longNonce := string(make([]byte, MaxNonceLen+1))
		if code := CheckAuthParamLengths("", "", "", longNonce, nil); code == "" {
			t.Error("expected error for long nonce")
		}
	})

	t.Run("overly long resource fails", func(t *testing.T) {
		longResource := "https://example.com/" + string(make([]byte, MaxResourceLen))
		if code := CheckAuthParamLengths("", "", "", "", []string{longResource}); code == "" {
			t.Error("expected error for long resource")
		}
	})

	t.Run("valid resources pass", func(t *testing.T) {
		code := CheckAuthParamLengths("", "", "", "", []string{"https://api.example.com/resource1", "https://api.example.com/resource2"})
		if code != "" {
			t.Errorf("expected empty, got %q", code)
		}
	})
}

func TestValidateAuthRequestParamLength(t *testing.T) {
	t.Run("empty value returns empty", func(t *testing.T) {
		if code := ValidateAuthRequestParamLength("state", ""); code != "" {
			t.Errorf("expected empty, got %q", code)
		}
	})

	t.Run("unknown key returns empty", func(t *testing.T) {
		if code := ValidateAuthRequestParamLength("unknown_key", "value"); code != "" {
			t.Errorf("expected empty for unknown key, got %q", code)
		}
	})

	t.Run("max state length respected", func(t *testing.T) {
		valid := string(make([]byte, MaxStateLen))
		if code := ValidateAuthRequestParamLength("state", valid); code != "" {
			t.Errorf("expected empty, got %q", code)
		}
		invalid := string(make([]byte, MaxStateLen+1))
		if code := ValidateAuthRequestParamLength("state", invalid); code == "" {
			t.Error("expected error for long state")
		}
	})
}
