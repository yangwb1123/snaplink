package webhook

import (
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
)

func TestValidateHTTPSURL(t *testing.T) {
	tests := []struct {
		url   string
		valid bool
	}{
		{"https://example.com/webhook", true},
		{"https://hooks.example.com/path?query=1", true},
		{"http://example.com/webhook", false},
		{"", false},
		{"not-a-url", false},
		{"https://", false},
		{"ftp://example.com/webhook", false},
		{"https://host:8443/path", true},
		{"  https://example.com/webhook  ", true}, // trimmed
	}

	for _, tc := range tests {
		err := validateHTTPSURL(tc.url)
		if tc.valid && err != nil {
			t.Errorf("validateHTTPSURL(%q) = %v, want nil", tc.url, err)
		}
		if !tc.valid && err == nil {
			t.Errorf("validateHTTPSURL(%q) = nil, want error", tc.url)
		}
	}
}

func TestEventSubscriptionValidate(t *testing.T) {
	t.Run("valid subscription", func(t *testing.T) {
		sub := EventSubscription{
			URL:    "https://hooks.example.com/callback",
			EventTypes: []audit.EventType{"login", "logout"},
			Secret:     "whsec_test-secret",
		}
		// Set ID to avoid validation error
		if err := sub.Validate(); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})
}
