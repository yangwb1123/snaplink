package webhook_test

import (
	"errors"
	"testing"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/lifecycle/webhook"
)

func TestEventSubscription_Matches(t *testing.T) {
	t.Parallel()
	sub := webhook.EventSubscription{
		EventTypes: []audit.EventType{audit.EventLogin, audit.EventLogout},
	}
	if !sub.Matches(audit.EventLogin) {
		t.Error("expected match on subscribed type")
	}
	if sub.Matches(audit.EventTokenIssued) {
		t.Error("expected no match on unsubscribed type")
	}
}

func TestEventSubscription_Matches_DisabledNeverMatches(t *testing.T) {
	t.Parallel()
	sub := webhook.EventSubscription{
		EventTypes: []audit.EventType{audit.EventLogin},
		Disabled:   true,
	}
	if sub.Matches(audit.EventLogin) {
		t.Error("a disabled subscription must never match")
	}
}

func TestEventSubscription_Matches_EmptyTypesNeverMatches(t *testing.T) {
	t.Parallel()
	sub := webhook.EventSubscription{}
	if sub.Matches(audit.EventLogin) {
		t.Error("a subscription with no EventTypes must never match — no implicit wildcard")
	}
}

func TestEventSubscription_Validate(t *testing.T) {
	t.Parallel()
	base := webhook.EventSubscription{
		URL:        "https://example.com/hook",
		EventTypes: []audit.EventType{audit.EventLogin},
		Secret:     "s3cr3t",
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("expected valid subscription, got %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(s webhook.EventSubscription) webhook.EventSubscription
		wantErr error
	}{
		{"no event types", func(s webhook.EventSubscription) webhook.EventSubscription {
			s.EventTypes = nil
			return s
		}, webhook.ErrNoEventTypes},
		{"no secret", func(s webhook.EventSubscription) webhook.EventSubscription {
			s.Secret = ""
			return s
		}, webhook.ErrSecretRequired},
		{"http not https", func(s webhook.EventSubscription) webhook.EventSubscription {
			s.URL = "http://example.com/hook"
			return s
		}, webhook.ErrInvalidURL},
		{"no host", func(s webhook.EventSubscription) webhook.EventSubscription {
			s.URL = "https:///hook"
			return s
		}, webhook.ErrInvalidURL},
		{"garbage url", func(s webhook.EventSubscription) webhook.EventSubscription {
			s.URL = "://not a url"
			return s
		}, webhook.ErrInvalidURL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.mutate(base).Validate()
			if !errors.Is(got, tc.wantErr) {
				t.Errorf("Validate() = %v, want %v", got, tc.wantErr)
			}
		})
	}
}
