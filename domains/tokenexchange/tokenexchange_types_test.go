package tokenexchange

import (
	"testing"
)

func TestHopFields(t *testing.T) {
	h := Hop{
		SubjectID:         "user-1",
		ActorSubject:      "admin-1",
		ClientID:          "client-1",
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		Scopes:            []string{"openid", "profile"},
		Resources:         []string{"https://api.example.com"},
	}

	if h.SubjectID != "user-1" {
		t.Errorf("expected 'user-1', got %q", h.SubjectID)
	}
	if h.ActorSubject != "admin-1" {
		t.Errorf("expected 'admin-1', got %q", h.ActorSubject)
	}
	if len(h.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(h.Scopes))
	}
	if len(h.Resources) != 1 {
		t.Errorf("expected 1 resource, got %d", len(h.Resources))
	}
}

func TestHopZeroValue(t *testing.T) {
	var h Hop
	if h.SubjectID != "" {
		t.Errorf("expected empty SubjectID, got %q", h.SubjectID)
	}
	if len(h.Scopes) != 0 {
		t.Errorf("expected empty Scopes, got %v", h.Scopes)
	}
}

func TestRuleFields(t *testing.T) {
	r := Rule{
		Name:          "allow-user-delegation",
		SubjectID:     "user-1",
		ActorSubject:  "admin-1",
		ClientID:      "client-1",
	}

	if r.Name != "allow-user-delegation" {
		t.Errorf("expected 'allow-user-delegation', got %q", r.Name)
	}
	if r.SubjectID != "user-1" {
		t.Errorf("expected 'user-1', got %q", r.SubjectID)
	}
	if r.ActorSubject != "admin-1" {
		t.Errorf("expected 'admin-1', got %q", r.ActorSubject)
	}
}

func TestRuleZeroValue(t *testing.T) {
	var r Rule
	if r.SubjectID != "" {
		t.Errorf("expected empty SubjectID, got %q", r.SubjectID)
	}
	if r.Deny {
		t.Error("expected Deny=false")
	}
}
