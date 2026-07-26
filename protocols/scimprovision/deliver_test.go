package scimprovision

import (
	"testing"

	"github.com/snaplink/sso/platform/audit"
)

func TestSubjectID(t *testing.T) {
	t.Run("from metadata subject", func(t *testing.T) {
		ev := audit.Event{Metadata: map[string]string{"subject": "user-1"}}
		if id := subjectID(ev); id != "user-1" {
			t.Errorf("expected 'user-1', got %q", id)
		}
	})

	t.Run("from metadata target_user", func(t *testing.T) {
		ev := audit.Event{Metadata: map[string]string{"target_user": "user-2"}}
		if id := subjectID(ev); id != "user-2" {
			t.Errorf("expected 'user-2', got %q", id)
		}
	})

	t.Run("subject takes priority over target_user", func(t *testing.T) {
		ev := audit.Event{Metadata: map[string]string{"subject": "user-1", "target_user": "user-2"}}
		if id := subjectID(ev); id != "user-1" {
			t.Errorf("expected 'user-1', got %q", id)
		}
	})

	t.Run("from reason prefix", func(t *testing.T) {
		ev := audit.Event{Reason: "target=user-3"}
		if id := subjectID(ev); id != "user-3" {
			t.Errorf("expected 'user-3', got %q", id)
		}
	})

	t.Run("empty returns empty", func(t *testing.T) {
		if id := subjectID(audit.Event{}); id != "" {
			t.Errorf("expected empty, got %q", id)
		}
	})
}

func TestGroupSubject(t *testing.T) {
	t.Run("from metadata subject", func(t *testing.T) {
		ev := audit.Event{Metadata: map[string]string{"subject": "role-admin"}}
		_, roleCode, ok := groupSubject(ev)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if roleCode != "role-admin" {
			t.Errorf("expected 'role-admin', got %q", roleCode)
		}
	})

	t.Run("from reason with clientID/roleCode", func(t *testing.T) {
		ev := audit.Event{Reason: "target=client-1/role-admin"}
		clientID, roleCode, ok := groupSubject(ev)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if clientID != "client-1" {
			t.Errorf("expected 'client-1', got %q", clientID)
		}
		if roleCode != "role-admin" {
			t.Errorf("expected 'role-admin', got %q", roleCode)
		}
	})

	t.Run("from reason without clientID", func(t *testing.T) {
		ev := audit.Event{Reason: "target=role-admin"}
		clientID, roleCode, ok := groupSubject(ev)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if clientID != "" {
			t.Errorf("expected empty clientID, got %q", clientID)
		}
		if roleCode != "role-admin" {
			t.Errorf("expected 'role-admin', got %q", roleCode)
		}
	})

	t.Run("empty returns false", func(t *testing.T) {
		_, _, ok := groupSubject(audit.Event{})
		if ok {
			t.Error("expected ok=false")
		}
	})
}
