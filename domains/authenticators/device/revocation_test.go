package device

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

type revocationSessions struct {
	list        []*core.Session
	listErr     error
	destroyFail map[string]bool
}

func (s *revocationSessions) Create(context.Context, string) (*core.Session, error) {
	return nil, errors.New("unused")
}
func (s *revocationSessions) Get(context.Context, string) (*core.Session, error) {
	return nil, errors.New("unused")
}
func (s *revocationSessions) Destroy(_ context.Context, id string) error {
	if s.destroyFail[id] {
		return errors.New("destroy failed")
	}
	return nil
}
func (s *revocationSessions) Refresh(context.Context, string) (*core.Session, error) {
	return nil, errors.New("unused")
}
func (s *revocationSessions) ListByUser(context.Context, string) ([]*core.Session, error) {
	return s.list, s.listErr
}
func (s *revocationSessions) ListAll(context.Context) ([]*core.Session, error) {
	return s.list, s.listErr
}

func TestRevokeSessionsReportsEveryOutcome(t *testing.T) {
	sessions := &revocationSessions{
		list: []*core.Session{
			{ID: "ok", DeviceID: "device-1"},
			{ID: "failed", DeviceID: "device-1"},
			{ID: "other", DeviceID: "device-2"},
		},
		destroyFail: map[string]bool{"failed": true},
	}
	got := RevokeSessions(t.Context(), sessions, "user-1", "device-1", "")
	if len(got) != 2 {
		t.Fatalf("results = %#v, want two matching sessions", got)
	}
	if got[0].Status != MutationRevoked || got[1].Status != MutationFailed {
		t.Fatalf("results = %#v, want revoked then failed", got)
	}
	result := MutationResult{DeviceID: "device-1", DeviceStatus: MutationDeleted, Sessions: got}
	if result.Succeeded() {
		t.Fatal("a failed session must make the device mutation partial")
	}
}

func TestRevokeSessionsReportsUnavailableManagerAndListFailure(t *testing.T) {
	got := RevokeSessions(t.Context(), nil, "user-1", "device-1", "")
	if len(got) != 1 || got[0].Error != "session_manager_unavailable" {
		t.Fatalf("nil manager result = %#v", got)
	}
	got = RevokeSessions(t.Context(), &revocationSessions{listErr: errors.New("down")}, "user-1", "device-1", "")
	if len(got) != 1 || got[0].Error != "session_list_failed" {
		t.Fatalf("list failure result = %#v", got)
	}
}
