package snapshot_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/interfaces/snapshot"
	"github.com/snaplink/sso/interfaces/sso"
)

// errUserBackendDown simulates a transient backend failure (connection
// reset, timeout) — NOT the canonical "no such user" sentinel.
var errUserBackendDown = errors.New("user backend: connection reset")

// flakyUserProvider implements sso.UserProvider. GetByID fails with a
// non-ErrNoSuchUser error for FailID; every other method records whether
// it was invoked so the test can prove CreateOrUpdate never ran.
type flakyUserProvider struct {
	FailID          string
	createOrUpdated []string
}

func (f *flakyUserProvider) GetByID(_ context.Context, id string) (*sso.User, error) {
	if id == f.FailID {
		return nil, errUserBackendDown
	}
	return nil, sso.ErrNoSuchUser
}

func (f *flakyUserProvider) GetByExternalID(_ context.Context, _, _ string) (*sso.User, error) {
	return nil, sso.ErrNoSuchUser
}

func (f *flakyUserProvider) CreateOrUpdate(_ context.Context, u *sso.User) error {
	f.createOrUpdated = append(f.createOrUpdated, u.ID)
	return nil
}

func (f *flakyUserProvider) List(_ context.Context) ([]*sso.User, error) {
	return nil, nil
}

func (f *flakyUserProvider) Delete(_ context.Context, _ string) error {
	return nil
}

// TestRestore_Merge_UserLookupTransientErrorAborts proves a transient
// GetByID failure (anything other than sso.ErrNoSuchUser) during a
// ModeMerge restore is propagated as a hard error and does NOT fall
// through to CreateOrUpdate. Before the fix, mergeUser treated ANY
// non-nil GetByID error identically to "user does not exist" and
// proceeded to CreateOrUpdate — silently overwriting a live user's data
// with the snapshot's copy on a mere backend hiccup, which breaks
// ModeMerge's documented contract of leaving existing records untouched.
func TestRestore_Merge_UserLookupTransientErrorAborts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fake := &flakyUserProvider{FailID: "u1"}
	r := &snapshot.Restorer{Users: fake}

	snap := &snapshot.Snapshot{
		SchemaVersion:   snapshot.SchemaVersion,
		SnapshotID:      "snap-1",
		SourceNamespace: "sso-server",
		Resources: snapshot.Resources{
			Users: []*sso.User{{ID: "u1", Email: "u1@example"}},
		},
	}

	_, err := r.Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge})
	if err == nil {
		t.Fatal("want error propagated from transient GetByID failure, got nil")
	}
	if !errors.Is(err, errUserBackendDown) {
		t.Errorf("error chain missing the transient backend error: %v", err)
	}
	if len(fake.createOrUpdated) != 0 {
		t.Errorf("CreateOrUpdate called on transient lookup error: %v (existing user data would have been clobbered)", fake.createOrUpdated)
	}
}

// TestRestore_Overwrite_UserLookupTransientErrorAborts is the
// ModeOverwrite counterpart — the report's Inserted/Updated bookkeeping
// must not be miscounted (or corrupted) on the back of an unresolved
// existence check either.
func TestRestore_Overwrite_UserLookupTransientErrorAborts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fake := &flakyUserProvider{FailID: "u1"}
	r := &snapshot.Restorer{Users: fake}

	snap := &snapshot.Snapshot{
		SchemaVersion:   snapshot.SchemaVersion,
		SnapshotID:      "snap-1",
		SourceNamespace: "sso-server",
		Resources: snapshot.Resources{
			Users: []*sso.User{{ID: "u1", Email: "u1@example"}},
		},
	}

	_, err := r.Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeOverwrite})
	if err == nil {
		t.Fatal("want error propagated from transient GetByID failure, got nil")
	}
	if !errors.Is(err, errUserBackendDown) {
		t.Errorf("error chain missing the transient backend error: %v", err)
	}
	if len(fake.createOrUpdated) != 0 {
		t.Errorf("CreateOrUpdate called on transient lookup error: %v", fake.createOrUpdated)
	}
}
