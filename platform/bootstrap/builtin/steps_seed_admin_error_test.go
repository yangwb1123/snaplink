package builtin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/bootstrap/builtin"
)

// errAdminLookupDown simulates a transient backend failure (connection
// reset, timeout) — NOT the canonical "no such user" sentinel.
var errAdminLookupDown = errors.New("user backend: connection reset")

// flakyAdminUserProvider implements sso.UserProvider. GetByID(AdminUserID)
// fails with a transient, non-ErrNoSuchUser error; every other lookup
// reports absent. CreateOrUpdate calls are recorded so a test can prove
// they never fired.
type flakyAdminUserProvider struct {
	AdminUserID     string
	createOrUpdated []*sso.User
}

func (f *flakyAdminUserProvider) GetByID(_ context.Context, id string) (*sso.User, error) {
	if id == f.AdminUserID {
		return nil, errAdminLookupDown
	}
	return nil, sso.ErrNoSuchUser
}

func (f *flakyAdminUserProvider) GetByExternalID(_ context.Context, _, _ string) (*sso.User, error) {
	return nil, sso.ErrNoSuchUser
}

func (f *flakyAdminUserProvider) CreateOrUpdate(_ context.Context, u *sso.User) error {
	f.createOrUpdated = append(f.createOrUpdated, u)
	return nil
}

func (f *flakyAdminUserProvider) List(_ context.Context) ([]*sso.User, error) { return nil, nil }

func (f *flakyAdminUserProvider) Delete(_ context.Context, _ string) error { return nil }

// TestSteps_SeedAdminUser_TransientLookupErrorAborts proves a transient
// GetByID failure during seed_admin_user is surfaced as a hard error and
// does NOT fall through to CreateOrUpdate. Before the fix, the step
// treated ANY non-nil GetByID error identically to "admin user absent"
// and proceeded to regenerate a brand-new random password and
// CreateOrUpdate a bare user struct over the row. Because CreateOrUpdate
// is a full-record replace (not a merge) on every UserProvider backend,
// that would silently wipe a live admin account's
// Email/Username/Attributes (including any password hash set after
// seeding) on nothing more than a boot-time backend hiccup — a much
// higher-stakes version of the same "any lookup error means absent"
// mistake, since this path holds the sole admin account's credentials.
func TestSteps_SeedAdminUser_TransientLookupErrorAborts(t *testing.T) {
	t.Parallel()
	fake := &flakyAdminUserProvider{AdminUserID: "admin"}
	seed := &builtin.AdminSeed{
		Permissions: permissions.NewMemoryProvider(),
		Users:       fake,
	}
	steps := builtin.Steps(seed)
	if len(steps) != 6 {
		t.Fatalf("Steps returned %d, want 6", len(steps))
	}
	adminUserStep := steps[1] // seed_admin_user, version 2
	if adminUserStep.Name() != "seed_admin_user" {
		t.Fatalf("steps[1].Name() = %q, want seed_admin_user", adminUserStep.Name())
	}

	err := adminUserStep.Run(context.Background())
	if err == nil {
		t.Fatal("want error propagated from transient GetByID failure, got nil")
	}
	if !errors.Is(err, errAdminLookupDown) {
		t.Errorf("error chain missing the transient backend error: %v", err)
	}
	if len(fake.createOrUpdated) != 0 {
		t.Errorf("CreateOrUpdate called on transient lookup error: %+v (live admin user would have been clobbered)", fake.createOrUpdated)
	}
}
