package grpcadmin

import (
	"context"
	"testing"

	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/platform/audit"
	"google.golang.org/grpc/codes"
)

// TestUserAdminService_NilDepsPreconditionFails proves every RPC returns
// FailedPrecondition (users) or Unimplemented (sessions) rather than
// panicking when a dependency is unwired.
func TestUserAdminService_NilDepsPreconditionFails(t *testing.T) {
	t.Parallel()
	svc := NewUserAdminService(nil, nil, nil)
	ctx := context.Background()

	_, err := svc.List(ctx, &adminv1.ListUsersRequest{})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Get(ctx, &adminv1.GetUserRequest{Id: "x"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Create(ctx, &adminv1.CreateUserRequest{User: &adminv1.User{Id: "x"}})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Update(ctx, &adminv1.UpdateUserRequest{User: &adminv1.User{Id: "x"}})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Delete(ctx, &adminv1.DeleteUserRequest{Id: "x"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.ListUserSessions(ctx, &adminv1.ListUserSessionsRequest{Id: "x"})
	requireCode(t, err, codes.Unimplemented)
}

// TestUserAdminService_InvalidArgument covers the guard clauses that run
// before the store is touched.
func TestUserAdminService_InvalidArgument(t *testing.T) {
	t.Parallel()
	users := defaultimpl.NewMemoryUserProvider()
	svc := NewUserAdminService(users, nil, nil)
	ctx := context.Background()

	_, err := svc.Get(ctx, &adminv1.GetUserRequest{})
	requireCode(t, err, codes.InvalidArgument)
	_, err = svc.Create(ctx, &adminv1.CreateUserRequest{})
	requireCode(t, err, codes.InvalidArgument)
	_, err = svc.Update(ctx, &adminv1.UpdateUserRequest{User: &adminv1.User{}})
	requireCode(t, err, codes.InvalidArgument)
	_, err = svc.Delete(ctx, &adminv1.DeleteUserRequest{})
	requireCode(t, err, codes.InvalidArgument)
}

// TestUserAdminService_CRUD drives Create/Get/List/Update/Delete directly
// and proves Create rejects an existing ID (unlike the underlying
// CreateOrUpdate store method, which is an upsert) while Update rejects a
// missing one.
func TestUserAdminService_CRUD(t *testing.T) {
	t.Parallel()
	users := defaultimpl.NewMemoryUserProvider()
	sink := audit.NewMemorySink(20)
	rec := audit.New(sink)
	svc := NewUserAdminService(users, nil, rec)
	ctx := context.Background()

	created, err := svc.Create(ctx, &adminv1.CreateUserRequest{
		User: &adminv1.User{Id: "alice", Provider: "password", ExternalId: "ext-1"},
	})
	requireOK(t, err, "Create")
	if created.User.Id != "alice" {
		t.Errorf("Create response = %+v", created.User)
	}

	_, err = svc.Create(ctx, &adminv1.CreateUserRequest{User: &adminv1.User{Id: "alice"}})
	requireCode(t, err, codes.AlreadyExists)

	got, err := svc.Get(ctx, &adminv1.GetUserRequest{Id: "alice"})
	requireOK(t, err, "Get")
	if got.User.ExternalId != "ext-1" {
		t.Errorf("Get ExternalId = %q", got.User.ExternalId)
	}

	_, err = svc.Get(ctx, &adminv1.GetUserRequest{Id: "missing"})
	requireCode(t, err, codes.NotFound)

	list, err := svc.List(ctx, &adminv1.ListUsersRequest{})
	requireOK(t, err, "List")
	if len(list.Users) != 1 {
		t.Errorf("List len = %d", len(list.Users))
	}

	_, err = svc.Update(ctx, &adminv1.UpdateUserRequest{User: &adminv1.User{Id: "missing"}})
	requireCode(t, err, codes.NotFound)

	_, err = svc.Update(ctx, &adminv1.UpdateUserRequest{User: &adminv1.User{Id: "alice", ExternalId: "ext-2"}})
	requireOK(t, err, "Update")
	got, _ = svc.Get(ctx, &adminv1.GetUserRequest{Id: "alice"})
	if got.User.ExternalId != "ext-2" {
		t.Errorf("after Update ExternalId=%q", got.User.ExternalId)
	}

	_, err = svc.Delete(ctx, &adminv1.DeleteUserRequest{Id: "alice"})
	requireOK(t, err, "Delete")
	_, err = svc.Get(ctx, &adminv1.GetUserRequest{Id: "alice"})
	requireCode(t, err, codes.NotFound)

	events, err := sink.Query(ctx, audit.Query{})
	requireOK(t, err, "sink.Query")
	if len(events) != 3 { // Create + Update + Delete succeeded; the duplicate Create and missing Update never reach recordAdmin
		t.Errorf("expected 3 audit events (create/update/delete), got %d", len(events))
	}
}

// TestUserAdminService_RedactsCredentialAttributes is the security-relevant
// case called out explicitly: password_hash / password_hash_format /
// seeded_password must never leak through Get or List, even though they are
// legitimately present in the underlying store (written by the password
// authenticator, not by this RPC).
func TestUserAdminService_RedactsCredentialAttributes(t *testing.T) {
	t.Parallel()
	users := defaultimpl.NewMemoryUserProvider()
	svc := NewUserAdminService(users, nil, nil)
	ctx := context.Background()

	_, err := svc.Create(ctx, &adminv1.CreateUserRequest{
		User: &adminv1.User{
			Id:       "bob",
			Provider: "password",
			Attributes: map[string]string{
				"password_hash":        "$2b$10$abcdefghijklmnopqrstuv",
				"password_hash_format": "bcrypt",
				"seeded_password":      "true",
				"display_name":         "Bob Example",
			},
		},
	})
	requireOK(t, err, "Create")

	got, err := svc.Get(ctx, &adminv1.GetUserRequest{Id: "bob"})
	requireOK(t, err, "Get")
	assertNoCredentialAttrs(t, got.User.Attributes)
	if got.User.Attributes["display_name"] != "Bob Example" {
		t.Errorf("expected display_name to survive redaction, got %+v", got.User.Attributes)
	}

	list, err := svc.List(ctx, &adminv1.ListUsersRequest{})
	requireOK(t, err, "List")
	if len(list.Users) != 1 {
		t.Fatalf("List len = %d", len(list.Users))
	}
	assertNoCredentialAttrs(t, list.Users[0].Attributes)

	// The underlying store must still hold the raw attributes: redaction is
	// a response-serialization concern, not a storage-time mutation — the
	// password authenticator needs password_hash to keep working.
	raw, err := users.GetByID(ctx, "bob")
	requireOK(t, err, "store.GetByID")
	if raw.Attributes["password_hash"] == "" {
		t.Error("expected the underlying store to retain password_hash; redaction must not mutate storage")
	}
}

func assertNoCredentialAttrs(t *testing.T, attrs map[string]string) {
	t.Helper()
	for _, k := range []string{"password_hash", "password_hash_format", "seeded_password"} {
		if _, present := attrs[k]; present {
			t.Errorf("credential attribute %q leaked into the admin response: %+v", k, attrs)
		}
	}
}

// TestUserAdminService_ListUserSessions proves the happy path once a real
// SessionManager is wired, and that a lookup for a user with no sessions
// returns an empty (not nil-erroring) list.
func TestUserAdminService_ListUserSessions(t *testing.T) {
	t.Parallel()
	users := defaultimpl.NewMemoryUserProvider()
	sessions := defaultimpl.NewMemorySessionManager()
	svc := NewUserAdminService(users, sessions, nil)
	ctx := context.Background()

	_, err := sessions.Create(ctx, "carol")
	requireOK(t, err, "sessions.Create")

	resp, err := svc.ListUserSessions(ctx, &adminv1.ListUserSessionsRequest{Id: "carol"})
	requireOK(t, err, "ListUserSessions")
	if len(resp.Sessions) != 1 || resp.Sessions[0].UserId != "carol" {
		t.Errorf("ListUserSessions = %+v", resp.Sessions)
	}

	empty, err := svc.ListUserSessions(ctx, &adminv1.ListUserSessionsRequest{Id: "nobody"})
	requireOK(t, err, "ListUserSessions for unknown user")
	if len(empty.Sessions) != 0 {
		t.Errorf("expected empty session list for unknown user, got %+v", empty.Sessions)
	}

	_, err = svc.ListUserSessions(ctx, &adminv1.ListUserSessionsRequest{})
	requireCode(t, err, codes.InvalidArgument)
}
