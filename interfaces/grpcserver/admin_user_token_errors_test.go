package grpcserver_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/grpcserver"
	"github.com/snaplink/sso/interfaces/sso"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// erroringUserProvider returns the configured error from every method.
type erroringUserProvider struct{ err error }

func (e *erroringUserProvider) GetByID(context.Context, string) (*sso.User, error) {
	return nil, e.err
}
func (e *erroringUserProvider) GetByExternalID(context.Context, string, string) (*sso.User, error) {
	return nil, e.err
}
func (e *erroringUserProvider) CreateOrUpdate(context.Context, *sso.User) error { return e.err }
func (e *erroringUserProvider) List(context.Context) ([]*sso.User, error)       { return nil, e.err }
func (e *erroringUserProvider) Delete(context.Context, string) error            { return e.err }

// notFoundUserProvider returns sso.ErrNoSuchUser on every GetByID so the
// admin Create RPC's "if exists" check resolves to "go ahead and create",
// and Update RPC's "if exists" check resolves to NotFound.
type notFoundUserProvider struct {
	erroringUserProvider
	listed []*sso.User
}

func (n *notFoundUserProvider) GetByID(context.Context, string) (*sso.User, error) {
	return nil, sso.ErrNoSuchUser
}
func (n *notFoundUserProvider) CreateOrUpdate(context.Context, *sso.User) error {
	return nil
}
func (n *notFoundUserProvider) List(context.Context) ([]*sso.User, error) { return n.listed, nil }
func (n *notFoundUserProvider) Delete(context.Context, string) error      { return nil }

// ---------- UserAdmin nil provider → FailedPrecondition ----------

func TestUserAdmin_NilUsers_FailedPrecondition(t *testing.T) {
	conn := startAdminGRPC(t, nil, nil, nil, nil, nil, nil)
	c := adminv1.NewUserAdminServiceClient(conn)
	ctx := context.Background()

	cases := []struct {
		name string
		call func() error
	}{
		{"List", func() error { _, e := c.List(ctx, &adminv1.ListUsersRequest{}); return e }},
		{"Get", func() error {
			_, e := c.Get(ctx, &adminv1.GetUserRequest{Id: "x"})
			return e
		}},
		{"Create", func() error {
			_, e := c.Create(ctx, &adminv1.CreateUserRequest{User: &adminv1.User{Id: "x"}})
			return e
		}},
		{"Update", func() error {
			_, e := c.Update(ctx, &adminv1.UpdateUserRequest{User: &adminv1.User{Id: "x"}})
			return e
		}},
		{"Delete", func() error {
			_, e := c.Delete(ctx, &adminv1.DeleteUserRequest{Id: "x"})
			return e
		}},
	}
	for _, tc := range cases {
		if got := status.Code(tc.call()); got != codes.FailedPrecondition {
			t.Errorf("%s: code = %v, want FailedPrecondition", tc.name, got)
		}
	}
}

// ListUserSessions has a separate gate: nil sessions → Unimplemented.
func TestUserAdmin_ListUserSessions_NilSessions_Unimplemented(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	conn := startAdminGRPC(t, nil, users, nil, nil, nil, nil)
	c := adminv1.NewUserAdminServiceClient(conn)

	_, err := c.ListUserSessions(context.Background(), &adminv1.ListUserSessionsRequest{Id: "x"})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("code = %v, want Unimplemented", status.Code(err))
	}
}

// ---------- UserAdmin bad args → InvalidArgument ----------

func TestUserAdmin_BadArgs_InvalidArgument(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	sessions := defaultimpl.NewMemorySessionManager()
	conn := startAdminGRPC(t, nil, users, sessions, nil, nil, nil)
	c := adminv1.NewUserAdminServiceClient(conn)
	ctx := context.Background()

	cases := []struct {
		name string
		call func() error
	}{
		{"Get-empty", func() error { _, e := c.Get(ctx, &adminv1.GetUserRequest{}); return e }},
		{"Create-nil-user", func() error {
			_, e := c.Create(ctx, &adminv1.CreateUserRequest{})
			return e
		}},
		{"Create-empty-id", func() error {
			_, e := c.Create(ctx, &adminv1.CreateUserRequest{User: &adminv1.User{}})
			return e
		}},
		{"Update-nil-user", func() error {
			_, e := c.Update(ctx, &adminv1.UpdateUserRequest{})
			return e
		}},
		{"Update-empty-id", func() error {
			_, e := c.Update(ctx, &adminv1.UpdateUserRequest{User: &adminv1.User{}})
			return e
		}},
		{"Delete-empty", func() error { _, e := c.Delete(ctx, &adminv1.DeleteUserRequest{}); return e }},
		{"ListSessions-empty", func() error {
			_, e := c.ListUserSessions(ctx, &adminv1.ListUserSessionsRequest{})
			return e
		}},
	}
	for _, tc := range cases {
		if got := status.Code(tc.call()); got != codes.InvalidArgument {
			t.Errorf("%s: code = %v, want InvalidArgument", tc.name, got)
		}
	}
}

// ---------- UserAdmin provider error → Internal ----------

func TestUserAdmin_ProviderError_Internal(t *testing.T) {
	users := &erroringUserProvider{err: errors.New("db down")}
	sessions := defaultimpl.NewMemorySessionManager()
	conn := startAdminGRPC(t, nil, users, sessions, nil, nil, nil)
	c := adminv1.NewUserAdminServiceClient(conn)
	ctx := context.Background()

	cases := []struct {
		name string
		call func() error
	}{
		{"List", func() error { _, e := c.List(ctx, &adminv1.ListUsersRequest{}); return e }},
		{"Get", func() error {
			_, e := c.Get(ctx, &adminv1.GetUserRequest{Id: "x"})
			return e
		}},
		{"Delete", func() error {
			_, e := c.Delete(ctx, &adminv1.DeleteUserRequest{Id: "x"})
			return e
		}},
	}
	for _, tc := range cases {
		if got := status.Code(tc.call()); got != codes.Internal {
			t.Errorf("%s: code = %v, want Internal", tc.name, got)
		}
	}
}

// ---------- UserAdmin sentinel mappings ----------

func TestUserAdmin_Get_NotFound(t *testing.T) {
	users := &erroringUserProvider{err: sso.ErrNoSuchUser}
	conn := startAdminGRPC(t, nil, users, nil, nil, nil, nil)
	c := adminv1.NewUserAdminServiceClient(conn)
	_, err := c.Get(context.Background(), &adminv1.GetUserRequest{Id: "ghost"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code = %v, want NotFound", status.Code(err))
	}
}

func TestUserAdmin_Update_NotFound(t *testing.T) {
	users := &notFoundUserProvider{}
	conn := startAdminGRPC(t, nil, users, nil, nil, nil, nil)
	c := adminv1.NewUserAdminServiceClient(conn)
	_, err := c.Update(context.Background(), &adminv1.UpdateUserRequest{
		User: &adminv1.User{Id: "ghost"},
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code = %v, want NotFound", status.Code(err))
	}
}

func TestUserAdmin_Update_HappyPath(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "alice", Provider: "password"})
	conn := startAdminGRPC(t, nil, users, nil, nil, nil, nil)
	c := adminv1.NewUserAdminServiceClient(conn)

	resp, err := c.Update(context.Background(), &adminv1.UpdateUserRequest{
		User: &adminv1.User{Id: "alice", Provider: "saml", ExternalId: "external-alice"},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if resp.User.Provider != "saml" || resp.User.ExternalId != "external-alice" {
		t.Errorf("Update returned %+v", resp.User)
	}
}

// ---------- TokenAdmin nil dependency → Unimplemented ----------

func TestTokenAdmin_ListSessions_NilSessions_Unimplemented(t *testing.T) {
	conn := startAdminGRPC(t, nil, nil, nil, nil, nil, nil)
	c := adminv1.NewTokenAdminServiceClient(conn)
	_, err := c.ListSessions(context.Background(), &adminv1.ListSessionsRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("code = %v, want Unimplemented", status.Code(err))
	}
}

func TestTokenAdmin_IssueTempToken_NilStore_Unimplemented(t *testing.T) {
	conn := startAdminGRPC(t, nil, nil, nil, nil, nil, nil)
	c := adminv1.NewTokenAdminServiceClient(conn)
	_, err := c.IssueTempToken(context.Background(), &adminv1.IssueTempTokenRequest{UserId: "u"})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("code = %v, want Unimplemented", status.Code(err))
	}
}

// ---------- TokenAdmin Revoke branches ----------

func TestTokenAdmin_Revoke_RequiresTokenOrSession(t *testing.T) {
	sessions := defaultimpl.NewMemorySessionManager()
	conn := startAdminGRPC(t, nil, nil, sessions, nil, nil, nil)
	c := adminv1.NewTokenAdminServiceClient(conn)

	_, err := c.Revoke(context.Background(), &adminv1.RevokeRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestTokenAdmin_Revoke_NoMatch_NotFound(t *testing.T) {
	// Empty SessionManager — Destroy returns nil but the session wasn't
	// found, so nothing actually got revoked. No issuers configured, so
	// the token path is a no-op too.
	sessions := defaultimpl.NewMemorySessionManager()
	conn := startAdminGRPC(t, nil, nil, sessions, nil, nil, nil)
	c := adminv1.NewTokenAdminServiceClient(conn)

	_, err := c.Revoke(context.Background(), &adminv1.RevokeRequest{
		Token: "bogus-token",
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code = %v, want NotFound", status.Code(err))
	}
}

func TestTokenAdmin_Revoke_SessionWithoutManager_FailedPrecondition(t *testing.T) {
	// No SessionManager wired but caller sends session_id.
	conn := startAdminGRPC(t, nil, nil, nil, nil, nil, nil)
	c := adminv1.NewTokenAdminServiceClient(conn)
	_, err := c.Revoke(context.Background(), &adminv1.RevokeRequest{SessionId: "sess-1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", status.Code(err))
	}
}

func TestTokenAdmin_Revoke_HappyPath(t *testing.T) {
	sessions := defaultimpl.NewMemorySessionManager()
	sess, _ := sessions.Create(context.Background(), "alice")
	conn := startAdminGRPC(t, nil, nil, sessions, nil, nil, nil)
	c := adminv1.NewTokenAdminServiceClient(conn)

	resp, err := c.Revoke(context.Background(), &adminv1.RevokeRequest{SessionId: sess.ID})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(resp.Revoked) == 0 {
		t.Errorf("expected revoked list to include 'session', got %v", resp.Revoked)
	}
}

// ---------- TokenAdmin IssueTempToken happy path with full claims ----------

func TestTokenAdmin_IssueTempToken_HappyPathWithClaims(t *testing.T) {
	store := authenticators.NewMemoryTempTokenStore()
	conn := startAdminGRPC(t, nil, nil, nil, nil, store, nil)
	c := adminv1.NewTokenAdminServiceClient(conn)

	resp, err := c.IssueTempToken(context.Background(), &adminv1.IssueTempTokenRequest{
		UserId:   "alice",
		ClientId: "web-app",
		Scopes:   []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatalf("IssueTempToken: %v", err)
	}
	if resp.Token == "" {
		t.Error("Token empty")
	}
	if resp.ExpiresAtUnix <= time.Now().Unix() {
		t.Errorf("ExpiresAtUnix %d not in future", resp.ExpiresAtUnix)
	}

	// The token should resolve via the store with the encoded claims.
	sub, err := store.Consume(context.Background(), resp.Token)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if sub.ID != "alice" {
		t.Errorf("Subject.ID = %q", sub.ID)
	}
	if sub.Claims["aud"] != "web-app" {
		t.Errorf("Subject.Claims[aud] = %q", sub.Claims["aud"])
	}
	if sub.Claims["scope"] != "openid profile" {
		t.Errorf("Subject.Claims[scope] = %q", sub.Claims["scope"])
	}
}

// ---------- TokenAdmin custom TTL ----------

func TestTokenAdmin_CustomTTL_AppliedToIssuedToken(t *testing.T) {
	// Construct the service with a non-default TTL via the public
	// TokenAdminConfig + wire it manually (the helper doesn't expose
	// the field).
	store := authenticators.NewMemoryTempTokenStore()
	svc := grpcserver.NewTokenAdminService(grpcserver.TokenAdminConfig{
		TempStore:    store,
		TempTokenTTL: 90 * time.Second,
	})
	resp, err := svc.IssueTempToken(context.Background(), &adminv1.IssueTempTokenRequest{
		UserId: "x",
	})
	if err != nil {
		t.Fatalf("IssueTempToken: %v", err)
	}
	exp := time.Until(time.Unix(resp.ExpiresAtUnix, 0))
	if exp < 60*time.Second || exp > 95*time.Second {
		t.Errorf("ExpiresAt window = %v, want ~90s", exp)
	}
}
