package local_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/ssoclient"
	"github.com/snaplink/sso/ssoclient/local"
)

// ---------- WithSessionManager + Logout coverage ----------

func TestLocalAuth_WithSessionManager_OptionWired(t *testing.T) {
	iss := defaultimpl.NewEd25519JWTIssuer()
	sm := defaultimpl.NewMemorySessionManager(time.Hour)
	sess, _ := sm.Create(context.Background(), "u-alice")

	client := local.NewAuthClient(iss, local.WithSessionManager(sm))

	// session_id only → must be destroyed via the wired SessionManager.
	if err := client.Logout(context.Background(), &ssoclient.LogoutRequest{
		SessionID: sess.ID,
	}); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := sm.Get(context.Background(), sess.ID); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Errorf("session not destroyed: err=%v", err)
	}
}

func TestLocalAuth_Logout_SessionIDWithoutManagerIsNoop(t *testing.T) {
	// Without WithSessionManager wired, a session-only Logout request
	// should silently skip the session step (no error, no panic).
	iss := defaultimpl.NewEd25519JWTIssuer()
	client := local.NewAuthClient(iss)
	if err := client.Logout(context.Background(), &ssoclient.LogoutRequest{
		SessionID: "some-id",
	}); err != nil {
		t.Errorf("Logout with no SessionManager wired: %v", err)
	}
}

func TestLocalAuth_Logout_BothPathsAggregateErrors(t *testing.T) {
	// Bearer token revoke succeeds, session destroy succeeds — combined
	// errors.Join(nil, nil) returns nil per the documented Joined contract.
	iss := defaultimpl.NewEd25519JWTIssuer()
	sm := defaultimpl.NewMemorySessionManager(time.Hour)
	tok, _ := iss.Issue(context.Background(), &sso.Subject{ID: "u"}, nil)
	sess, _ := sm.Create(context.Background(), "u")

	client := local.NewAuthClient(iss, local.WithSessionManager(sm))
	if err := client.Logout(context.Background(), &ssoclient.LogoutRequest{
		AccessToken: tok.AccessToken,
		SessionID:   sess.ID,
	}); err != nil {
		t.Fatalf("Logout: %v", err)
	}
}

func TestLocalAuth_Logout_TokenRevokeErrorSurfaces(t *testing.T) {
	// A re-revoke of an already-revoked token surfaces an error from the
	// issuer. Logout must propagate it.
	iss := defaultimpl.NewEd25519JWTIssuer()
	tok, _ := iss.Issue(context.Background(), &sso.Subject{ID: "u"}, nil)
	client := local.NewAuthClient(iss)

	if err := client.Logout(context.Background(), &ssoclient.LogoutRequest{
		AccessToken: tok.AccessToken,
	}); err != nil {
		t.Fatalf("first Logout: %v", err)
	}
	// Second revoke should error — the Ed25519 issuer rejects unknown tokens.
	if err := client.Logout(context.Background(), &ssoclient.LogoutRequest{
		AccessToken: tok.AccessToken,
	}); err == nil {
		t.Error("re-revoke of already-revoked token should surface error")
	}
}

func TestLocalAuth_Logout_NilRequestErrors(t *testing.T) {
	client := local.NewAuthClient(defaultimpl.NewEd25519JWTIssuer())
	if err := client.Logout(context.Background(), nil); err == nil {
		t.Error("Logout(nil) should error")
	}
}

// ---------- ListPermissions coverage ----------

func TestLocalAuthz_ListPermissions_HappyPath(t *testing.T) {
	prov := authzFixture(t)
	c := local.NewAuthzClient(prov)

	perms, err := c.ListPermissions(context.Background(), "user-alice", "web-app")
	if err != nil {
		t.Fatalf("ListPermissions: %v", err)
	}
	if len(perms) == 0 {
		t.Errorf("expected at least one permission, got %v", perms)
	}
}

func TestLocalAuthz_ListPermissions_UnknownUserReturnsEmpty(t *testing.T) {
	// permissions.ErrUserNotFound is swallowed and the caller sees an
	// empty, non-nil slice — same contract as ListRoles / GetMenus.
	c := local.NewAuthzClient(authzFixture(t))
	perms, err := c.ListPermissions(context.Background(), "user-ghost", "web-app")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if perms == nil {
		t.Error("ListPermissions returned nil; want non-nil empty slice for SPA contract")
	}
	if len(perms) != 0 {
		t.Errorf("got %d perms for unknown user, want 0", len(perms))
	}
}

func TestLocalAuthz_ListPermissions_ProviderErrorSurfaces(t *testing.T) {
	// A non-NotFound provider error must propagate. We can't easily
	// trigger one from MemoryProvider, so use a stub.
	c := local.NewAuthzClient(&erroringProvider{err: errors.New("db down")})
	if _, err := c.ListPermissions(context.Background(), "u", "c"); err == nil {
		t.Error("expected provider error to surface")
	}
}

func TestLocalAuthz_ListRoles_ProviderErrorSurfaces(t *testing.T) {
	c := local.NewAuthzClient(&erroringProvider{err: errors.New("db down")})
	if _, err := c.ListRoles(context.Background(), "u", "c"); err == nil {
		t.Error("expected provider error to surface")
	}
}

func TestLocalAuthz_GetMenus_ProviderErrorSurfaces(t *testing.T) {
	c := local.NewAuthzClient(&erroringProvider{err: errors.New("db down")})
	if _, err := c.GetMenus(context.Background(), "u", "c"); err == nil {
		t.Error("expected provider error to surface")
	}
}

// erroringProvider is a permissions.Provider that returns the configured
// error on every read operation. Used to exercise the error-propagation
// branches of the local AuthzClient.
type erroringProvider struct{ err error }

func (e *erroringProvider) Permissions(context.Context, string, string) ([]permissions.Permission, error) {
	return nil, e.err
}
func (e *erroringProvider) Roles(context.Context, string, string) ([]permissions.Role, error) {
	return nil, e.err
}
func (e *erroringProvider) Menus(context.Context, string, string) (permissions.MenuTree, error) {
	return nil, e.err
}
func (e *erroringProvider) AddRole(context.Context, string, permissions.Role) error {
	return e.err
}
func (e *erroringProvider) UpdateRole(context.Context, string, permissions.Role) error {
	return e.err
}
func (e *erroringProvider) RemoveRole(context.Context, string, string) error { return e.err }
func (e *erroringProvider) ListAllRoles(context.Context, string) ([]permissions.Role, error) {
	return nil, e.err
}
func (e *erroringProvider) AssignRoles(context.Context, string, string, []string) error { return e.err }
func (e *erroringProvider) UnassignRoles(context.Context, string, string, []string) error {
	return e.err
}
func (e *erroringProvider) ListAssignments(context.Context, string) ([]permissions.Assignment, error) {
	return nil, e.err
}
func (e *erroringProvider) SetMenus(context.Context, string, permissions.MenuTree) error {
	return e.err
}
func (e *erroringProvider) GetMenus(context.Context, string) (permissions.MenuTree, error) {
	return nil, e.err
}
