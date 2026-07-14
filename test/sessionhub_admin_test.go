package ssotest

import (
	"testing"

	"github.com/snaplink/sso/interfaces/admin"
	"github.com/snaplink/sso/interfaces/sso"
)

// TestLinkedSessionsAdmin_PathIsAdminProtected proves the cross-protocol
// session-hub admin query (GET /api/v1/admin/sessions/linked/:subject) lives
// under the admin-gated prefix, so any deployment wiring AdminMiddleware
// (see test/admin_middleware_test.go) automatically requires an admin:read
// bearer for it — no per-route auth wiring needed. Mirrors
// TestTokenUsageAdmin_PathIsAdminProtected's convention for the sibling
// Token Portfolio per-subject view.
func TestLinkedSessionsAdmin_PathIsAdminProtected(t *testing.T) {
	path := "/api/v1" + sso.PathAdminSessionsLinked
	if !admin.IsProtectedPath(path) {
		t.Fatalf("IsProtectedPath(%q) = false, want true", path)
	}
}
