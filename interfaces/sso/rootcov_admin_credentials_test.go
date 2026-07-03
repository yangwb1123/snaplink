package sso_test

// rootcov_admin_credentials_test.go covers GET /api/v1/admin/credentials —
// the read-only governance inventory backing WithCredentialRotation.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/rotation"
	"github.com/snaplink/sso/shared/core/corecredential"
)

// stubRotator is a minimal corecredential.CredentialRotator for the HTTP
// surface test — the rotation MECHANICS are covered exhaustively in
// platform/rotation; this only needs a registry with a known Inventory().
type stubRotator struct{ overlap time.Duration }

func (stubRotator) Type() corecredential.CredentialType { return "test_stub_cred" }
func (s stubRotator) OverlapWindow() time.Duration      { return s.overlap }
func (stubRotator) Rotate(context.Context) (corecredential.CredentialMeta, error) {
	return corecredential.CredentialMeta{}, nil
}
func (stubRotator) CurrentMeta() corecredential.CredentialMeta {
	return corecredential.CredentialMeta{
		ID: "test_stub_cred/v1", Type: "test_stub_cred", Version: 1,
		Status: corecredential.CredentialStatusActive, Algorithm: "HMAC-SHA256",
	}
}

var _ rotation.CurrentMetaProvider = stubRotator{}

// TestRcovAdmin_CredentialsNotMountedWithoutRegistry proves the byte-identical
// default: without WithCredentialRotation the route 404s (not just "unauthorized"
// — genuinely unmounted) even for a fully-authorized admin bearer.
func TestRcovAdmin_CredentialsNotMountedWithoutRegistry(t *testing.T) {
	t.Parallel()
	env := rcovNewAdminServer(t)
	status, _ := rcovDo(t, http.MethodGet, env.url+"/api/v1/admin/credentials", env.token, nil)
	if status != http.StatusNotFound {
		t.Fatalf("GET /api/v1/admin/credentials without a registry = %d, want 404", status)
	}
}

// TestRcovAdmin_CredentialsRequiresAdminBearer proves the endpoint sits
// behind the same AdminMiddleware gate as every other /api/v1/admin/* route.
func TestRcovAdmin_CredentialsRequiresAdminBearer(t *testing.T) {
	t.Parallel()
	reg := rotation.NewRegistry()
	if err := reg.Register(stubRotator{overlap: time.Minute}, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}
	env := rcovNewAdminServer(t, sso.WithCredentialRotation(reg))

	status, _ := rcovDo(t, http.MethodGet, env.url+"/api/v1/admin/credentials", "", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("no-bearer credentials inventory = %d, want 401", status)
	}
}

// TestRcovAdmin_CredentialsInventory proves the endpoint returns the
// registered credential class's governance metadata — type, version, status,
// algorithm, next rotation due — and NOTHING resembling secret material.
func TestRcovAdmin_CredentialsInventory(t *testing.T) {
	t.Parallel()
	reg := rotation.NewRegistry()
	if err := reg.Register(stubRotator{overlap: time.Minute}, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}
	env := rcovNewAdminServer(t, sso.WithCredentialRotation(reg))

	status, out := rcovDo(t, http.MethodGet, env.url+"/api/v1/admin/credentials", env.token, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/v1/admin/credentials = %d body=%v", status, out)
	}
	creds, _ := out["credentials"].([]any)
	if len(creds) != 1 {
		t.Fatalf("credentials = %d entries, want 1 (body=%v)", len(creds), out)
	}
	entry, _ := creds[0].(map[string]any)
	if entry["id"] != "test_stub_cred/v1" {
		t.Errorf("id = %v, want test_stub_cred/v1", entry["id"])
	}
	if entry["type"] != "test_stub_cred" {
		t.Errorf("type = %v", entry["type"])
	}
	if entry["status"] != "active" {
		t.Errorf("status = %v, want active", entry["status"])
	}
	if entry["next_rotation"] == nil || entry["next_rotation"] == "" {
		t.Errorf("next_rotation missing: %v", entry)
	}
	for k := range entry {
		if k == "id" || k == "type" || k == "version" || k == "status" ||
			k == "created_at" || k == "not_after" || k == "algorithm" || k == "next_rotation" {
			continue
		}
		t.Errorf("unexpected field %q in credentials inventory entry (governance-only surface): %v", k, entry)
	}
}
