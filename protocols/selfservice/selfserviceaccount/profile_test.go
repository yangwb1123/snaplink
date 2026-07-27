package selfserviceaccount

import (
	"net/http"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestHandleMe_AssemblesProfileWithCounts(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.users.CreateOrUpdate(t.Context(), &core.User{
		ID: "user-1", Name: "Alice", Email: "alice@example.com",
		Attributes: map[string]string{"name": "Alice", "password_hash": "should-never-appear"},
	})
	_, _ = d.sessions.Create(t.Context(), "user-1")
	_, _ = d.sessions.Create(t.Context(), "user-1")

	ctx, rec := newCtx(http.MethodGet, "", "")
	HandleMe(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeBody(t, rec)
	if resp[core.KeySub] != "user-1" {
		t.Errorf("sub = %v, want user-1", resp[core.KeySub])
	}
	if got := resp["active_sessions"]; got != float64(2) {
		t.Errorf("active_sessions = %v, want 2", got)
	}
	u, _ := resp["user"].(map[string]any)
	attrs, _ := u["attributes"].(map[string]any)
	if _, leaked := attrs["password_hash"]; leaked {
		t.Error("password_hash must never appear in the /me response")
	}
}

func TestHandleMe_ResidencyGateDenies(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	d.residencyAccessDeny = "region_not_allowed"
	ctx, rec := newCtx(http.MethodGet, "", "")
	HandleMe(d, ctx)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestHandleMyProfileUpdate_NameAlwaysEditable(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.users.CreateOrUpdate(t.Context(), &core.User{ID: "user-1", Name: "Old Name"})

	ctx, rec := newCtx(http.MethodPatch, core.ContentTypeJSON, `{"name":"New Name"}`)
	HandleMyProfileUpdate(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	u, _ := d.users.GetByID(t.Context(), "user-1")
	if u.Name != "New Name" {
		t.Errorf("name = %q, want New Name", u.Name)
	}
}

func TestHandleMyProfileUpdate_AttributeAllowlist(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	d.selfEditableAttrs = map[string]struct{}{"locale": {}}
	_ = d.users.CreateOrUpdate(t.Context(), &core.User{ID: "user-1"})

	body := `{"attributes":{"locale":"fr-FR","password_hash":"attacker-controlled"}}`
	ctx, rec := newCtx(http.MethodPatch, core.ContentTypeJSON, body)
	HandleMyProfileUpdate(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	u, _ := d.users.GetByID(t.Context(), "user-1")
	if u.Attributes["locale"] != "fr-FR" {
		t.Errorf("locale = %q, want fr-FR", u.Attributes["locale"])
	}
	if _, ok := u.Attributes["password_hash"]; ok {
		t.Error("a non-allowlisted attribute key must be silently dropped, never applied")
	}
}

func TestHandleMyProfileUpdate_UnknownUser404(t *testing.T) {
	t.Parallel()
	d := newTestDeps() // user-1 never created
	ctx, rec := newCtx(http.MethodPatch, core.ContentTypeJSON, `{"name":"New Name"}`)
	HandleMyProfileUpdate(d, ctx)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandleMyProfileUpdate_ResidencyGateDenies(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.users.CreateOrUpdate(t.Context(), &core.User{ID: "user-1"})
	d.residencyWriteDeny = "region_not_allowed"
	ctx, rec := newCtx(http.MethodPatch, core.ContentTypeJSON, `{"name":"New Name"}`)
	HandleMyProfileUpdate(d, ctx)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}
