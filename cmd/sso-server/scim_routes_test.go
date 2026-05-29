package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/scim"
)

// scimTestServer builds a bare *sso.Server, materializes its router via
// Handler() (the same ordering cmd uses), then mounts the SCIM routes so
// requests exercise the real router dispatch — including the /Users/:id
// param route and the admin-prefix path the handler strips.
func scimTestServer(t *testing.T) (http.Handler, *defaultimpl.MemoryUserProvider, *audit.MemorySink) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	sink := audit.NewMemorySink(64)
	srv := sso.NewServer()
	base := srv.Handler() // calls Mount() once, creating the router
	if err := mountSCIMRoutes(srv, users, audit.New(sink), nil); err != nil {
		t.Fatalf("mountSCIMRoutes: %v", err)
	}
	return base, users, sink
}

func scimReq(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, scimBasePath+path, nil)
	} else {
		r = httptest.NewRequest(method, scimBasePath+path, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// TestSCIMRoutesMounted drives create -> get -> delete through the real
// router so the :id param route and the discovery routes are proven wired.
func TestSCIMRoutesMounted(t *testing.T) {
	h, users, _ := scimTestServer(t)

	// Create via POST /Users.
	rec := scimReq(t, h, http.MethodPost, "/Users", `{"userName":"bob@example.com"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var created scim.Resource
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.ID == "" {
		t.Fatal("created resource has no id")
	}
	// The store now holds the user under the server-minted id.
	if _, err := users.GetByID(context.Background(), created.ID); err != nil {
		t.Fatalf("user not persisted: %v", err)
	}

	// GET /Users/{id} via the :id param route.
	rec = scimReq(t, h, http.MethodGet, "/Users/"+created.ID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200", rec.Code)
	}

	// DELETE /Users/{id}.
	rec = scimReq(t, h, http.MethodDelete, "/Users/"+created.ID, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", rec.Code)
	}
}

func TestSCIMDiscoveryRoutesMounted(t *testing.T) {
	h, _, _ := scimTestServer(t)
	for _, p := range []string{"/ServiceProviderConfig", "/Schemas"} {
		rec := scimReq(t, h, http.MethodGet, p, "")
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", p, rec.Code)
		}
	}
}

// TestSCIMRoutesNoUserProvider confirms the mount is a no-op (no error)
// when there is no user provider to provision against.
func TestSCIMRoutesNoUserProvider(t *testing.T) {
	srv := sso.NewServer()
	_ = srv.Handler()
	if err := mountSCIMRoutes(srv, nil, nil, nil); err != nil {
		t.Fatalf("mountSCIMRoutes(nil users) = %v, want nil (no-op)", err)
	}
}

// TestSCIMGroupRoutesMounted drives create -> get -> delete on /Groups
// through the real router so the :id param route is proven wired and the
// SCIM group -> permissions role mapping runs end-to-end.
func TestSCIMGroupRoutesMounted(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	perms := permissions.NewMemoryProvider()
	srv := sso.NewServer()
	base := srv.Handler()
	deps := &scimGroupDeps{provider: perms, clientID: "app"}
	if err := mountSCIMRoutes(srv, users, audit.New(audit.NewMemorySink(8)), deps); err != nil {
		t.Fatalf("mountSCIMRoutes(groups): %v", err)
	}

	rec := scimReq(t, base, http.MethodPost, "/Groups", `{"displayName":"Ops","members":[{"value":"u1"}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create group status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var g scim.GroupResource
	if err := json.Unmarshal(rec.Body.Bytes(), &g); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if g.ID == "" {
		t.Fatal("group has no id")
	}
	// Mapping ran: u1 holds the role under "app".
	roles, err := perms.Roles(context.Background(), "u1", "app")
	if err != nil || len(roles) != 1 || roles[0].Code != g.ID {
		t.Fatalf("membership did not map to role: roles=%+v err=%v", roles, err)
	}

	rec = scimReq(t, base, http.MethodGet, "/Groups/"+g.ID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get group status = %d, want 200", rec.Code)
	}
	rec = scimReq(t, base, http.MethodDelete, "/Groups/"+g.ID, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete group status = %d, want 204", rec.Code)
	}
}

// TestSCIMGroupsNotMountedWithoutDeps confirms /Groups 404s when groups
// aren't wired (the User surface stays independent of permissions).
func TestSCIMGroupsNotMountedWithoutDeps(t *testing.T) {
	h, _, _ := scimTestServer(t) // mounted with nil group deps
	rec := scimReq(t, h, http.MethodGet, "/Groups", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /Groups (groups unmounted) = %d, want 404", rec.Code)
	}
}
