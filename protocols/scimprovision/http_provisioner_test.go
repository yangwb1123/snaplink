package scimprovision

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/yangwb1123/snaplink/protocols/scim"
	"github.com/yangwb1123/snaplink/shared/core"
)

const testBasePath = "/scim/v2"
const testGroupClientID = "app1"

// newTestSCIMServer stands up a REAL protocols/scim.Handler (RFC 7643/7644)
// behind httptest — this is the "downstream SCIM-compliant application"
// HTTPSCIMProvisioner pushes to in every test below. Using the codebase's
// own receiver (rather than a hand-rolled mock) both satisfies "no mocks"
// and proves HTTPSCIMProvisioner's wire format actually interoperates with
// a real SCIM 2.0 implementation. requireToken, when non-empty, gates every
// request behind Authorization: Bearer <requireToken> — a stand-in for
// whatever auth a real downstream app enforces, letting the auth tests
// below exercise HTTPSCIMProvisioner's bearer-token header.
func newTestSCIMServer(t *testing.T, requireToken string) (*httptest.Server, core.UserProvider, permissions.Provider) {
	t.Helper()
	users := memorystoreidentity.NewMemoryUserProvider()
	perms := permissions.NewMemoryProvider()
	h := scim.NewHandler(users, testBasePath, scim.WithGroups(perms, testGroupClientID))
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if requireToken != "" && r.Header.Get("Authorization") != "Bearer "+requireToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, users, perms
}

func newTestProvisioner(t *testing.T, srv *httptest.Server, token string) *HTTPSCIMProvisioner {
	t.Helper()
	// httptest binds loopback; explicitly inject a test client to bypass the
	// production SSRF guard while retaining the real wire-level receiver.
	return NewHTTPSCIMProvisioner(srv.URL+testBasePath, WithBearerToken(token),
		WithHTTPClient(&http.Client{Timeout: DefaultHTTPTimeout}))
}

func TestNewHTTPSCIMProvisioner_DefaultClientGuardsPrivateAddresses(t *testing.T) {
	t.Parallel()
	p := NewHTTPSCIMProvisioner("http://127.0.0.1:1")
	_, err := p.CreateUser(context.Background(), scim.Resource{ExternalID: "u1"})
	if err == nil || !strings.Contains(err.Error(), "SSRF guard") {
		t.Fatalf("private-address request error = %v, want SSRF guard rejection", err)
	}
}

// fakeGroup is one stored Group in newFakeGroupSCIMServer's in-memory table.
type fakeGroup struct {
	id, externalID, displayName string
	members                     []scim.GroupMember
}

// newFakeGroupSCIMServer is a minimal, REAL (not mocked) SCIM 2.0 /Groups
// implementation that — unlike this SDK's own protocols/scim receiver (see
// the comment on TestHTTPSCIMProvisioner_ReplaceGroupMembers_CreateThenUpdate)
// — actually persists and filters by externalId, standing in for a
// downstream SCIM app (Okta, Azure AD, ...) that supports the RFC 7644
// §3.4.2.2 lookup HTTPSCIMProvisioner relies on to resolve create-vs-update.
func newFakeGroupSCIMServer(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	store := map[string]*fakeGroup{}
	nextID := 0

	mux := http.NewServeMux()
	mux.HandleFunc("POST "+testBasePath+"/Groups", func(w http.ResponseWriter, r *http.Request) {
		var g scim.GroupResource
		if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		nextID++
		id := fmt.Sprintf("fake-group-%d", nextID)
		store[id] = &fakeGroup{id: id, externalID: g.ExternalID, displayName: g.DisplayName, members: g.Members}
		mu.Unlock()
		writeFakeGroup(w, http.StatusCreated, store[id])
	})
	mux.HandleFunc("GET "+testBasePath+"/Groups", func(w http.ResponseWriter, r *http.Request) {
		ext, ok := parseExternalIDFilter(r.URL.Query().Get("filter"))
		mu.Lock()
		var resources []scim.GroupResource
		if ok {
			for _, fg := range store {
				if fg.externalID == ext {
					resources = append(resources, fakeGroupResource(fg))
				}
			}
		}
		mu.Unlock()
		writeJSON(w, http.StatusOK, scim.GroupListResponse{
			Schemas:      []string{scim.SchemaListResponse},
			TotalResults: len(resources),
			ItemsPerPage: len(resources),
			Resources:    resources,
		})
	})
	mux.HandleFunc("PATCH "+testBasePath+"/Groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fg, ok := store[r.PathValue("id")]
		mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var patch scim.PatchRequest
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		applyFakeGroupPatch(fg, patch)
		mu.Unlock()
		writeFakeGroup(w, http.StatusOK, fg)
	})
	mux.HandleFunc("DELETE "+testBasePath+"/Groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		delete(store, r.PathValue("id"))
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// applyFakeGroupPatch applies the displayName/members "replace" ops
// groupReplacePatch produces — enough of RFC 7644 §3.5.2 to exercise
// HTTPSCIMProvisioner's outbound PATCH shape, not a general PATCH engine.
func applyFakeGroupPatch(fg *fakeGroup, patch scim.PatchRequest) {
	for _, op := range patch.Operations {
		switch op.Path {
		case "displayName":
			var name string
			_ = json.Unmarshal(op.Value, &name)
			fg.displayName = name
		case "members":
			var members []scim.GroupMember
			_ = json.Unmarshal(op.Value, &members)
			fg.members = members
		}
	}
}

func fakeGroupResource(fg *fakeGroup) scim.GroupResource {
	return scim.GroupResource{
		Schemas:     []string{scim.SchemaGroup},
		ID:          fg.id,
		ExternalID:  fg.externalID,
		DisplayName: fg.displayName,
		Members:     fg.members,
	}
}

func writeFakeGroup(w http.ResponseWriter, status int, fg *fakeGroup) {
	writeJSON(w, status, fakeGroupResource(fg))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", scim.ContentTypeSCIM)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// parseExternalIDFilter extracts the quoted value from a
// `externalId eq "<value>"` filter (RFC 7644 §3.4.2.2) — just enough to
// drive this fake, not a general filter parser (protocols/scim's real
// filter.go already covers that grammar for the actual receiver).
func parseExternalIDFilter(raw string) (value string, ok bool) {
	const prefix = `externalId eq "`
	if !strings.HasPrefix(raw, prefix) || !strings.HasSuffix(raw, `"`) {
		return "", false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(raw, prefix), `"`)
	inner = strings.ReplaceAll(inner, `\"`, `"`)
	inner = strings.ReplaceAll(inner, `\\`, `\`)
	return inner, true
}

func TestHTTPSCIMProvisioner_CreateUser(t *testing.T) {
	srv, _, _ := newTestSCIMServer(t, "")
	p := newTestProvisioner(t, srv, "")
	ctx := context.Background()

	in := scim.Resource{
		Schemas:     []string{scim.SchemaUser},
		ExternalID:  "local-user-1",
		UserName:    "alice",
		DisplayName: "Alice Example",
	}
	out, err := p.CreateUser(ctx, in)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if out.ID == "" {
		t.Fatal("CreateUser: downstream did not assign an id")
	}
	if out.ExternalID != "local-user-1" {
		t.Fatalf("CreateUser: ExternalID = %q, want %q", out.ExternalID, "local-user-1")
	}
}

func TestHTTPSCIMProvisioner_ReplaceUser_SelfHealsToCreate(t *testing.T) {
	srv, users, _ := newTestSCIMServer(t, "")
	p := newTestProvisioner(t, srv, "")
	ctx := context.Background()

	// Never created downstream — ReplaceUser must self-heal via CreateUser
	// rather than erroring (see SCIMProvisioner.ReplaceUser).
	in := scim.Resource{ExternalID: "local-user-2", UserName: "bob", DisplayName: "Bob"}
	out, err := p.ReplaceUser(ctx, in)
	if err != nil {
		t.Fatalf("ReplaceUser (self-heal): %v", err)
	}
	if out.ID == "" {
		t.Fatal("ReplaceUser (self-heal): no downstream id assigned")
	}
	all, err := users.List(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("downstream store: List() = %v, %v; want exactly 1 user", all, err)
	}
}

func TestHTTPSCIMProvisioner_ReplaceUser_UpdatesExisting(t *testing.T) {
	srv, _, _ := newTestSCIMServer(t, "")
	p := newTestProvisioner(t, srv, "")
	ctx := context.Background()

	in := scim.Resource{ExternalID: "local-user-3", UserName: "carol", DisplayName: "Carol"}
	if _, err := p.CreateUser(ctx, in); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	in.DisplayName = "Carol Renamed"
	out, err := p.ReplaceUser(ctx, in)
	if err != nil {
		t.Fatalf("ReplaceUser: %v", err)
	}
	if out.DisplayName != "Carol Renamed" {
		t.Fatalf("ReplaceUser: DisplayName = %q, want %q", out.DisplayName, "Carol Renamed")
	}
}

func TestHTTPSCIMProvisioner_DeleteUser_IdempotentAndEffective(t *testing.T) {
	srv, users, _ := newTestSCIMServer(t, "")
	p := newTestProvisioner(t, srv, "")
	ctx := context.Background()

	in := scim.Resource{ExternalID: "local-user-4", UserName: "dave"}
	if _, err := p.CreateUser(ctx, in); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := p.DeleteUser(ctx, "local-user-4"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if all, _ := users.List(ctx); len(all) != 0 {
		t.Fatalf("downstream store still has %d user(s) after delete", len(all))
	}
	// Idempotent: deleting an externalId the downstream never had is success.
	if err := p.DeleteUser(ctx, "never-existed"); err != nil {
		t.Fatalf("DeleteUser (idempotent): %v", err)
	}
}

func TestHTTPSCIMProvisioner_BearerAuth(t *testing.T) {
	srv, _, _ := newTestSCIMServer(t, "s3cr3t")
	ctx := context.Background()

	t.Run("correct token succeeds", func(t *testing.T) {
		p := newTestProvisioner(t, srv, "s3cr3t")
		if _, err := p.CreateUser(ctx, scim.Resource{ExternalID: "u1", UserName: "u1"}); err != nil {
			t.Fatalf("CreateUser with correct token: %v", err)
		}
	})

	t.Run("missing token fails", func(t *testing.T) {
		p := newTestProvisioner(t, srv, "")
		_, err := p.CreateUser(ctx, scim.Resource{ExternalID: "u2", UserName: "u2"})
		var statusErr *StatusError
		if err == nil {
			t.Fatal("expected an error with no bearer token, got nil")
		}
		if !asStatusError(err, &statusErr) || statusErr.Status != http.StatusUnauthorized {
			t.Fatalf("expected *StatusError{401}, got %v", err)
		}
	})

	t.Run("wrong token fails", func(t *testing.T) {
		p := newTestProvisioner(t, srv, "wrong")
		_, err := p.CreateUser(ctx, scim.Resource{ExternalID: "u3", UserName: "u3"})
		var statusErr *StatusError
		if err == nil || !asStatusError(err, &statusErr) || statusErr.Status != http.StatusUnauthorized {
			t.Fatalf("expected *StatusError{401}, got %v", err)
		}
	})
}

func asStatusError(err error, target **StatusError) bool {
	se, ok := err.(*StatusError)
	if !ok {
		return false
	}
	*target = se
	return true
}

// TestHTTPSCIMProvisioner_ReplaceGroupMembers_CreateThenUpdate runs against
// newFakeGroupSCIMServer rather than the real protocols/scim receiver: this
// SDK's own /Groups maps onto a permissions.Role, which has no externalId
// column (Users have one; Groups don't — see doc.go's group-provisioning
// note), so it can never report an existing group back on a
// filter=externalId lookup and every push looks like a fresh create. A real
// downstream SCIM app (Okta, Azure AD, a generic RFC-7644-compliant server)
// DOES persist Group.externalId, so this exercises the create-vs-update
// resolution logic HTTPSCIMProvisioner is actually responsible for.
func TestHTTPSCIMProvisioner_ReplaceGroupMembers_CreateThenUpdate(t *testing.T) {
	srv := newFakeGroupSCIMServer(t)
	p := newTestProvisioner(t, srv, "")
	ctx := context.Background()

	g := scim.GroupResource{
		Schemas:     []string{scim.SchemaGroup},
		ExternalID:  "eng",
		DisplayName: "Engineering",
		Members:     []scim.GroupMember{{Value: "user-1"}},
	}
	out, err := p.ReplaceGroupMembers(ctx, g)
	if err != nil {
		t.Fatalf("ReplaceGroupMembers (create): %v", err)
	}
	if out.ID == "" {
		t.Fatal("ReplaceGroupMembers (create): no downstream id assigned")
	}

	// Full-state reconciliation: pushing a DIFFERENT member set replaces it
	// entirely (not an add) — see doc.go's "full-state reconciliation" note.
	g.Members = []scim.GroupMember{{Value: "user-2"}}
	out2, err := p.ReplaceGroupMembers(ctx, g)
	if err != nil {
		t.Fatalf("ReplaceGroupMembers (update): %v", err)
	}
	if out2.ID != out.ID {
		t.Fatalf("ReplaceGroupMembers (update): id changed from %q to %q — should have updated the SAME downstream group, not created a second one", out.ID, out2.ID)
	}
	if len(out2.Members) != 1 || out2.Members[0].Value != "user-2" {
		t.Fatalf("ReplaceGroupMembers (update): Members = %+v, want exactly [user-2]", out2.Members)
	}
}

func TestHTTPSCIMProvisioner_DeleteGroup_Idempotent(t *testing.T) {
	srv := newFakeGroupSCIMServer(t)
	p := newTestProvisioner(t, srv, "")
	ctx := context.Background()

	g := scim.GroupResource{ExternalID: "sales", DisplayName: "Sales"}
	if _, err := p.ReplaceGroupMembers(ctx, g); err != nil {
		t.Fatalf("ReplaceGroupMembers: %v", err)
	}
	if err := p.DeleteGroup(ctx, "sales"); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	if err := p.DeleteGroup(ctx, "sales"); err != nil {
		t.Fatalf("DeleteGroup (idempotent repeat): %v", err)
	}
}

func TestEscapeFilterValue(t *testing.T) {
	cases := []struct{ in, want string }{
		{`plain`, `plain`},
		{`has "quote"`, `has \"quote\"`},
		{`back\slash`, `back\\slash`},
	}
	for _, c := range cases {
		if got := escapeFilterValue(c.in); got != c.want {
			t.Errorf("escapeFilterValue(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
