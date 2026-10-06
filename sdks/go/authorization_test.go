package snaplink

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The cases in ops/build/sdk-conformance/authorization.json are the shared
// contract. A client rule that disagrees with the server is worse than no rule
// at all, so the rule is implemented once here and asserted against one fixture.

type authorizationRuleCase struct {
	ID       string   `json:"id"`
	Held     []string `json:"held"`
	Required string   `json:"required"`
	Expect   bool     `json:"expect"`
}

func loadAuthorizationFixture(t *testing.T) []authorizationRuleCase {
	t.Helper()
	path := filepath.Join("..", "..", "ops", "build", "sdk-conformance", "authorization.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read the shared fixture: %v", err)
	}
	var document struct {
		Cases []authorizationRuleCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("the shared fixture must be valid JSON: %v", err)
	}
	if len(document.Cases) == 0 {
		t.Fatal("the shared fixture must not be empty")
	}
	return document.Cases
}

func TestHoldsMatchesEveryRuleCase(t *testing.T) {
	for _, testCase := range loadAuthorizationFixture(t) {
		t.Run(testCase.ID, func(t *testing.T) {
			if got := Holds(testCase.Held, testCase.Required); got != testCase.Expect {
				t.Fatalf("Holds(%q, %q) = %v, want %v",
					testCase.Held, testCase.Required, got, testCase.Expect)
			}
		})
	}
}

func TestHoldsFixtureCoversTheWildcardBoundary(t *testing.T) {
	present := map[string]bool{}
	for _, testCase := range loadAuthorizationFixture(t) {
		present[testCase.ID] = true
	}
	for _, required := range []string{
		"exact_match",
		"absent_permission_is_denied",
		"domain_wildcard_does_not_match_a_similar_looking_domain",
		"a_bare_star_grants_everything",
		"an_unqualified_permission_is_never_a_prefix",
		"an_empty_requirement_is_always_granted",
	} {
		if !present[required] {
			t.Fatalf("fixture must keep the %s case", required)
		}
	}
}

func TestNodeVisibilityAndButtonsUseTheSameRule(t *testing.T) {
	node := &MenuNode{
		ID: "users", Name: "Users",
		Buttons: []MenuButton{
			{Code: "create", Permission: "panel:inbound:write"},
			{Code: "delete", Permission: "panel:*"},
			{Code: "help"},
		},
	}
	if !node.IsVisible(nil) {
		t.Fatal("a node with no permission is always visible")
	}
	if !node.IsVisible([]string{"panel:read"}) {
		t.Fatal("a node with no permission is always visible")
	}
	if codes := buttonCodes(node.Actions([]string{"panel:inbound:write"})); len(codes) != 2 ||
		codes[0] != "create" || codes[1] != "help" {
		t.Fatalf("narrow grant kept %v", codes)
	}
	if codes := buttonCodes(node.Actions([]string{"panel:*"})); len(codes) != 3 {
		t.Fatalf("wildcard grant kept %v", codes)
	}
	if codes := buttonCodes(node.Actions(nil)); len(codes) != 1 || codes[0] != "help" {
		t.Fatalf("empty grant kept %v", codes)
	}
}

func buttonCodes(buttons []MenuButton) []string {
	out := make([]string, 0, len(buttons))
	for _, button := range buttons {
		out = append(out, button.Code)
	}
	return out
}

func TestVisibleMenusDropsADeniedParentWithItsChildren(t *testing.T) {
	tree := []*MenuNode{
		{ID: "admin", Permission: "panel:*", Children: []*MenuNode{
			{ID: "audit", Permission: "panel:read"},
		}},
		{ID: "portal", Children: []*MenuNode{{ID: "me"}}},
	}
	viewer := Authorization{Subject: "u", Menus: tree}
	visible := viewer.VisibleMenus()
	if len(visible) != 1 || visible[0].ID != "portal" {
		t.Fatalf("a denied parent must be dropped with its children, got %+v", visible)
	}
	owner := Authorization{Subject: "u", Permissions: []string{"panel:*"}, Menus: tree}
	visible = owner.VisibleMenus()
	if len(visible) != 2 {
		t.Fatalf("wildcard owner kept %d nodes", len(visible))
	}
	if len(visible[0].Children) != 1 || visible[0].Children[0].ID != "audit" {
		t.Fatalf("child projection wrong: %+v", visible[0].Children)
	}
}

// authorizationServer serves the four reads and records what was asked for.
type authorizationServer struct {
	*httptest.Server
	paths  []string
	scopes []string
}

func newAuthorizationServer(t *testing.T, permissions, roles []string, menus []*MenuNode) *authorizationServer {
	t.Helper()
	fixture := &authorizationServer{}
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, value any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(value)
	}
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		fixture.paths = append(fixture.paths, r.URL.Path)
		writeJSON(w, map[string]any{
			"sub": "user-alice", "email": "alice@example.test", "name": "Alice",
		})
	})
	mux.HandleFunc("/permissions/me", func(w http.ResponseWriter, r *http.Request) {
		fixture.paths = append(fixture.paths, r.URL.Path)
		fixture.scopes = append(fixture.scopes, r.URL.Query().Get("client_id"))
		writeJSON(w, map[string]any{"permissions": permissions})
	})
	mux.HandleFunc("/roles/me", func(w http.ResponseWriter, r *http.Request) {
		fixture.paths = append(fixture.paths, r.URL.Path)
		fixture.scopes = append(fixture.scopes, r.URL.Query().Get("client_id"))
		writeJSON(w, map[string]any{"roles": roles})
	})
	mux.HandleFunc("/menus/me", func(w http.ResponseWriter, r *http.Request) {
		fixture.paths = append(fixture.paths, r.URL.Path)
		fixture.scopes = append(fixture.scopes, r.URL.Query().Get("client_id"))
		writeJSON(w, map[string]any{"menus": menus})
	})
	fixture.Server = httptest.NewServer(mux)
	t.Cleanup(fixture.Close)
	return fixture
}

func (s *authorizationServer) client() *Client {
	client := NewClient(nil, s.Client())
	client.tokens = &TokenResponse{AccessToken: "access-1", TokenType: "Bearer"}
	client.baseURL = s.URL
	client.clientID = "spa-client"
	return client
}

func TestAuthorizeReadsIdentityPermissionsRolesAndMenus(t *testing.T) {
	server := newAuthorizationServer(t,
		[]string{"panel:read", "panel:config:apply"}, []string{"panel-viewer"},
		[]*MenuNode{{ID: "m", Name: "Inbounds", Permission: "panel:read"}},
	)
	authorization, err := server.client().Authorize(context.Background(), "singbox-panel")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if authorization.Subject != "user-alice" || authorization.Email != "alice@example.test" {
		t.Fatalf("identity %+v", authorization)
	}
	if len(authorization.Permissions) != 2 || len(authorization.Roles) != 1 {
		t.Fatalf("grants %+v %+v", authorization.Permissions, authorization.Roles)
	}
	if len(authorization.Menus) != 1 {
		t.Fatalf("menus %+v", authorization.Menus)
	}
	if !authorization.Allows("panel:config:apply") || authorization.Allows("other:read") {
		t.Fatal("Allows must use the same rule")
	}
}

func TestAuthorizeScopesEveryProjectionToTheApplication(t *testing.T) {
	server := newAuthorizationServer(t, []string{"panel:read"}, []string{"viewer"}, nil)
	if _, err := server.client().Authorize(context.Background(), "singbox-panel"); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if len(server.paths) != 4 {
		t.Fatalf("expected four reads, got %v", server.paths)
	}
	for _, scope := range server.scopes {
		if scope != "singbox-panel" {
			t.Fatalf("every projection must be scoped, got %q", scope)
		}
	}
}

func TestAuthorizeRequiresAClientID(t *testing.T) {
	server := newAuthorizationServer(t, nil, nil, nil)
	if _, err := server.client().Authorize(context.Background(), "  "); err == nil {
		t.Fatal("a blank client_id must be refused before any request")
	}
	if len(server.paths) != 0 {
		t.Fatalf("no request may be made, got %v", server.paths)
	}
}

func TestAuthorizeRequiresASession(t *testing.T) {
	server := newAuthorizationServer(t, nil, nil, nil)
	if _, err := NewClient(nil, server.Client()).Authorize(context.Background(), "app"); err == nil {
		t.Fatal("authorize without a session must fail")
	}
}

func TestACodeListWithNoReadableCodeGrantsNothing(t *testing.T) {
	// An empty entry dropped rather than surfaced as a code that might match
	// the always-granted empty requirement.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/userinfo":
			_, _ = w.Write([]byte(`{"sub":"u"}`))
		case "/permissions/me":
			_, _ = w.Write([]byte(`{"permissions":[{"code":""},{"description":"no code"},"panel:read"]}`))
		case "/roles/me":
			_, _ = w.Write([]byte(`{"roles":[]}`))
		default:
			_, _ = w.Write([]byte(`{"menus":null}`))
		}
	}))
	defer server.Close()

	client := NewClient(nil, server.Client())
	client.tokens = &TokenResponse{AccessToken: "access-1"}
	client.baseURL = server.URL

	authorization, err := client.Authorize(context.Background(), "app")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	for _, code := range authorization.Permissions {
		if strings.TrimSpace(code) == "" {
			t.Fatalf("an empty code must be dropped, got %q", authorization.Permissions)
		}
	}
	if len(authorization.Permissions) != 1 || authorization.Permissions[0] != "panel:read" {
		t.Fatalf("permissions %q", authorization.Permissions)
	}
}

func TestAUserInfoWithoutASubjectIsRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/userinfo" {
			_, _ = w.Write([]byte(`{"email":"nobody@example.test"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := NewClient(nil, server.Client())
	client.tokens = &TokenResponse{AccessToken: "access-1"}
	client.baseURL = server.URL

	if _, err := client.Authorize(context.Background(), "app"); err == nil {
		t.Fatal("a response with no subject must not be trusted")
	}
}
