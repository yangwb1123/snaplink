package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPathExpr_TerminatesAndSubstitutesAllParams is a regression test: an
// earlier version of tsPathExpr/pyPathExpr mutated-and-rescanned their own
// output, which contains the SAME "{"/"}" characters the substitution
// syntax uses ("${encodeURIComponent(...)}" / "{urllib.parse.quote(...)}")
// -- rescanning that output for the next "{" found the substitution's OWN
// brace and looped forever. Both must terminate promptly and substitute
// every {name} exactly once.
func TestPathExpr_TerminatesAndSubstitutesAllParams(t *testing.T) {
	const path = "/tenants/{tenant_id}/users/{user_id}"
	done := make(chan struct{})
	var ts, py string
	go func() {
		ts = tsPathExpr(path)
		py = pyPathExpr(path)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("tsPathExpr/pyPathExpr did not terminate within 5s (infinite-loop regression)")
	}

	wantTS := "`/tenants/${encodeURIComponent(tenantId)}/users/${encodeURIComponent(userId)}`"
	if ts != wantTS {
		t.Errorf("tsPathExpr(%q) = %q, want %q", path, ts, wantTS)
	}
	wantPy := `f"/tenants/{urllib.parse.quote(tenant_id)}/users/{urllib.parse.quote(user_id)}"`
	if py != wantPy {
		t.Errorf("pyPathExpr(%q) = %q, want %q", path, py, wantPy)
	}
}

func TestPathExpr_NoParams(t *testing.T) {
	if got := tsPathExpr("/token"); got != "`/token`" {
		t.Errorf("tsPathExpr(no params) = %q", got)
	}
	if got := pyPathExpr("/token"); got != `"/token"` {
		t.Errorf("pyPathExpr(no params) = %q", got)
	}
}

func TestCamelCase(t *testing.T) {
	cases := map[string]string{
		"client_id":  "clientId",
		"id":         "id",
		"user_agent": "userAgent",
	}
	for in, want := range cases {
		if got := camelCase(in); got != want {
			t.Errorf("camelCase(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPySnakeCase(t *testing.T) {
	cases := map[string]string{
		"postToken":        "post_token",
		"postRevokeAll":    "post_revoke_all",
		"getJWKS":          "get_jwks",
		"postPAR":          "post_par",
		"getClientByID":    "get_client_by_id",
		"changeMyPassword": "change_my_password",
	}
	for in, want := range cases {
		if got := pySnakeCase(in); got != want {
			t.Errorf("pySnakeCase(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTsType_RefUnionEnum(t *testing.T) {
	ref := &TypeSpec{Kind: KindRef, Name: "TokenIssuance"}
	if got := tsType(ref); got != "TokenIssuance" {
		t.Errorf("tsType(ref) = %q", got)
	}
	union := &TypeSpec{Kind: KindUnion, Variants: []*TypeSpec{
		{Kind: KindString}, {Kind: KindArray, Elem: &TypeSpec{Kind: KindString}},
	}}
	if got := tsType(union); got != "string | string[]" {
		t.Errorf("tsType(union) = %q, want %q", got, "string | string[]")
	}
	enum := &TypeSpec{Kind: KindString, Enum: []string{"a", "b"}}
	if got := tsType(enum); got != `"a" | "b"` {
		t.Errorf("tsType(enum) = %q", got)
	}
	if tsType(nil) != "void" {
		t.Error("tsType(nil) should be void")
	}
}

func TestPyType_RefUnionMap(t *testing.T) {
	ref := &TypeSpec{Kind: KindRef, Name: "TokenIssuance"}
	if got := pyType(ref); got != "TokenIssuance" {
		t.Errorf("pyType(ref) = %q", got)
	}
	union := &TypeSpec{Kind: KindUnion, Variants: []*TypeSpec{
		{Kind: KindString}, {Kind: KindArray, Elem: &TypeSpec{Kind: KindString}},
	}}
	if got := pyType(union); got != "Union[str, List[str]]" {
		t.Errorf("pyType(union) = %q", got)
	}
	m := &TypeSpec{Kind: KindMap, Elem: &TypeSpec{Kind: KindString}}
	if got := pyType(m); got != "Dict[str, str]" {
		t.Errorf("pyType(map) = %q", got)
	}
	if pyType(nil) != "None" {
		t.Error("pyType(nil) should be None")
	}
}

func TestGenerateTS_BalancedBracesAndNoRawTemplateLeftovers(t *testing.T) {
	reg := NewRegistry(docAny(map[string]interface{}{
		"Widget": map[string]interface{}{
			"type":       "object",
			"required":   []interface{}{"id"},
			"properties": map[string]interface{}{"id": map[string]interface{}{"type": "string"}},
		},
	}))
	ops := []Operation{
		{
			ID: "getWidget", Method: "get", Path: "/widgets/{id}", Tag: "widgets",
			PathParams: []Param{{Name: "id", In: "path", Required: true, Type: &TypeSpec{Kind: KindString}}},
			ResultType: &TypeSpec{Kind: KindRef, Name: "Widget"},
		},
	}
	out := GenerateTS("Test", "1.0", reg, ops)
	if strings.Count(out, "{") != strings.Count(out, "}") {
		t.Errorf("unbalanced braces in generated TS (regression: a prior bug emitted an extra '}' per method call)")
	}
	if !strings.Contains(out, "`/widgets/${encodeURIComponent(id)}`") {
		t.Error("expected the path template literal in the generated method body")
	}
	if strings.Contains(out, "}});") {
		t.Error(`generated output contains "}});" -- the extra-closing-brace regression`)
	}
}

func TestTSWireQueryUsesOpenAPIParameterNames(t *testing.T) {
	params := []Param{
		{Name: "client_id", Type: &TypeSpec{Kind: KindString}},
		{Name: "include_disabled", Type: &TypeSpec{Kind: KindBoolean}},
	}
	want := `{ "client_id": query?.clientId, "include_disabled": query?.includeDisabled }`
	if got := tsWireQuery(params); got != want {
		t.Errorf("tsWireQuery() = %q, want %q", got, want)
	}
}

func TestTSClientAuthenticationOperations(t *testing.T) {
	cases := map[string]bool{
		"postToken":      true,
		"postIntrospect": true,
		"postRevoke":     true,
		"postPAR":        true,
		"postLogin":      false,
		"postLogout":     false,
	}
	for operationID, want := range cases {
		if got := tsUsesClientAuth(operationID); got != want {
			t.Errorf("tsUsesClientAuth(%q) = %v, want %v", operationID, got, want)
		}
	}
}

// TestPyFieldName_KeywordAndNonIdentifierMangling proves wire keys that are
// Python keywords (BootstrapAdvance.from, ClassifyResponse.class) or
// non-identifiers (SCIM's "$ref", extension-namespaced keys) get a
// deterministic, valid identifier — the generated client.py must parse, and
// the wire key is never changed (only the TypedDict attribute name).
func TestPyFieldName_KeywordAndNonIdentifierMangling(t *testing.T) {
	cases := map[string]string{
		"from":   "from_",
		"class":  "class_",
		"$ref":   "_ref",
		"value":  "value",
		"normal": "normal",
	}
	for in, want := range cases {
		if got := pyFieldName(in); got != want {
			t.Errorf("pyFieldName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSurfaceIncludesSVERPAdminReads(t *testing.T) {
	surface, err := loadSurface(filepath.Join("..", "..", defaultSurfacePath))
	if err != nil {
		t.Fatalf("loadSurface: %v", err)
	}
	for _, operationID := range []string{"adminLocalUserList", "permissionListRoles"} {
		if !surface[operationID] {
			t.Errorf("SDK surface does not include %q", operationID)
		}
	}
}

func TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport(t *testing.T) {
	reg := NewRegistry(docAny(map[string]interface{}{}))
	ops := []Operation{
		{
			ID: "postToken", Method: "post", Path: "/token", Tag: "auth", HasBody: true,
			BodyRequired: true, BodyType: &TypeSpec{Kind: KindRef, Name: "TokenRequest"},
		},
		{
			ID: "getMyPermissions", Method: "get", Path: "/permissions/me", Tag: "me",
			QueryParams: []Param{{Name: "client_id", Type: &TypeSpec{Kind: KindString}}},
		},
		{
			ID: "finishPasskey", Method: "post", Path: "/passkey", Tag: "auth", HasBody: true,
			BodyRequired: true, BodyType: &TypeSpec{Kind: KindObject},
			QueryParams: []Param{{Name: "session_id", Type: &TypeSpec{Kind: KindString}}},
		},
	}
	out := GenerateTS("Test", "1.0", reg, ops)
	for _, want := range []string{
		"export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;",
		"clientSecret?: string;",
		"requestTimeoutMs?: number;",
		`headers["Authorization"] = "Basic " + encodeBasicCredentials(clientId, clientSecret);`,
		"delete withoutCredentials.client_secret;",
		`{ body, clientAuth: true });`,
		`query: { "client_id": query?.clientId }`,
		"const init: RequestInit = { method, headers };",
		"init.signal = AbortSignal.timeout(this.requestTimeoutMs);",
		"async finishPasskey(body: Record<string, unknown>, query?: { sessionId?: string })",
		"for (const item of v) qs.append(k, String(item));",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("generated TypeScript missing %q", want)
		}
	}
	if strings.Contains(out, "{ method, headers, body }") {
		t.Error("generated TypeScript explicitly assigns an undefined body to RequestInit")
	}
	if strings.Contains(out, "fetch?: typeof fetch") {
		t.Error("generated TypeScript requires runtime-specific static fetch properties")
	}
}

// TestLoadSurface_FlattensAndRejectsDuplicates covers the registry loader:
// duplicate operationIds across groups must fail loud (the registry checker
// rejects them too, but the generator must not silently pick one).
func TestLoadSurface_FlattensAndRejectsDuplicates(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/surface.json"
	write := func(content string) {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"groups":[{"id":"a","operations":["x","y"]},{"id":"b","operations":["z"]}]}`)
	got, err := loadSurface(path)
	if err != nil {
		t.Fatalf("loadSurface: %v", err)
	}
	if len(got) != 3 || !got["x"] || !got["z"] {
		t.Errorf("loadSurface flattened = %v, want {x,y,z}", got)
	}
	write(`{"groups":[{"id":"a","operations":["x"]},{"id":"b","operations":["x"]}]}`)
	if _, err := loadSurface(path); err == nil {
		t.Fatal("loadSurface with duplicate operationId: want error")
	}
}
