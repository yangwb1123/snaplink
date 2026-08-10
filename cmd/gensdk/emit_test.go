package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/docs"
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

// realExtract runs Extract over the real spec and surface registry —
// the exact inputs the generator's main() uses — so the content-type
// and blocked-field assertions below are pinned to the shipped
// contracts, not to synthetic fixtures.
func realExtract(t *testing.T) ([]Operation, *Registry) {
	t.Helper()
	surface, err := loadSurface(filepath.Join("..", "..", defaultSurfacePath))
	if err != nil {
		t.Fatalf("loadSurface: %v", err)
	}
	doc, err := parseSpec(docs.OpenAPISpec)
	if err != nil {
		t.Fatalf("parseSpec: %v", err)
	}
	reg := NewRegistry(doc)
	return Extract(doc, reg, surface), reg
}

// TestContentTypeSelection (AC2(a)) pins the schema-driven form
// selection: exactly the seven credential-family operations get
// formContentType; JSON-only ops, the body-less postRevokeAll, and the
// two admin compromise ops (reconciliation D3 exclusion) stay empty;
// postBackchannelAuthentication is dual-content but out of the surface.
func TestContentTypeSelection(t *testing.T) {
	ops, _ := realExtract(t)
	byID := map[string]Operation{}
	for _, op := range ops {
		byID[op.ID] = op
	}
	for _, id := range []string{"postToken", "postIntrospect", "postRevoke", "postPAR", "postDeviceCode", "postDeviceVerify", "postMFAComplete"} {
		op, ok := byID[id]
		if !ok {
			t.Fatalf("surface op %q missing from Extract output", id)
		}
		if op.ContentType != formContentType {
			t.Errorf("%s ContentType = %q, want %q", id, op.ContentType, formContentType)
		}
		if !op.HasBody {
			t.Errorf("%s: expected HasBody", id)
		}
	}
	for _, id := range []string{"postLogin", "postRegister", "postRevokeAll", "adminCompromiseCredential", "adminReportCryptoKeyCompromise"} {
		op, ok := byID[id]
		if !ok {
			t.Fatalf("surface op %q missing from Extract output", id)
		}
		if op.ContentType != "" {
			t.Errorf("%s ContentType = %q, want empty (JSON)", id, op.ContentType)
		}
	}
	if op := byID["postRevokeAll"]; op.HasBody {
		t.Error("postRevokeAll must stay body-less (no requestBody in the spec)")
	}
	if _, ok := byID["postBackchannelAuthentication"]; ok {
		t.Error("postBackchannelAuthentication must not be in the SDK surface")
	}
	// MFACompleteRequest.params is the only map-typed body field in the
	// whole surface; every other operation has no form-blocked field.
	for _, op := range ops {
		want := []string(nil)
		if op.ID == "postMFAComplete" {
			want = []string{"params"}
		}
		if !reflect.DeepEqual(op.FormBlockedFields, want) {
			t.Errorf("%s FormBlockedFields = %v, want %v", op.ID, op.FormBlockedFields, want)
		}
	}
}

// TestGenerateTS_FormBranch (AC2(b)) pins the generated TypeScript: the
// URLSearchParams branch, the exact form header (no charset), the
// undefined-skip, Basic-strip-before-serialize ordering, the form flag
// on all seven ops, and the presence-based params guard.
func TestGenerateTS_FormBranch(t *testing.T) {
	ops, reg := realExtract(t)
	out := GenerateTS("Test", "1.0", reg, ops)
	for _, want := range []string{
		`headers["Content-Type"] = "application/x-www-form-urlencoded";`,
		"function formSerialize(body: Record<string, unknown>, blockedFields: string[]): string {",
		"if (blocked.has(k) || v === undefined || v === null) continue;",
		"for (const item of v) params.append(k, item);",
		"params.set(k, JSON.stringify(v));",
		"init.body = formSerialize(authenticatedBody as Record<string, unknown>, opts.formBlockedFields ?? []);",
		// All seven credential ops carry the form flag (spec-driven, not
		// the tsUsesClientAuth list which omits three of them).
		"(\"POST\", `/token`, { body, clientAuth: true, form: true });",
		"(\"POST\", `/token/introspect`, { body, clientAuth: true, form: true });",
		"(\"POST\", `/token/revoke`, { body, clientAuth: true, form: true });",
		"(\"POST\", `/par`, { body, clientAuth: true, form: true });",
		"(\"POST\", `/device/code`, { body, form: true });",
		"(\"POST\", `/device/verify`, { body, auth: true, form: true });",
		// C1 guard with presence semantics + defense-in-depth skip.
		"if (body.params !== undefined && body.params !== null) {",
		`"params has no application/x-www-form-urlencoded encoding; use code/assertion"`,
		`{ body, form: true, formBlockedFields: ["params"] });`,
		// Unchanged surfaces: JSON-only postLogin, body-less postRevokeAll.
		"`/auth/login`, { body });",
		"`/token/revoke-all`, { auth: true });",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("generated TypeScript missing %q", want)
		}
	}
	// JSON-only operations must NOT gain the params-style guard: a map
	// field is only blocked on the form wire (tenantCreate.settings,
	// adminUserCreate.attributes etc. keep working over JSON).
	for _, leak := range []string{"body.settings !== undefined", "body.attributes !== undefined", "body.branding !== undefined"} {
		if strings.Contains(out, leak) {
			t.Errorf("guard leaked onto a JSON-only operation (%q)", leak)
		}
	}
	// Basic-strip runs before serialization in the runtime const.
	authIdx := strings.Index(out, "this.withClientAuthentication(opts.body, headers)")
	formIdx := strings.Index(out, "formSerialize(authenticatedBody")
	if authIdx < 0 || formIdx < 0 || authIdx > formIdx {
		t.Errorf("withClientAuthentication (idx %d) must precede formSerialize (idx %d)", authIdx, formIdx)
	}
}

// TestGeneratePy_FormBranch (AC2(c)) pins the generated Python: the
// _form_encode runtime, the form flag on the seven ops, the C1 guard,
// body credentials retained in post_token (Python has no Basic path),
// and the unchanged JSON-only/body-less methods.
func TestGeneratePy_FormBranch(t *testing.T) {
	ops, reg := realExtract(t)
	out := GeneratePython("Test", "1.0", reg, ops)
	for _, want := range []string{
		"def _form_encode(body: Dict[str, Any], blocked_fields: Optional[List[str]] = None) -> str:",
		`headers["Content-Type"] = "application/x-www-form-urlencoded"`,
		`data = _form_encode(body, form_blocked_fields).encode("utf-8")`,
		"return urllib.parse.urlencode(encoded, doseq=True)",
		`encoded[key] = "true" if value else "false"`,
		// All seven ops carry form=True; post_token keeps the body
		// credentials (Python has no Basic-strip path — C5).
		`return self._request("POST", "/token", body=body, form=True)`,
		`return self._request("POST", "/token/introspect", body=body, form=True)`,
		`return self._request("POST", "/token/revoke", body=body, form=True)`,
		`return self._request("POST", "/par", body=body, form=True)`,
		`return self._request("POST", "/device/code", body=body, form=True)`,
		`return self._request("POST", "/device/verify", body=body, form=True, auth=True)`,
		// C1 guard with presence semantics + defense-in-depth skip.
		`if body.get("params") is not None:`,
		`raise SSOError(0, "invalid_request", "params has no application/x-www-form-urlencoded encoding; use code/assertion")`,
		`return self._request("POST", "/auth/mfa", body=body, form=True, form_blocked_fields=["params"])`,
		// Unchanged surfaces: JSON-only post_login, body-less post_revoke_all.
		`return self._request("POST", "/auth/login", body=body)`,
		`return self._request("POST", "/token/revoke-all", auth=True)`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("generated Python missing %q", want)
		}
	}
	// No guard on JSON-only ops with map fields.
	for _, leak := range []string{`body.get("settings")`, `body.get("attributes")`, `body.get("branding")`} {
		if strings.Contains(out, leak) {
			t.Errorf("guard leaked onto a JSON-only operation (%q)", leak)
		}
	}
}

// pyFormGolden is one behavioral _form_encode case: the body, the
// blocked-fields list, the exact raw encoding, and the parse_qs-decoded
// value map (repeated keys collapse to lists; blank values kept).
type pyFormGolden struct {
	Body    map[string]any      `json:"body"`
	Blocked []string            `json:"blocked"`
	Raw     string              `json:"raw"`
	Parsed  map[string][]string `json:"parsed"`
}

// TestFormEncode_PythonBehavior (AC2(c)/G3) executes the generated
// _form_encode with real python3 — string-presence assertions cannot
// prove coercion (a `v is True` typo would pass them). No t.Skip: a
// missing python3 fails the test, it does not pass silently.
func TestFormEncode_PythonBehavior(t *testing.T) {
	ops, reg := realExtract(t)
	out := GeneratePython("Test", "1.0", reg, ops)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "client.py"), []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	goldens := map[string]pyFormGolden{
		"bool_true":       {Body: map[string]any{"approve": true}, Raw: "approve=true", Parsed: map[string][]string{"approve": {"true"}}},
		"bool_false":      {Body: map[string]any{"approve": false}, Raw: "approve=false", Parsed: map[string][]string{"approve": {"false"}}},
		"repeated":        {Body: map[string]any{"resource": []any{"a", "b"}}, Raw: "resource=a&resource=b", Parsed: map[string][]string{"resource": {"a", "b"}}},
		"empty_elem":      {Body: map[string]any{"resource": []any{""}}, Raw: "resource=", Parsed: map[string][]string{"resource": {""}}},
		"empty_arr":       {Body: map[string]any{"resource": []any{}}, Raw: "", Parsed: map[string][]string{}},
		"none_drop":       {Body: map[string]any{"code": nil, "grant_type": "client_credentials"}, Raw: "grant_type=client_credentials", Parsed: map[string][]string{"grant_type": {"client_credentials"}}},
		"body_creds":      {Body: map[string]any{"client_id": "c", "client_secret": "s", "grant_type": "client_credentials"}, Raw: "client_id=c&client_secret=s&grant_type=client_credentials", Parsed: map[string][]string{"client_id": {"c"}, "client_secret": {"s"}, "grant_type": {"client_credentials"}}},
		"claims_json":     {Body: map[string]any{"claims": map[string]any{"userinfo": map[string]any{"email": nil}}}, Parsed: map[string][]string{"claims": {`{"userinfo": {"email": null}}`}}},
		"authz_details":   {Body: map[string]any{"authorization_details": []any{map[string]any{"type": "payment_initiation"}}}, Parsed: map[string][]string{"authorization_details": {`[{"type": "payment_initiation"}]`}}},
		"blocked_skipped": {Body: map[string]any{"params": map[string]any{"a": "b"}}, Blocked: []string{"params"}, Raw: "", Parsed: map[string][]string{}},
		"blocked_none":    {Body: map[string]any{"params": nil}, Blocked: []string{"params"}, Raw: "", Parsed: map[string][]string{}},
	}
	raw, err := json.Marshal(goldens)
	if err != nil {
		t.Fatal(err)
	}
	casesPath := filepath.Join(dir, "cases.json")
	if err := os.WriteFile(casesPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	script := `
import json
import sys
import urllib.parse
sys.path.insert(0, sys.argv[1])
from client import _form_encode
cases = json.load(open(sys.argv[2]))
for name, case in cases.items():
    got = _form_encode(case["body"], case.get("blocked"))
    parsed = urllib.parse.parse_qs(got, keep_blank_values=True)
    print(name + "\t" + got + "\t" + json.dumps(parsed, sort_keys=True))
`
	outB, err := exec.Command("python3", "-c", script, dir, casesPath).CombinedOutput()
	if err != nil {
		t.Fatalf("python3 run failed: %v\n%s", err, outB)
	}
	byName := map[string]struct {
		raw    string
		parsed map[string][]string
	}{}
	for _, line := range strings.Split(strings.TrimSpace(string(outB)), "\n") {
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			t.Fatalf("unexpected python output line %q", line)
		}
		var parsed map[string][]string
		if err := json.Unmarshal([]byte(parts[2]), &parsed); err != nil {
			t.Fatalf("unparseable parsed output %q: %v", parts[2], err)
		}
		byName[parts[0]] = struct {
			raw    string
			parsed map[string][]string
		}{parts[1], parsed}
	}
	for name, want := range goldens {
		got, ok := byName[name]
		if !ok {
			t.Errorf("case %s: no output (python lines: %d)", name, len(byName))
			continue
		}
		if want.Raw != "" && got.raw != want.Raw {
			t.Errorf("case %s: raw = %q, want %q", name, got.raw, want.Raw)
		}
		if want.Parsed != nil && !reflect.DeepEqual(got.parsed, want.Parsed) {
			t.Errorf("case %s: parsed = %v, want %v", name, got.parsed, want.Parsed)
		}
	}
}

// TestMFACompleteParamsGuard_Executes (AC2(c)/D4) runs the generated
// post_mfa_complete through real python3: params present (even {})
// throws client-side SSOError with no wire attempt; params None is
// treated as absent (JSON-wire null equivalence).
func TestMFACompleteParamsGuard_Executes(t *testing.T) {
	ops, reg := realExtract(t)
	out := GeneratePython("Test", "1.0", reg, ops)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "client.py"), []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	script := `
import sys
sys.path.insert(0, sys.argv[1])
from client import SSOClient, SSOError
c = SSOClient("http://127.0.0.1:1")  # unreachable: guard must fire pre-flight
try:
    c.post_mfa_complete({"params": {}, "mfa_challenge_id": "c", "mfa_method": "totp"})
    print("RESULT NO-THROW")
except SSOError as e:
    print("RESULT THREW %d %s" % (e.status, e.error))
`
	outB, err := exec.Command("python3", "-c", script, dir).CombinedOutput()
	if err != nil {
		t.Fatalf("python3 run failed: %v\n%s", err, outB)
	}
	if want := "RESULT THREW 0 invalid_request"; !strings.Contains(string(outB), want) {
		t.Errorf("params guard output = %q, want %q", strings.TrimSpace(string(outB)), want)
	}
}
