package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// surfaceRegistry is the committed SDK-surface file
// (ops/build/sdk-surface.json): the operationId allowlist grouped by
// surface, capability linkage and language compatibility policy. The
// generator reads ONLY this file for its selection — there is no
// second allowlist in code (the previous hand-scoped coreSurface map
// was removed when the registry landed).
type surfaceRegistry struct {
	Groups []struct {
		ID         string   `json:"id"`
		Name       string   `json:"name"`
		Capability *string  `json:"capability"`
		Operations []string `json:"operations"`
	} `json:"groups"`
}

// loadSurface reads + flattens the registry into the operationId set.
func loadSurface(path string) (map[string]bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read sdk-surface registry: %w", err)
	}
	var reg surfaceRegistry
	if err := json.Unmarshal(raw, &reg); err != nil {
		return nil, fmt.Errorf("parse sdk-surface registry %s: %w", path, err)
	}
	set := map[string]bool{}
	for _, g := range reg.Groups {
		for _, id := range g.Operations {
			if set[id] {
				return nil, fmt.Errorf("sdk-surface registry %s: operationId %q appears in more than one group", path, id)
			}
			set[id] = true
		}
	}
	return set, nil
}

// Param is one path or query parameter.
type Param struct {
	Name     string
	In       string // "path" | "query"
	Required bool
	Type     *TypeSpec
	Doc      string
}

// formContentType is the wire content type of the OAuth credential
// family (RFC 6749 §3.2 and the token/introspection/revocation/PAR/
// device/MFA siblings). The generator prefers it over JSON for request
// bodies whenever the spec declares both, so generated clients survive
// Content-Type enforcement (B4-4) without server changes.
const formContentType = "application/x-www-form-urlencoded"

// Operation is one curated, extracted endpoint — everything a language
// emitter needs to generate one client method.
type Operation struct {
	ID           string // operationId, used verbatim as the generated method name
	Method       string // GET/POST/PUT/PATCH/DELETE
	Path         string // e.g. /token, /register/{client_id}
	Summary      string
	Tag          string
	PathParams   []Param
	QueryParams  []Param
	HasBody      bool
	BodyRequired bool
	BodyType     *TypeSpec
	ResultType   *TypeSpec // nil => no response body (void/None)
	RequiresAuth bool
	// ContentType is the request-body content type to emit:
	// formContentType for the credential family, empty = JSON (the
	// status quo for every JSON-only operation). Schema-driven via the
	// declared request-body content map — deliberately NOT the
	// tsUsesClientAuth hard-coded list, which omits postDeviceCode/
	// postDeviceVerify/postMFAComplete.
	ContentType string
	// FormBlockedFields names request-body fields that have no form
	// representation (resolved schema Kind == KindMap: e.g.
	// MFACompleteRequest.params). No RFC defines a form encoding for
	// maps, so generated clients fail loud client-side on their
	// presence instead of attempting a wire the server rejects.
	FormBlockedFields []string
}

// coreSurface is the operationId allowlist this generator emits clients
// for, loaded from the committed SDK-surface registry
// (ops/build/sdk-surface.json, validated by `cli.py sdk-surface check`)
// rather than a hard-coded Go map — see the package doc. The registry
// groups operations by surface (discovery, oauth-core, self-service,
// admin, scim, ssf, federation, ...), links each group to a capability in
// ops/build/capabilities.json where one exists, and carries the per-
// language compatibility policy. loadSurface returns the flattened set;
// every id MUST exist in docs/openapi.yaml (the checker enforces it).
var coreSurface map[string]bool

var httpMethods = []string{"get", "post", "put", "patch", "delete"}

// Extract walks doc.paths and returns one Operation per allowed
// operationId (from the sdk-surface registry), resolving its
// parameters/request body/success response against reg. Sorted by
// (tag, path, method) for deterministic output.
func Extract(doc map[string]interface{}, reg *Registry, allowed map[string]bool) []Operation {
	paths, _ := doc["paths"].(map[string]interface{})
	var ops []Operation
	for path, rawItem := range paths {
		item, _ := rawItem.(map[string]interface{})
		itemParams, _ := item["parameters"].([]interface{})
		for _, method := range httpMethods {
			if op, ok := extractOne(path, method, item, itemParams, reg, allowed); ok {
				ops = append(ops, op)
			}
		}
	}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Tag != ops[j].Tag {
			return ops[i].Tag < ops[j].Tag
		}
		if ops[i].Path != ops[j].Path {
			return ops[i].Path < ops[j].Path
		}
		return ops[i].Method < ops[j].Method
	})
	return ops
}

// extractOne builds one Operation, returning ok==false when this
// path+method isn't in the allowed surface (or doesn't exist).
func extractOne(path, method string, item map[string]interface{}, itemParams []interface{}, reg *Registry, allowed map[string]bool) (Operation, bool) {
	rawOp, ok := item[method].(map[string]interface{})
	if !ok {
		return Operation{}, false
	}
	id, _ := rawOp["operationId"].(string)
	if !allowed[id] {
		return Operation{}, false
	}
	op := Operation{
		ID:           id,
		Method:       method,
		Path:         path,
		Summary:      stringField(rawOp, "summary"),
		Tag:          firstTag(rawOp),
		RequiresAuth: rawOp["security"] != nil,
	}
	allParams := append(append([]interface{}{}, itemParams...), asSlice(rawOp["parameters"])...)
	splitParams(&op, allParams, reg)
	op.BodyType, op.BodyRequired, op.HasBody, op.ContentType = extractRequestBody(rawOp, reg)
	// ContentType is empty for the JSON wire (the design's zero value);
	// only the form variant is recorded.
	if op.ContentType == "application/json" {
		op.ContentType = ""
	}
	// FormBlockedFields is only meaningful on the form wire: a map field
	// is expressible in JSON, so JSON-only operations keep nil (the
	// design pins "empty for every other op").
	if op.ContentType == formContentType {
		op.FormBlockedFields = formBlockedFields(op.BodyType, reg)
	}
	op.ResultType = extractResult(rawOp, reg)
	return op, true
}

func asSlice(v any) []interface{} {
	s, _ := v.([]interface{})
	return s
}

func firstTag(op map[string]interface{}) string {
	tags := asSlice(op["tags"])
	if len(tags) == 0 {
		return "other"
	}
	s, _ := tags[0].(string)
	if s == "" {
		return "other"
	}
	return s
}

// splitParams resolves each raw parameter node into a Param and files it
// under op.PathParams or op.QueryParams. Path parameters are REQUIRED per
// the OpenAPI 3.0 spec regardless of whether `required` is restated.
func splitParams(op *Operation, raw []interface{}, reg *Registry) {
	for _, r := range raw {
		m, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		in, _ := m["in"].(string)
		required, _ := m["required"].(bool)
		if in == "path" {
			required = true
		}
		schema, _ := m["schema"].(map[string]interface{})
		p := Param{
			Name:     stringField(m, "name"),
			In:       in,
			Required: required,
			Type:     reg.Resolve(schema),
			Doc:      firstLine(stringField(m, "description")),
		}
		switch in {
		case "path":
			op.PathParams = append(op.PathParams, p)
		case "query":
			op.QueryParams = append(op.QueryParams, p)
		}
	}
}

// contentTypeOf returns the content type to emit for a request
// body/response content map: form-urlencoded first (the RFC-mandated
// wire for the OAuth credential family), application/json as the
// fallback. Safe because every dual-content operation's variants are
// byte-identical $refs — the preference only decides which wire the
// generated client emits, never which schema is resolved.
func contentTypeOf(content map[string]interface{}) string {
	for _, ct := range [...]string{formContentType, "application/json"} {
		if entry, ok := content[ct].(map[string]interface{}); ok {
			if _, ok := entry["schema"].(map[string]interface{}); ok {
				return ct
			}
		}
	}
	return ""
}

// contentSchema picks a requestBody/response's schema, preferring
// form-urlencoded (see contentTypeOf) over any other declared content
// type. Zero responses in the spec declare the form variant, so
// response resolution is provably unaffected by the preference.
func contentSchema(content map[string]interface{}) map[string]interface{} {
	ct := contentTypeOf(content)
	if ct == "" {
		return nil
	}
	entry, _ := content[ct].(map[string]interface{})
	schema, _ := entry["schema"].(map[string]interface{})
	return schema
}

func extractRequestBody(op map[string]interface{}, reg *Registry) (*TypeSpec, bool, bool, string) {
	rb, ok := op["requestBody"].(map[string]interface{})
	if !ok {
		return nil, false, false, ""
	}
	required, _ := rb["required"].(bool)
	content, _ := rb["content"].(map[string]interface{})
	ct := contentTypeOf(content)
	schema := contentSchema(content)
	if schema == nil {
		return nil, required, true, ct
	}
	return reg.Resolve(schema), required, true, ct
}

// formBlockedFields returns the request-body field names that have no
// form-urlencoded representation: fields whose resolved schema is a
// KindMap (additionalProperties-only). Schema-driven, so a future map
// field is picked up here with no emitter change; today exactly
// MFACompleteRequest.params matches (KindMap — a bare `type: object`
// like PARRequest.claims is KindObject and stays form-expressible as a
// JSON-string key, per RFC 9396 §3 / OIDC Core §5.5).
func formBlockedFields(t *TypeSpec, reg *Registry) []string {
	if t == nil {
		return nil
	}
	obj := derefNamed(t, reg)
	if obj.Kind != KindObject {
		return nil
	}
	var out []string
	for _, f := range obj.Fields {
		if derefNamed(f.Type, reg).Kind == KindMap {
			out = append(out, f.Name)
		}
	}
	return out
}

// derefNamed resolves a KindRef to its named body, falling back to the
// ref stub itself when the name is unknown (dangling $ref).
func derefNamed(t *TypeSpec, reg *Registry) *TypeSpec {
	if t.Kind != KindRef {
		return t
	}
	if named := reg.NamedType(t.Name); named != nil {
		return named
	}
	return t
}

// extractResult resolves the first (lowest-numbered) 2xx response that
// carries a body schema; a 2xx with no content (e.g. postRevoke's bare
// 200, DELETE's 204) or no 2xx at all yields nil (void/None).
func extractResult(op map[string]interface{}, reg *Registry) *TypeSpec {
	responses, _ := op["responses"].(map[string]interface{})
	var codes []string
	for code := range responses {
		if len(code) > 0 && code[0] == '2' {
			codes = append(codes, code)
		}
	}
	sort.Strings(codes)
	for _, code := range codes {
		r, _ := responses[code].(map[string]interface{})
		content, _ := r["content"].(map[string]interface{})
		if schema := contentSchema(content); schema != nil {
			return reg.Resolve(schema)
		}
	}
	return nil
}
