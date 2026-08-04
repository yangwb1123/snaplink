package main

import "sort"

// Param is one path or query parameter.
type Param struct {
	Name     string
	In       string // "path" | "query"
	Required bool
	Type     *TypeSpec
	Doc      string
}

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
}

// coreSurface is the curated, hand-scoped operationId allowlist this
// generator emits clients for — the "pragmatic subset" the SDKs cover
// (see docs/sdks/*/README.md for the full rationale of what's in vs.
// deferred). Grouped by theme purely for readability here; extraction
// order is re-derived from the spec (by tag, then path) in Extract.
var coreSurface = map[string]bool{
	// Discovery.
	"getJWKS": true, "getOpenIDConfiguration": true, "getOAuthAuthorizationServerMetadata": true,
	// Core OAuth2/OIDC auth + token lifecycle.
	"postLogin": true, "postMFAComplete": true, "postSendCode": true,
	"postToken": true, "postIntrospect": true, "postRevoke": true, "postRevokeAll": true,
	"postPAR": true, "postDeviceCode": true, "postDeviceVerify": true,
	"postRegister": true, "getRegistration": true, "putRegistration": true, "deleteRegistration": true,
	"postLogout": true, "getUserInfo": true,
	// Self-service (/me* family).
	"getMe": true, "patchMe": true, "changeMyPassword": true, "listMyMFAFactors": true,
	"listMySessions": true, "revokeMySessions": true, "listMyConsents": true,
	"getMyPermissions": true, "getMyRoles": true, "getMyMenus": true,
	// Small representative admin sample (see README — NOT the full ~150-route
	// grpc-gateway-generated admin CRUD surface).
	"getClientByID": true, "getAdminEndpoints": true, "queryAuditEvents": true,
	"adminLocalUserList": true, "permissionListRoles": true,
}

var httpMethods = []string{"get", "post", "put", "patch", "delete"}

// Extract walks doc.paths and returns one Operation per coreSurface
// operationId found, resolving its parameters/request body/success
// response against reg. Sorted by (tag, path, method) for deterministic
// output.
func Extract(doc map[string]interface{}, reg *Registry) []Operation {
	paths, _ := doc["paths"].(map[string]interface{})
	var ops []Operation
	for path, rawItem := range paths {
		item, _ := rawItem.(map[string]interface{})
		itemParams, _ := item["parameters"].([]interface{})
		for _, method := range httpMethods {
			if op, ok := extractOne(path, method, item, itemParams, reg); ok {
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
// path+method isn't in coreSurface (or doesn't exist).
func extractOne(path, method string, item map[string]interface{}, itemParams []interface{}, reg *Registry) (Operation, bool) {
	rawOp, ok := item[method].(map[string]interface{})
	if !ok {
		return Operation{}, false
	}
	id, _ := rawOp["operationId"].(string)
	if !coreSurface[id] {
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
	op.BodyType, op.BodyRequired, op.HasBody = extractRequestBody(rawOp, reg)
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

// contentSchema picks a requestBody/response's schema, preferring
// application/json (every curated operation's JSON variant is either the
// only content type or byte-identical to its form-urlencoded sibling —
// see docs/sdks/*/README.md) over any other declared content type.
func contentSchema(content map[string]interface{}) map[string]interface{} {
	for _, ct := range [...]string{"application/json", "application/x-www-form-urlencoded"} {
		if entry, ok := content[ct].(map[string]interface{}); ok {
			if schema, ok := entry["schema"].(map[string]interface{}); ok {
				return schema
			}
		}
	}
	return nil
}

func extractRequestBody(op map[string]interface{}, reg *Registry) (*TypeSpec, bool, bool) {
	rb, ok := op["requestBody"].(map[string]interface{})
	if !ok {
		return nil, false, false
	}
	required, _ := rb["required"].(bool)
	content, _ := rb["content"].(map[string]interface{})
	schema := contentSchema(content)
	if schema == nil {
		return nil, required, true
	}
	return reg.Resolve(schema), required, true
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
