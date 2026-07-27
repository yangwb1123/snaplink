// Package apidocs renders the repo's OpenAPI specification
// (docs/openapi.yaml, embedded at github.com/yangwb1123/snaplink/docs.OpenAPISpec)
// as a read-only, self-contained developer-documentation viewer — the
// embedded-docs-UI half of the "multi-language SDK generation + developer
// portal" backlog item (docs/deferred-backlog.md). Wired via
// sso.WithAPIDocsUI; see that option's doc for the admin-gating rationale.
//
// The viewer has NO external runtime dependency: no CDN script, no
// vendored Swagger-UI/Redoc bundle. It is a small hand-written
// HTML/CSS/vanilla-JS page (template.go) matching the style of the SDK's
// other embedded SPAs (interfaces/web/{admin,login,portal}). The OpenAPI
// document is parsed server-side ONCE (YAML -> JSON, via the goccy/go-yaml
// dependency already in go.mod — no new module dependency) and inlined
// into the page, so a saved copy (e.g. `curl -H "Authorization: Bearer
// $TOKEN" .../docs -o d.html`) renders fully offline.
package apidocs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/goccy/go-yaml"

	"github.com/yangwb1123/snaplink/shared/core"
)

// New parses specYAML (docs/openapi.yaml's bytes) once and returns the two
// admin-gated route handlers sso.WithAPIDocsUI wires: ui renders the
// self-contained HTML viewer, spec serves the same document as plain JSON
// (for Postman/Insomnia/curl, or cross-checking against cmd/gensdk's
// output). A parse error — only possible with a hand-edited, malformed
// spec, since the embedded docs.OpenAPISpec is validated by `make
// docs-validate` in CI — is returned so the caller can fail safe by
// leaving the feature unmounted rather than serving a broken page.
//
// AllowDuplicateMapKey tolerates docs/openapi.yaml's one known duplicate
// top-level path key (a bulk-revoke and a session-revoke handler are each
// documented, in two unrelated sections, under the same literal path);
// last value wins, matching ordinary lenient YAML/JSON parser behavior
// (e.g. the swaggerapi/swagger-ui image `make docs-serve` already uses).
func New(specYAML []byte) (ui core.HandlerFunc, spec core.HandlerFunc, err error) {
	var doc any
	dec := yaml.NewDecoder(bytes.NewReader(specYAML), yaml.AllowDuplicateMapKey())
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, fmt.Errorf("apidocs: parse openapi spec: %w", err)
	}
	specJSON, err := json.Marshal(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("apidocs: marshal openapi spec: %w", err)
	}
	title, version := specTitleVersion(doc)
	return handleUI(specJSON, title, version), handleSpec(doc), nil
}

// specTitleVersion best-effort extracts info.title/info.version for the
// viewer's <title>/header. Absent or malformed fields just fall back to
// empty strings rather than failing New over cosmetic metadata.
func specTitleVersion(doc any) (title, version string) {
	root, ok := doc.(map[string]interface{})
	if !ok {
		return "", ""
	}
	info, ok := root["info"].(map[string]interface{})
	if !ok {
		return "", ""
	}
	title, _ = info["title"].(string)
	version, _ = info["version"].(string)
	return title, version
}

// handleSpec serves the parsed document verbatim as JSON — the
// machine-readable companion to the HTML viewer. Cache-Control: no-store
// since it mirrors the live server's full endpoint + schema surface
// (operationally sensitive, same reasoning as every other
// /api/v1/admin/ route — see sso.WithAPIDocsUI).
func handleSpec(doc any) core.HandlerFunc {
	return func(ctx core.HandlerContext) {
		ctx.ResponseWriter().Header().Set("Cache-Control", "no-store")
		ctx.JSON(http.StatusOK, doc)
	}
}
