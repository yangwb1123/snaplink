// Package docs embeds this repo's canonical OpenAPI specification
// (openapi.yaml) so a Go program can serve or parse it without a
// filesystem dependency at runtime. go:embed patterns cannot climb out of
// the directory containing the source file ("../" is rejected), so this
// is the only way to embed the file at its single, canonical location
// (docs/openapi.yaml) rather than maintaining a duplicate copy elsewhere —
// there is exactly one source of truth, and it stays validated by `make
// docs-validate` in CI.
//
// Two consumers import OpenAPISpec: interfaces/apidocs (the opt-in
// embedded API-docs viewer, sso.WithAPIDocsUI) and cmd/gensdk (the
// TypeScript/Python consumer-SDK generator). Both sit at a strictly higher
// layer rank than this package (see architecture_layer_test.go's
// layerName, which classifies the bare "docs" package as "shared" — rank
// 0 — since it has no internal imports of its own and is therefore safe
// for any layer to depend on).
package docs

import _ "embed"

// OpenAPISpec holds the raw bytes of openapi.yaml as of the build that
// compiled this package in.
//
//go:embed openapi.yaml
var OpenAPISpec []byte
