// Command gensdk regenerates the consumer SDKs committed at
// docs/sdks/typescript/client.ts and docs/sdks/python/client.py from
// docs/openapi.yaml — the "multi-language SDK generation + developer
// portal" backlog item (docs/deferred-backlog.md).
//
// This is deliberately NOT a general-purpose OpenAPI-to-any-language
// codegen tool (that is what oapi-codegen/openapi-generator are for, and
// this repo's minimal-dependency philosophy rules out adding either as a
// build-time Go/Node dependency — see AGENTS.md). It is a small generator
// covering the operationId set declared in the committed SDK-surface
// registry ops/build/sdk-surface.json (core OAuth2/OIDC, token lifecycle,
// self-service, admin, SCIM, SSF and Federation — see
// docs/sdks/*/README.md) with a schema resolver that handles the shapes
// docs/openapi.yaml actually uses ($ref, arrays, objects, simple
// oneOf/single-entry allOf, additionalProperties maps) rather than the
// full JSON-Schema/OpenAPI object model.
//
// Regenerate after any docs/openapi.yaml or ops/build/sdk-surface.json
// change:
//
//	go run ./cmd/gensdk --lang=ts
//	go run ./cmd/gensdk --lang=py
//	go run ./cmd/gensdk --lang=all   # default
//
// The generator reads the SAME embedded spec (github.com/yangwb1123/snaplink/docs)
// the opt-in admin API-docs viewer (interfaces/apidocs, sso.WithAPIDocsUI)
// serves, so both stay in lockstep with docs/openapi.yaml without a
// separate copy. Pass --spec to point at a different file (e.g. while
// iterating on a not-yet-committed spec change) and --surface to point at
// a different sdk-surface registry.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"

	"github.com/yangwb1123/snaplink/docs"
)

var defaultSurfacePath = filepath.Join("ops", "build", "sdk-surface.json")

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "gensdk:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	opts, err := parseFlags(args)
	if err != nil {
		return err
	}
	surface, err := loadSurface(opts.surfacePath)
	if err != nil {
		return err
	}
	specBytes := docs.OpenAPISpec
	if opts.specPath != "" {
		specBytes, err = os.ReadFile(opts.specPath)
		if err != nil {
			return err
		}
	}
	doc, err := parseSpec(specBytes)
	if err != nil {
		return err
	}

	reg := NewRegistry(doc)
	ops := Extract(doc, reg, surface) // populates reg's named-schema set as a side effect
	info, _ := doc["info"].(map[string]interface{})
	title, version := stringField(info, "title"), stringField(info, "version")

	return generate(opts, title, version, reg, ops)
}

// generate dispatches to the requested emitter(s) — split out of run to
// keep it under the function-length budget.
func generate(opts cliOptions, title, version string, reg *Registry, ops []Operation) error {
	switch opts.lang {
	case "ts":
		return writeFile(opts.outTS, GenerateTS(title, version, reg, ops))
	case "py":
		return writeFile(opts.outPy, GeneratePython(title, version, reg, ops))
	case "all":
		if err := writeFile(opts.outTS, GenerateTS(title, version, reg, ops)); err != nil {
			return err
		}
		return writeFile(opts.outPy, GeneratePython(title, version, reg, ops))
	default:
		return fmt.Errorf("unknown --lang %q (want ts|py|all)", opts.lang)
	}
}

type cliOptions struct {
	lang        string
	specPath    string
	surfacePath string
	outTS       string
	outPy       string
}

func parseFlags(args []string) (cliOptions, error) {
	fs := flag.NewFlagSet("gensdk", flag.ContinueOnError)
	opts := cliOptions{surfacePath: defaultSurfacePath}
	fs.StringVar(&opts.lang, "lang", "all", "target language: ts | py | all")
	fs.StringVar(&opts.specPath, "spec", "", "override the OpenAPI spec path (default: the embedded docs.OpenAPISpec)")
	fs.StringVar(&opts.surfacePath, "surface", defaultSurfacePath, "path to the sdk-surface registry (ops/build/sdk-surface.json)")
	fs.StringVar(&opts.outTS, "out-ts", filepath.Join("docs", "sdks", "typescript", "client.ts"), "TypeScript output path")
	fs.StringVar(&opts.outPy, "out-py", filepath.Join("docs", "sdks", "python", "client.py"), "Python output path")
	if err := fs.Parse(args); err != nil {
		return cliOptions{}, err
	}
	return opts, nil
}

// parseSpec decodes YAML into a generic map, tolerating
// docs/openapi.yaml's one known duplicate top-level path key — see
// interfaces/apidocs.New's doc for why AllowDuplicateMapKey is required.
func parseSpec(b []byte) (map[string]interface{}, error) {
	var doc interface{}
	dec := yaml.NewDecoder(bytes.NewReader(b), yaml.AllowDuplicateMapKey())
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse openapi spec: %w", err)
	}
	m, ok := doc.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("openapi spec root is not a mapping")
	}
	return m, nil
}

func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "gensdk: wrote %s (%d bytes)\n", path, len(content))
	return nil
}
