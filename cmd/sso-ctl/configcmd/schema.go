package configcmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/goccy/go-yaml"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/config/schema"
)

// runSchema implements `sso-ctl config schema`: emits the reflection-
// generated JSON Schema document describing config.Config's shape (the
// same Document config.Schema() feeds into Loader.Load's warn-only check),
// so operators can point an editor (e.g. the redhat.vscode-yaml extension)
// at it for autocompletion + typo-detection on their config.yaml, or feed
// it into any external JSON-Schema-aware tool.
func runSchema(args []string) int {
	fs := flag.NewFlagSet("schema", flag.ContinueOnError)
	out := fs.String("out", "", "write the schema to this file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	raw, err := json.MarshalIndent(config.Schema(), "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, progName+": render schema: %v\n", err)
		return 1
	}
	raw = append(raw, '\n')

	if *out == "" {
		if _, err := os.Stdout.Write(raw); err != nil {
			fmt.Fprintf(os.Stderr, progName+": write schema: %v\n", err)
			return 1
		}
		return 0
	}
	if err := os.WriteFile(*out, raw, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, progName+": write %s: %v\n", *out, err)
		return 1
	}
	fmt.Printf("schema written: %s\n", *out)
	return 0
}

// runValidateSchema implements `sso-ctl config validate-schema`: parses the
// file's raw YAML into the same map[string]any shape Loader.Load merges
// Sources into, then runs schema.Validate directly — unlike Loader.Load's
// own warn-only pass (see config/source.go), THIS command treats every
// violation as fatal (exit 1), because it's an explicit, operator-invoked
// check (a CI / pre-deploy gate), not something that could unexpectedly
// break an existing production boot the way promoting Loader.Load's check
// to a hard failure would risk (see schema.Validate's doc).
//
// Deliberately validates the file in isolation (no env/etcd/flag layers) —
// this is a "does this YAML document's shape match config.Config" check,
// independent of what a specific deployment's environment happens to
// override.
func runValidateSchema(args []string) int {
	fs := flag.NewFlagSet("validate-schema", flag.ContinueOnError)
	file := fs.String("file", "", "path to the config file (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *file == "" {
		fmt.Fprintln(os.Stderr, progName+": --file is required")
		usage()
		return 2
	}

	data, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, progName+": read %s: %v\n", *file, err)
		return 1
	}
	merged := map[string]any{}
	if err := yaml.Unmarshal(data, &merged); err != nil {
		fmt.Fprintf(os.Stderr, progName+": parse %s: %v\n", *file, err)
		return 1
	}

	violations := schema.Validate(config.Schema(), merged)
	if len(violations) == 0 {
		fmt.Printf("schema OK: %s\n", *file)
		return 0
	}
	fmt.Fprintf(os.Stderr, progName+": %d schema violation(s) in %s:\n", len(violations), *file)
	for _, v := range violations {
		fmt.Fprintf(os.Stderr, "  - %s\n", v.String())
	}
	return 1
}
