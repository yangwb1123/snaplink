// Package configcmd is the offline config-validation subcommand for sso-ctl.
// It loads a server config file through the SAME loader the server uses
// (file source -> defaults -> validate) so operators can catch config errors
// in CI / a deploy pre-check without starting the server.
//
// Subcommands:
//
//	sso-ctl config validate --file config.yaml
//	sso-ctl config validate --file config.yaml --print
//	sso-ctl config schema [--out schema.json]
//	sso-ctl config validate-schema --file config.yaml
//
// validate exits 0 when the config loads and passes validation, 1 otherwise.
// --print additionally dumps the fully-resolved config (after defaults are
// applied) as JSON, so operators can see exactly what the server would run.
//
// schema and validate-schema are implemented in schema.go — see its doc for
// how they relate to the warn-only schema check Loader.Load already runs on
// every boot.
package configcmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/yangwb1123/snaplink/config"
)

const progName = "sso-ctl config"

// Run is the config subcommand entry point. args has the leading program name
// stripped (the dispatcher's os.Args[2:]). It returns the process exit code.
func Run(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	switch args[0] {
	case "validate":
		return runValidate(args[1:])
	case "schema":
		return runSchema(args[1:])
	case "validate-schema":
		return runValidateSchema(args[1:])
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, progName+": unknown subcommand %q\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, progName+` — offline server-config validation.

Usage:
  `+progName+` validate --file <config.yaml> [--print]
  `+progName+` schema [--out <schema.json>]
  `+progName+` validate-schema --file <config.yaml>

Subcommands:
  validate         Load and validate a config file (same loader the server uses).
  schema           Print the generated JSON Schema for config.Config.
  validate-schema  Validate a config file against the generated schema; exits 1
                   on any violation (unknown key or type mismatch) — a strict
                   CI-gate sibling of the warn-only check the server runs on
                   every boot.

Flags:
  --file     Path to the config file (required for validate / validate-schema).
  --print    Also print the fully-resolved config (after defaults) as JSON.
  --out      Write the schema to a file instead of stdout (schema only).

Examples:
  `+progName+` validate --file ./config.yaml
  `+progName+` validate --file /etc/sso/config.yaml --print
  `+progName+` schema --out docs/config.schema.json
  `+progName+` validate-schema --file ./config.yaml`)
}

func runValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	file := fs.String("file", "", "path to the config file (required)")
	printResolved := fs.Bool("print", false, "print the fully-resolved config as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *file == "" {
		fmt.Fprintln(os.Stderr, progName+": --file is required")
		usage()
		return 2
	}

	cfg, err := config.Load(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, progName+": invalid config: %v\n", err)
		return 1
	}
	fmt.Printf("config OK: %s\n", *file)
	if *printResolved {
		if err := printConfig(os.Stdout, cfg); err != nil {
			fmt.Fprintf(os.Stderr, progName+": render config: %v\n", err)
			return 1
		}
	}
	return 0
}

// printConfig writes the resolved config as indented JSON. Factored out so the
// rendering is unit-testable without capturing os.Stdout.
func printConfig(w io.Writer, cfg *config.Config) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(cfg)
}
