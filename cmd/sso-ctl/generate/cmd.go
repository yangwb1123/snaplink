// Package generate provides scaffolding for common component patterns.
// It generates boilerplate code for authenticators, stores, handlers, and grants,
// following the established architectural patterns in the codebase.
//
// Usage:
//
//	sso-ctl generate authenticator --name totp --package authenticators --desc "TOTP time-based one-time passwords"
//	sso-ctl generate store --name redis --package infrastructure/redis --desc "Redis-backed storage"
//	sso-ctl generate handler --name custom-auth --package internal/handler --desc "custom authentication endpoint"
//	sso-ctl generate grant --name device-code --package protocols/grants --desc "RFC 8628 device authorization grant"
//
// A grant scaffold's --package MUST NOT be protocols/oauth itself: the
// generated file imports "github.com/snaplink/sso/protocols/oauth" for its
// oauth.TokenRequest parameter, and a package cannot import itself. Any
// sibling package works (protocols/grants above is a suggestion, not a
// requirement) — it just needs to live at or above the protocols layer
// rank so importing protocols/oauth doesn't violate the dependency
// direction gate (see architecture_layer_test.go).
package generate

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const progName = "sso-ctl generate"

// Run is the generate subcommand entry point. args has the leading program name
// stripped; returns the process exit code.
func Run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}

	compType := args[0]
	remaining := args[1:]

	switch compType {
	case "authenticator", "store", "handler", "grant":
		return runGenerate(compType, remaining)
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown component type %q\n", progName, compType)
		usage()
		return 2
	}
}

func runGenerate(compType string, args []string) int {
	fs := flag.NewFlagSet(progName+" "+compType, flag.ExitOnError)
	name := fs.String("name", "", "Component name (e.g., totp, redis, custom-auth)")
	pkg := fs.String("package", "", "Target package path (e.g., authenticators, infrastructure/redis)")
	desc := fs.String("desc", "", "Brief description of the component")
	output := fs.String("output", "", "Output directory (default: inferred from package)")
	skipBuildCheck := fs.Bool("skip-build-check", false,
		"Skip running 'go build' on the generated output (on by default: a scaffold that doesn't compile defeats the point of scaffolding)")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progName, err)
		return 2
	}
	if code, ok := validateGenerateFlags(*name, *pkg); !ok {
		return code
	}
	if *desc == "" {
		*desc = *name + " component"
	}

	// Infer output directory from package path if not specified.
	if *output == "" {
		*output = inferOutputDir(*pkg)
	}

	scaffold := NewScaffold(compType, *name, *pkg, *desc)
	if err := scaffold.Generate(*output); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progName, err)
		return 1
	}
	printGenerateSuccess(compType, *name, *pkg, *output)

	if !*skipBuildCheck {
		if err := verifyGeneratedBuild(*output); err != nil {
			fmt.Fprintf(os.Stderr, "\n%s: generated output does not compile:\n%v\n", progName, err)
			fmt.Fprintln(os.Stderr, "(this is a template bug, not something you wrote yet — re-run with --skip-build-check to keep the files anyway)")
			return 1
		}
	}

	printNextSteps()
	return 0
}

// validateGenerateFlags checks the required --name/--package flags, printing
// a usage error and returning the process exit code when invalid. The bool
// return reports whether validation passed (false means the caller must
// return the accompanying exit code immediately).
func validateGenerateFlags(name, pkg string) (int, bool) {
	if name == "" {
		fmt.Fprintf(os.Stderr, "%s: --name is required\n", progName)
		return 2, false
	}
	if pkg == "" {
		fmt.Fprintf(os.Stderr, "%s: --package is required\n", progName)
		return 2, false
	}
	return 0, true
}

// printGenerateSuccess reports the files a Generate call produced.
func printGenerateSuccess(compType, name, pkg, output string) {
	fmt.Printf("\n✓ Successfully generated %s scaffold\n", compType)
	fmt.Printf("  Name: %s\n", name)
	fmt.Printf("  Package: %s\n", pkg)
	fmt.Printf("  Output: %s\n", output)
}

// printNextSteps prints the operator follow-up checklist after a scaffold
// (and its build check, if not skipped) has succeeded.
func printNextSteps() {
	fmt.Println("\nNext steps:")
	fmt.Println("  1. Review the generated code and fill in the TODO sections")
	fmt.Println("  2. Implement the business logic in the marked sections")
	fmt.Println("  3. Write unit tests for the new component")
	fmt.Println("  4. Wire the component into the server (see docs/developer-guide.md)")
}

// inferOutputDir maps a package path to a filesystem directory.
// This follows the codebase's architectural layering.
func inferOutputDir(pkg string) string {
	// Map common package patterns to directories.
	switch {
	case strings.HasPrefix(pkg, "authenticator"):
		return filepath.Join("domains", "authenticators")
	case strings.HasPrefix(pkg, "infrastructure"):
		return filepath.Join("infrastructure", strings.TrimPrefix(pkg, "infrastructure/"))
	case strings.HasPrefix(pkg, "internal"):
		return filepath.Join("internal", strings.TrimPrefix(pkg, "internal/"))
	case strings.HasPrefix(pkg, "protocols"):
		return filepath.Join("protocols", strings.TrimPrefix(pkg, "protocols/"))
	case strings.HasPrefix(pkg, "platform"):
		return filepath.Join("platform", strings.TrimPrefix(pkg, "platform/"))
	case strings.HasPrefix(pkg, "domains"):
		return filepath.Join("domains", strings.TrimPrefix(pkg, "domains/"))
	default:
		// Default: use the package path as-is.
		return pkg
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `%s — Generate scaffolding for common component patterns.

Usage:
  %s <component-type> [flags]

Component types:
  authenticator   Generate a new authenticator (implements core.Authenticator)
  store           Generate a new storage backend (implements core storage interfaces)
  handler         Generate a new HTTP handler (hexagonal pattern)
  grant           Generate a new OAuth grant handler (OAuth 2.0 flow)

Flags:
  --name string      Component name (required, e.g., totp, redis, custom-auth)
  --package string   Target package path (required, e.g., authenticators, infrastructure/redis)
  --desc string      Brief description (optional, defaults to "<name> component")
  --output string    Output directory (optional, inferred from package path)

Examples:
  # Generate a TOTP authenticator
  %s authenticator --name totp --package authenticators --desc "TOTP time-based one-time passwords"

  # Generate a Redis store
  %s store --name redis --package infrastructure/redis --desc "Redis-backed session storage"

  # Generate a custom handler
  %s handler --name webhook --package internal/handler --desc "webhook event handler"

  # Generate an OAuth grant (--package must not be protocols/oauth itself —
  # see the package doc comment at the top of this file for why)
  %s grant --name device-code --package protocols/grants --desc "RFC 8628 device authorization"

The generated code includes:
  - Package structure and imports
  - Interface implementations with TODO markers
  - Configuration structs
  - Constructor functions
  - Example method signatures with documentation

After generation, fill in the TODO sections with your business logic.
`, progName, progName, progName, progName, progName, progName)
}
