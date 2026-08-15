package composition

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
)

// Execute runs the small-edition CLI: version/modules commands, config
// parsing, handler construction (delegated to the composition root via
// build), and HTTP serving.
func Execute(
	ctx context.Context,
	args []string,
	stdout, stderr io.Writer,
	getenv func(string) string,
	edition Edition,
	build func(RuntimeConfig) (http.Handler, error),
) int {
	if handled, code := HandleCommand(args, stdout, stderr, edition); handled {
		return code
	}
	cfg, err := ParseRuntimeConfig(args, getenv, stderr, edition)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", ProgramName, err)
		return 2
	}
	app, err := build(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "%s: build: %v\n", ProgramName, err)
		return 1
	}
	if err := Serve(ctx, cfg, app, stderr); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", ProgramName, err)
		return 1
	}
	return 0
}

func writeUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(w, `%s — prototype/minimal in-memory SSO server.

Usage:
  %s [flags]
  %s version
  %s modules [--json]

The defaults seed alice/s3cret plus demo-app and demo-app-b on loopback only.
Every flag also has an SSO_MINIMAL_* environment equivalent.

Flags:
`, ProgramName, ProgramName, ProgramName, ProgramName)
	fs.PrintDefaults()
}
