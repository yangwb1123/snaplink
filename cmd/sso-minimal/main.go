package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(execute(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

func execute(
	ctx context.Context,
	args []string,
	stdout, stderr io.Writer,
	getenv func(string) string,
) int {
	if handled, code := handleCommand(args, stdout, stderr); handled {
		return code
	}
	cfg, err := parseRuntimeConfig(args, getenv, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", programName, err)
		return 2
	}
	app, err := buildHandler(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "%s: build: %v\n", programName, err)
		return 1
	}
	if err := serve(ctx, cfg, app, stderr); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", programName, err)
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
`, programName, programName, programName, programName)
	fs.PrintDefaults()
}
