package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// progName prefixes every diagnostic so multi-binary deployments can
// tell which tool emitted a line.
const progName = "sso-server"

// usage prints the standard "<prog> — <desc> / Usage / Flags" banner
// shared in style across the sso-* CLIs. Wired as flag.Usage so -h and
// parse errors render it.
func usage() {
	fmt.Fprint(os.Stderr, progName+` — OAuth 2.0 / OIDC SSO server.

Usage:
  `+progName+` [flags]      run the server (the default; reads --config)
  `+progName+` version      print the build version and exit

Flags:
`)
	flag.PrintDefaults()
}

// fail prints "<prog>: <msg>" to stderr and exits 1 (runtime error).
// CLI-misuse errors should exit 2 via flag.Usage instead.
func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, progName+": "+format+"\n", args...)
	os.Exit(1)
}

// writeAdminPasswordFile atomically writes the bootstrap admin
// password to path at mode 0600. Atomicity (tmp + rename) prevents
// a crashed write from leaving a half-empty file the operator
// might trust as authoritative. Parent directory must exist —
// not auto-created so an operator who points at /secrets/admin
// without mounting the volume sees the error rather than the
// password landing somewhere unexpected.
func writeAdminPasswordFile(path, password string) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".admin-password-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	// chmod BEFORE writing so a concurrent reader can't observe
	// 0644 in the brief window before the rename.
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.WriteString(password + "\n"); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
