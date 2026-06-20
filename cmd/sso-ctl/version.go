package main

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

// version is overridable at build time via
// -ldflags "-X main.version=v1.2.3"; otherwise it is derived from the
// embedded module build info (the module version for a `go install
// module@version`, or the VCS revision + dirty flag for a local build).
var version = ""

// writeVersion renders the toolbelt version line(s) to w. Kept separate from
// the dispatcher so it is unit-testable without capturing os.Stdout.
func writeVersion(w io.Writer) {
	v, rev, dirty := resolveVersion()
	if rev == "" {
		fmt.Fprintf(w, "%s %s (%s)\n", progName, v, runtime.Version())
		return
	}
	suffix := ""
	if dirty {
		suffix = " (modified)"
	}
	fmt.Fprintf(w, "%s %s\n  revision: %s%s\n  go:       %s\n", progName, v, rev, suffix, runtime.Version())
}

// resolveVersion picks the most specific version string available: an
// ldflags-injected value wins; otherwise the module version from build info;
// otherwise "(devel)". It also surfaces the VCS revision and dirty flag when
// the binary was built from a source tree.
func resolveVersion() (ver, revision string, dirty bool) {
	ver = version
	info, ok := debug.ReadBuildInfo()
	if !ok {
		if ver == "" {
			ver = "(unknown)"
		}
		return ver, "", false
	}
	if ver == "" {
		ver = info.Main.Version
		if ver == "" || ver == "(devel)" {
			ver = "(devel)"
		}
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	return ver, revision, dirty
}
