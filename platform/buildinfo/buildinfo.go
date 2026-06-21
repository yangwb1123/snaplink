// Package buildinfo renders a binary's version line from the embedded Go build
// info, shared by the sso-server and sso-ctl commands so both report versions
// identically. An ldflags-injected override (-X .../buildinfo.Version or a
// per-binary main.version passed in) wins; otherwise the module version, or the
// VCS revision + dirty flag for a local build.
package buildinfo

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

// Resolve picks the most specific version available: the ldflags override if
// non-empty, else the module version from build info, else "(devel)". It also
// surfaces the VCS revision and dirty flag when built from a source tree.
func Resolve(override string) (ver, revision string, dirty bool) {
	ver = override
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

// Write renders the version line(s) for progName to w. With no VCS revision
// (e.g. `go install module@version`) it is a single line; from a source tree it
// adds the revision (with a "modified" marker when dirty) and the Go version.
func Write(w io.Writer, progName, override string) {
	v, rev, dirty := Resolve(override)
	if rev == "" {
		_, _ = fmt.Fprintf(w, "%s %s (%s)\n", progName, v, runtime.Version())
		return
	}
	suffix := ""
	if dirty {
		suffix = " (modified)"
	}
	_, _ = fmt.Fprintf(w, "%s %s\n  revision: %s%s\n  go:       %s\n", progName, v, rev, suffix, runtime.Version())
}
