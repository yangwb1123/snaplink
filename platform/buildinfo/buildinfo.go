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
	"strings"

	"github.com/yangwb1123/snaplink/shared/core"
)

const productName = "snaplink"

var editionProfiles = map[string]struct{}{
	"prototype": {},
	"minimal":   {},
	"full":      {},
}

// Version is replaced by release or profile builds through -ldflags.
var Version = ""

// Resolve picks the most specific version available: the ldflags override if
// non-empty, else the module version from build info, else "(devel)". It also
// surfaces the VCS revision and dirty flag when built from a source tree.
func Resolve(override string) (ver, revision string, dirty bool) {
	return ResolveProfile(override, BuildProfile)
}

// ResolveProfile resolves and decorates a version for one immutable build
// profile. Ordinary and compatibility builds retain their historical version.
func ResolveProfile(override, profile string) (ver, revision string, dirty bool) {
	ver = override
	if ver == "" {
		ver = Version
	}
	info := core.ReadBuildInfo()
	if ver == "" {
		ver = info.Version
	}
	return FormatEditionVersion(ver, profile), info.VCSRevision, info.VCSModified
}

// FormatEditionVersion returns the public identity of a tier build.
// Compatibility and custom profiles are returned unchanged.
func FormatEditionVersion(base, profile string) string {
	if !IsEditionProfile(profile) {
		return base
	}
	base = strings.TrimPrefix(strings.TrimSpace(base), productName+"-")
	base = strings.TrimSuffix(base, ".production")
	for edition := range editionProfiles {
		base = strings.TrimSuffix(base, "."+edition)
	}
	return productName + "-" + base + "." + profile
}

// IsEditionProfile reports whether profile is a public product tier.
func IsEditionProfile(profile string) bool {
	_, ok := editionProfiles[profile]
	return ok
}

// ProgramName returns the inventory program identity for profile.
func ProgramName(fallback, profile string) string {
	if IsEditionProfile(profile) {
		return productName
	}
	return fallback
}

// Write renders the version line(s) for progName to w. With no VCS revision
// (e.g. `go install module@version`) it is a single line; from a source tree it
// adds the revision (with a "modified" marker when dirty) and the Go version.
func Write(w io.Writer, progName, override string) {
	WriteProfile(w, progName, override, BuildProfile)
}

// WriteProfile renders a version using an explicit profile identity.
func WriteProfile(w io.Writer, progName, override, profile string) {
	v, rev, dirty := ResolveProfile(override, profile)
	info := core.ReadBuildInfo()
	label := progName + " " + v
	if IsEditionProfile(profile) {
		label = v
	}
	suffix := ""
	if dirty {
		suffix = " (modified)"
	}
	_, _ = fmt.Fprintf(
		w,
		"%s\n  build time: %s\n  git hash:   %s%s\n  go:         %s\n",
		label,
		fallback(info.BuildTime, "(unknown)"),
		fallback(rev, "(unknown)"),
		suffix,
		runtime.Version(),
	)
}
