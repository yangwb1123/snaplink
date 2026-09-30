package core

import (
	"runtime/debug"
	"sync"
)

// BuildInfo captures the deployment's version + VCS identity.
// Reads runtime/debug.ReadBuildInfo at first call; cached so
// /health is cheap. Operators investigating which commit a
// production replica is running read this from the unauthenticated
// health endpoint — saves a shell into the container.
//
// Fields are best-effort: release builders inject BuildTime and may override
// the version and revision. Ordinary builds fall back to runtime/debug, where
// VCSTime is the commit time rather than the build time. Version defaults to
// "(devel)" when not built from a tagged module so operators never see an
// empty version.
type BuildInfo struct {
	Version     string `json:"version"`
	VCSRevision string `json:"vcs_revision,omitempty"`
	VCSTime     string `json:"vcs_time,omitempty"`
	BuildTime   string `json:"build_time,omitempty"`
	VCSModified bool   `json:"vcs_modified,omitempty"`
}

var (
	// BuildVersion, BuildTime, GitHash, and BuildModified are populated by
	// release builders. runtime/debug remains the fallback for ordinary builds.
	BuildVersion  string
	BuildTime     string
	GitHash       string
	BuildModified string

	buildInfoOnce sync.Once
	buildInfoVal  BuildInfo
)

// ReadBuildInfo returns the cached BuildInfo, populating from
// runtime/debug.ReadBuildInfo on first call. Safe for concurrent
// use. Returns the zero value when the binary lacks build info
// (e.g. `go run` without -trimpath) — the health endpoint then
// surfaces Version="(devel)" without VCS fields, which operators
// can still read as a meaningful "this is a dev build" signal.
func ReadBuildInfo() BuildInfo {
	buildInfoOnce.Do(func() { buildInfoVal = collectBuildInfo() })
	return buildInfoVal
}

// collectBuildInfo resolves the build identity from the linker defaults and
// then, when the binary carries module build info, lets it fill the gaps. The
// order matters: a linker-injected version always wins over the module's own,
// because that is the value an operator set deliberately.
func collectBuildInfo() BuildInfo {
	collected := BuildInfo{
		Version:     BuildVersion,
		VCSRevision: GitHash,
		BuildTime:   BuildTime,
		VCSModified: BuildModified == "true",
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		if collected.Version == "" {
			collected.Version = "(unknown)"
		}
		return collected
	}
	if collected.Version == "" {
		collected.Version = info.Main.Version
	}
	if collected.Version == "" {
		collected.Version = "(devel)"
	}
	for _, setting := range info.Settings {
		applyBuildSetting(&collected, setting.Key, setting.Value)
	}
	return collected
}

// applyBuildSetting folds one VCS setting into the collected info. A value the
// linker already provided is never overwritten: `BuildModified` is baked in
// at link time, so a `vcs.modified` setting must not second-guess it.
func applyBuildSetting(collected *BuildInfo, key, value string) {
	switch key {
	case "vcs.revision":
		if collected.VCSRevision == "" {
			collected.VCSRevision = value
		}
	case "vcs.time":
		collected.VCSTime = value
	case "vcs.modified":
		if BuildModified == "" {
			collected.VCSModified = value == "true"
		}
	}
}
