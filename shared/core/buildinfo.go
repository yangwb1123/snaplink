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
	buildInfoOnce.Do(func() {
		buildInfoVal = BuildInfo{
			Version:     BuildVersion,
			VCSRevision: GitHash,
			BuildTime:   BuildTime,
			VCSModified: BuildModified == "true",
		}
		info, ok := debug.ReadBuildInfo()
		if !ok {
			if buildInfoVal.Version == "" {
				buildInfoVal.Version = "(unknown)"
			}
			return
		}
		if buildInfoVal.Version == "" {
			buildInfoVal.Version = info.Main.Version
		}
		if buildInfoVal.Version == "" {
			buildInfoVal.Version = "(devel)"
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if buildInfoVal.VCSRevision == "" {
					buildInfoVal.VCSRevision = s.Value
				}
			case "vcs.time":
				buildInfoVal.VCSTime = s.Value
			case "vcs.modified":
				if BuildModified == "" {
					buildInfoVal.VCSModified = s.Value == "true"
				}
			}
		}
	})
	return buildInfoVal
}
