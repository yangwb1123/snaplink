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
// Fields are best-effort: when the binary wasn't built with
// `-buildvcs=true` (default for `go build`) or via `go install`
// from a non-VCS path, VCSRevision + VCSTime will be empty. Version
// defaults to "(devel)" when not built from a tagged module —
// matches the runtime/debug behavior so operators see something
// rather than an empty field.
type BuildInfo struct {
	Version     string `json:"version"`
	VCSRevision string `json:"vcs_revision,omitempty"`
	VCSTime     string `json:"vcs_time,omitempty"`
}

var (
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
		info, ok := debug.ReadBuildInfo()
		if !ok {
			buildInfoVal = BuildInfo{Version: "(unknown)"}
			return
		}
		buildInfoVal.Version = info.Main.Version
		if buildInfoVal.Version == "" {
			buildInfoVal.Version = "(devel)"
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				buildInfoVal.VCSRevision = s.Value
			case "vcs.time":
				buildInfoVal.VCSTime = s.Value
			}
		}
	})
	return buildInfoVal
}
