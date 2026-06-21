package main

import (
	"io"

	"github.com/snaplink/sso/platform/buildinfo"
)

// version is overridable at build time via -ldflags "-X main.version=v1.2.3";
// otherwise buildinfo derives it from the embedded module/VCS build info.
var version = ""

// writeVersion renders the toolbelt version line(s) to w. Kept as a thin wrapper
// over buildinfo.Write so the dispatcher and tests have a local entry point.
func writeVersion(w io.Writer) { buildinfo.Write(w, progName, version) }
