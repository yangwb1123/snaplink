package main

import (
	"os"
	"testing"

	"github.com/snaplink/sso/config"
)

// pinRuntimeTuningEnv sets GOGC/GOMAXPROCS/GOMEMLIMIT to explicit non-empty
// values so applyRuntimeTuning's early "already overridden" guards on each
// skip their debug.SetGCPercent/runtime.GOMAXPROCS/debug.SetMemoryLimit
// calls. Those are process-wide, non-test-scoped mutations (t.Setenv only
// restores env vars, not runtime GC/GOMAXPROCS state) that would otherwise
// leak into every other test sharing this binary -- these tests only care
// about the GODEBUG/HTTP2 branch.
func pinRuntimeTuningEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GOGC", "100")
	t.Setenv("GOMAXPROCS", "1")
	t.Setenv("GOMEMLIMIT", "1GiB")
}

// TestApplyRuntimeTuning_HTTP2Toggle covers the GODEBUG side effect of the
// server.http2.enabled config toggle. Not parallel: t.Setenv forbids it, and
// the function under test mutates the process-wide GODEBUG env var.
func TestApplyRuntimeTuning_HTTP2Toggle(t *testing.T) {
	cases := []struct {
		name        string
		cfg         *config.HTTP2Config
		wantGODEBUG string
	}{
		{"nil config disables HTTP/2 (current default)", nil, "http2server=0"},
		{"explicit disabled disables HTTP/2", &config.HTTP2Config{Enabled: false}, "http2server=0"},
		{"explicit enabled leaves GODEBUG untouched", &config.HTTP2Config{Enabled: true}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pinRuntimeTuningEnv(t)
			t.Setenv("GODEBUG", "") // os.Getenv("GODEBUG") == "" reproduces "unset" for the function under test
			applyRuntimeTuning(tc.cfg)
			if got := os.Getenv("GODEBUG"); got != tc.wantGODEBUG {
				t.Errorf("GODEBUG = %q, want %q", got, tc.wantGODEBUG)
			}
		})
	}
}

// TestApplyRuntimeTuning_HTTP2EnabledRespectsExplicitGODEBUG proves an
// operator's own GODEBUG setting wins even when config explicitly enables
// HTTP/2 -- an explicit env override must never be silently clobbered.
func TestApplyRuntimeTuning_HTTP2EnabledRespectsExplicitGODEBUG(t *testing.T) {
	pinRuntimeTuningEnv(t)
	t.Setenv("GODEBUG", "http2client=0")
	applyRuntimeTuning(&config.HTTP2Config{Enabled: true})
	if got := os.Getenv("GODEBUG"); got != "http2client=0" {
		t.Errorf("GODEBUG = %q, want unchanged %q", got, "http2client=0")
	}
}

// TestApplyRuntimeTuning_HTTP2DisabledRespectsExplicitGODEBUG proves the
// disabled path ALSO leaves an operator's own GODEBUG setting alone --
// disabling HTTP/2 via config must not override an explicit env var either.
func TestApplyRuntimeTuning_HTTP2DisabledRespectsExplicitGODEBUG(t *testing.T) {
	pinRuntimeTuningEnv(t)
	t.Setenv("GODEBUG", "http2client=0")
	applyRuntimeTuning(&config.HTTP2Config{Enabled: false})
	if got := os.Getenv("GODEBUG"); got != "http2client=0" {
		t.Errorf("GODEBUG = %q, want unchanged %q", got, "http2client=0")
	}
}
