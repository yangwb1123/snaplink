package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/yangwb1123/snaplink/config"
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
  `+progName+` modules      print the compiled module profile and exit

Flags:
`)
	flag.PrintDefaults()
}

// fail prints "<prog>: <msg>" to stderr and exits 1 (runtime error).
func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, progName+": "+format+"\n", args...)
	os.Exit(1)
}

// failUsage reports command misuse with the conventional exit status 2.
func failUsage(format string, args ...any) {
	fmt.Fprintf(os.Stderr, progName+": "+format+"\n", args...)
	os.Exit(2)
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

// applyRuntimeTuning adjusts Go runtime parameters for SSO-server workloads.
// High-throughput token signing creates many short-lived objects; a higher
// GC target reduces GC frequency at the cost of a small heap increase.
//
// GOMAXPROCS and GOMEMLIMIT are detected from the cgroup (v1 or v2) when
// running inside a container and no explicit env override is set. This
// prevents CPU throttling jitter (GOMAXPROCS defaulting to host cores) and
// OOM kills (GC seeing all host memory as available).
//
// http2Cfg controls HTTP/2 server-side support. nil or {Enabled: false}
// disables HTTP/2 via GODEBUG (current default). When Enabled is true,
// HTTP/2 remains active unless GODEBUG is already explicitly set by the
// operator (explicit env override takes precedence).
func applyRuntimeTuning(http2Cfg *config.HTTP2Config) {
	// GC target: 200% instead of the default 100% — fewer GC cycles
	// under spiky token-issuance load. Respects explicit env override.
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(200)
	}

	// GOMAXPROCS: respect cgroup CPU quota when inside a container and
	// GOMAXPROCS is not explicitly overridden. Detected by parsing
	// cgroup v2's cpu.max or falling back to cgroup v1's cpu.cfs_*.
	if os.Getenv("GOMAXPROCS") == "" {
		if quota := detectCgroupCPUQuota(); quota > 0 {
			runtime.GOMAXPROCS(quota)
		}
	}

	// GOMEMLIMIT: set a soft memory limit from the cgroup memory.max
	// (v2) or memory.limit_in_bytes (v1), at 90% of the limit so the
	// GC kicks in before the OOM killer. Respects explicit env override
	// and only applies when the limit is a reasonable finite value.
	if os.Getenv("GOMEMLIMIT") == "" {
		if memLimit := detectCgroupMemoryLimit(); memLimit > 0 && memLimit < (1<<62) {
			// 90% of cgroup limit leaves headroom for OS / non-Go memory.
			debug.SetMemoryLimit(int64(float64(memLimit) * 0.9))
		}
	}

	// HTTP/2 server-side control.
	// When running behind a reverse proxy (Envoy, NGINX, OpenResty),
	// the server-to-proxy hop gains nothing from h2 — disable it.
	// When the operator explicitly enables HTTP/2 via config, leave
	// it active unless GODEBUG was already set by the operator
	// (explicit env override takes precedence).
	if http2Cfg == nil || !http2Cfg.Enabled {
		if os.Getenv("GODEBUG") == "" {
			os.Setenv("GODEBUG", "http2server=0")
		}
	}
	// If Enabled, do nothing — HTTP/2 stays on by default in Go's
	// net/http unless GODEBUG=http2server=0 is set. The operator's
	// explicit GODEBUG env var (set outside config) still wins.
}

// detectCgroupCPUQuota reads the cgroup CPU quota and returns the number of
// CPUs available, or 0 if undetectable / unlimited.
//
// cgroup v2: /sys/fs/cgroup/cpu.max — format "$MAX $PERIOD"
// cgroup v1: /sys/fs/cgroup/cpu/cpu.cfs_quota_us + cpu.cfs_period_us
func detectCgroupCPUQuota() int {
	// cgroup v2
	data, err := os.ReadFile("/sys/fs/cgroup/cpu.max")
	if err == nil {
		parts := strings.Fields(strings.TrimSpace(string(data)))
		if len(parts) >= 2 && parts[0] != "max" {
			max, err1 := strconv.Atoi(parts[0])
			period, err2 := strconv.Atoi(parts[1])
			if err1 == nil && err2 == nil && period > 0 {
				quota := max / period
				if quota > 0 {
					return quota
				}
			}
		}
		return 0 // max means unlimited
	}

	// cgroup v1
	quotaB, err1 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	periodB, err2 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if err1 == nil && err2 == nil {
		quota, err1 := strconv.Atoi(strings.TrimSpace(string(quotaB)))
		period, err2 := strconv.Atoi(strings.TrimSpace(string(periodB)))
		if err1 == nil && err2 == nil && quota > 0 && period > 0 {
			return quota / period
		}
	}
	return 0
}

// detectCgroupMemoryLimit reads the cgroup memory limit in bytes, or 0 if
// undetectable / unlimited. cgroup v2 first, then v1.
func detectCgroupMemoryLimit() int64 {
	// cgroup v2
	data, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	if err == nil {
		s := strings.TrimSpace(string(data))
		if s == "max" {
			return 0 // unlimited
		}
		v, err := strconv.ParseInt(s, 10, 64)
		if err == nil && v > 0 {
			return v
		}
		return 0
	}

	// cgroup v1
	data, err = os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes")
	if err == nil {
		s := strings.TrimSpace(string(data))
		v, err := strconv.ParseInt(s, 10, 64)
		if err == nil && v > 0 && v < (1<<62) {
			return v
		}
	}
	return 0
}
