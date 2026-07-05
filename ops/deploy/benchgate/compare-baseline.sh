#!/usr/bin/env bash
# Benchmark budget CI gate: runs the gated benchmark set fresh, then uses
# benchstat (golang.org/x/perf/cmd/benchstat) to compare against the
# checked-in baseline. Fails (non-zero) if any gated benchmark's sec/op
# regresses beyond benchmarks.yaml's threshold_percent AND benchstat
# considers the change statistically significant (default alpha=0.05) —
# this second condition is what keeps a single noisy run from failing the
# gate.
#
# benchstat is deliberately fetched via `go run ...@latest` rather than
# added to go.mod: it's a CI-only tool, not a runtime dependency (see
# AGENTS.md "no new go.mod runtime deps for tool-only code").
#
# NOT part of `make ci` / the PR-blocking GitHub Actions workflow —
# benchmarks are noisier and much slower than the race-detector suite other
# agents rely on as a hard, fast gate. Invoke manually (`make bench-gate`)
# or from the separate, non-blocking .github/workflows/benchmark-gate.yml.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="$SCRIPT_DIR/benchmarks.yaml"
BASELINE="$SCRIPT_DIR/baseline.txt"

if [ ! -f "$BASELINE" ]; then
  echo "ERROR: no baseline at $BASELINE — run 'make bench-gate-record' first." >&2
  exit 1
fi

THRESHOLD="$(awk -F': *' '/^threshold_percent:/ {print $2; exit}' "$CONFIG")"
THRESHOLD="${THRESHOLD:-10}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
CURRENT="$WORKDIR/current.txt"

echo "==> Running gated benchmarks (this takes a while)..." >&2
"$SCRIPT_DIR/run-benchmarks.sh" "$CONFIG" >"$CURRENT"

echo "==> Comparing against baseline (threshold: ${THRESHOLD}% regression)..." >&2
BENCHSTAT="go run golang.org/x/perf/cmd/benchstat@latest"

# Human-readable table for CI logs / local runs.
$BENCHSTAT "$BASELINE" "$CURRENT" 2>/dev/null || true

csv="$($BENCHSTAT -format csv "$BASELINE" "$CURRENT" 2>/dev/null)"

# Walk only the "sec/op" table (skip B/op / allocs/op — this gate is a CPU
# regression gate, not an allocation-budget gate). benchstat marks a change
# "~" when it is NOT statistically significant at its default alpha; those
# rows are intentionally NOT compared to threshold_percent — see file header.
regressions="$(printf '%s\n' "$csv" | awk -F, -v thr="$THRESHOLD" '
  $2 == "sec/op" { insec = 1; next }
  $2 == "B/op" || $2 == "allocs/op" { insec = 0; next }
  /^$/ { insec = 0; next }
  insec && NF >= 6 {
    name = $1; vsbase = $6
    if (vsbase ~ /^\+/) {
      pct = vsbase
      sub(/^\+/, "", pct)
      sub(/%$/, "", pct)
      if (pct + 0 > thr + 0) {
        printf "  %s: +%s%% (threshold %s%%)\n", name, pct, thr
      }
    }
  }
')"

if [ -n "$regressions" ]; then
  echo "" >&2
  echo "FAIL: benchmark regression(s) beyond ${THRESHOLD}% vs baseline:" >&2
  echo "$regressions" >&2
  exit 1
fi

echo "PASS: no gated benchmark regressed beyond ${THRESHOLD}% vs baseline." >&2
