#!/usr/bin/env bash
# Regenerate ops/deploy/benchgate/baseline.txt from the current working
# tree. Run this deliberately after a perf-sensitive change lands and the
# new numbers are the accepted normal — a baseline update is a human
# decision, same as ops/deploy/loadtest/record-baseline.sh. NOT run in CI.
#
# Usage: record-baseline.sh [output-file]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$SCRIPT_DIR/baseline.txt}"

echo "==> Recording benchmark baseline -> $OUT" >&2
"$SCRIPT_DIR/run-benchmarks.sh" "$SCRIPT_DIR/benchmarks.yaml" >"$OUT"
echo "==> Done. $(grep -c '^Benchmark' "$OUT") benchmark result line(s) captured." >&2
