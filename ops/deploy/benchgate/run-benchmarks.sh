#!/usr/bin/env bash
# Runs every benchmark declared in benchmarks.yaml and streams raw
# `go test -bench` output to stdout. Shared by record-baseline.sh and
# compare-baseline.sh so a baseline and a comparison run always exercise the
# identical benchmark set + -count — a mismatched -count makes benchstat's
# confidence interval meaningless.
#
# The config format is deliberately flat (no nested maps/anchors) so this
# script reads it with a plain awk/bash state machine instead of pulling in
# a YAML-parsing dependency for a CI-only tool script.
#
# Usage: run-benchmarks.sh [path/to/benchmarks.yaml]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CONFIG="${1:-$SCRIPT_DIR/benchmarks.yaml}"

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

count="$(awk -F': *' '/^count:/ {print $2; exit}' "$CONFIG")"
count="$(trim "${count:-6}")"

cd "$REPO_ROOT"

pkg=""
ran=0
while IFS= read -r line; do
  case "$line" in
  *'- pkg:'*)
    pkg="$(trim "${line#*pkg:}")"
    ;;
  *'bench:'*)
    bench="$(trim "${line#*bench:}")"
    if [ -n "$pkg" ]; then
      echo "==> go test -run='^\$' -bench='$bench' -benchmem -count=$count $pkg" >&2
      go test -run='^$' -bench="$bench" -benchmem -count="$count" "$pkg"
      ran=$((ran + 1))
      pkg=""
    fi
    ;;
  esac
done < <(awk '/^benchmarks:/{f=1; next} f' "$CONFIG")

if [ "$ran" -eq 0 ]; then
  echo "ERROR: no benchmarks found in $CONFIG" >&2
  exit 1
fi
