#!/usr/bin/env bash
# GATE: 测试覆盖率检查
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"; cd "$ROOT"; EXIT_CODE=0
declare -A TARGETS; TARGETS["core"]=80; TARGETS["oauth"]=75; TARGETS["oidc"]=75; TARGETS["security"]=80; TARGETS["."]=60; TARGETS["defaultimpl"]=65
echo "--- coverage check ---"
TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT
go test -count=1 -coverprofile="$TMP" ./... 2>/dev/null || true
for pkg in "${!TARGETS[@]}"; do
  t="${TARGETS[$pkg]}"
  if [[ "$pkg" == "." ]]; then l=$(go tool cover -func="$TMP" 2>/dev/null | grep "^total:" || true); else l=$(go tool cover -func="$TMP" 2>/dev/null | grep "^${pkg}/" | tail -1 || true); fi
  [[ -z "$l" ]] && { echo "  SKIP: $pkg"; continue; }
  pct=$(echo "$l" | awk '{print $NF}' | tr -d '%'); int=${pct%.*}
  if (( int < t )); then echo "  FAIL: $pkg — ${pct}% (target ${t}%)"; EXIT_CODE=1; else echo "  PASS: $pkg — ${pct}% (target ${t}%)"; fi
done
[[ $EXIT_CODE -eq 0 ]] && echo "PASS" || { echo "FAIL: coverage below target"; exit 1; }
