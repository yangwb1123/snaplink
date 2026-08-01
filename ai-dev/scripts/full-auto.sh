#!/usr/bin/env bash
# Full-auto: module-by-module analysis -> auto-extract directions -> full
# SDLC implementation for every direction, with no human in the loop.
#
# Phase A  module discovery: scan the project's architecture layers
#          (domains, interfaces, infrastructure, platform, protocols,
#          shared) per AGENTS.md and pick the module directories.
# Phase B  per-module analysis: one prompt per module, scanned against the
#          whole codebase, listing 3-5 expansion directions as "## " headings.
# Phase C  direction extraction: every "## " heading becomes one direction
#          (capped by --max-directions per module).
# Phase D  per-direction full SDLC: a pipeline generated from
#          full-sdlc-implement.yaml with the module+direction injected,
#          running requirements -> design -> adversarial review -> gate ->
#          real implementation (go build/vet gate) -> QA acceptance gate.
#          Failures (gate FAIL etc.) are recorded and the run continues.
# Phase E  summary report in docs/auto/SUMMARY.md.
#
# Usage:
#   ai-dev/scripts/full-auto.sh [--modules m1,m2] [--max-directions N] [--dry-run]
#     --modules          comma-separated module dirs (default: all layers)
#     --max-directions   directions per module (default 3)
#     --dry-run          print the plan without executing
#   Non-interactive by design; safe to run under nohup for multi-hour runs.
#
# Requires: pi in PATH with API access, git repository, go toolchain.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

MODULES=""
MAX_DIRECTIONS=3
DRY_RUN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --modules) MODULES="$2"; shift 2 ;;
    --max-directions) MAX_DIRECTIONS="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) echo "usage: full-auto.sh [--modules m1,m2] [--max-directions N] [--dry-run]"; exit 1 ;;
  esac
done

# --- Phase A: module discovery -------------------------------------------
if [ -n "$MODULES" ]; then
  IFS=',' read -r -a MODULE_DIRS <<< "$MODULES"
else
  LAYERS=(domains interfaces infrastructure platform protocols shared)
  MODULE_DIRS=()
  for layer in "${LAYERS[@]}"; do
    [ -d "$layer" ] || continue
    for d in "$layer"/*/; do
      [ -d "$d" ] || continue
      # skip vendored/generated/non-module dirs
      case "$d" in
        *testdata*|*gen/*|*mock*|*/defaultimpl/*) continue ;;
      esac
      MODULE_DIRS+=("${d%/}")
    done
  done
fi
if [ ${#MODULE_DIRS[@]} -eq 0 ]; then
  echo "ERROR: no modules found"; exit 1
fi

echo "== Modules to analyze: ${#MODULE_DIRS[@]} =="
printf '   %s\n' "${MODULE_DIRS[@]}"

mkdir -p docs/auto logs
SUMMARY="docs/auto/SUMMARY.md"
: > "$SUMMARY"
echo "# Full-auto summary $(date '+%Y-%m-%d %H:%M:%S')" >> "$SUMMARY"
echo "" >> "$SUMMARY"

ANALYZE_PROMPT='基于目前已经实现的功能，以资深架构师/产品经理的角度分析 %s 模块（目录 %s/ 及其在代码库中的相关接口），全局扫描一次当前代码库作为上下文。列出最多 %s 个高价值的扩展方向/改进点：每个方向用 "## " 开头（标题即方向名，便于自动提取），下面说明问题、证据（文件/符号）、为什么需要。不要编写任何代码。'

ok_count=0
fail_count=0
for module in "${MODULE_DIRS[@]}"; do
  module_slug=${module//\//-}
  analysis="docs/auto/${module_slug}-analysis.md"
  echo ""
  echo "== Phase B: analyzing module '$module' =="
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "   (dry-run) would analyze $module and extract up to $MAX_DIRECTIONS directions"
    continue
  fi
  if python ./ai-dev/pi-batch.py -p "$(printf "$ANALYZE_PROMPT" "$module" "$module" "$MAX_DIRECTIONS")" \
      --output "$analysis" --retries 2 --log-file logs/full-auto.log; then
    echo "   analysis: $analysis"
  else
    echo "   WARNING: analysis failed for $module; skipping module"
    echo "- module $module: analysis FAILED" >> "$SUMMARY"
    fail_count=$((fail_count+1))
    continue
  fi

  # --- Phase C: direction extraction --------------------------------------
  mapfile -t directions < <(grep -E "^## " "$analysis" | sed 's/^## *//' | head -n "$MAX_DIRECTIONS" || true)
  if [ ${#directions[@]} -eq 0 ]; then
    echo "   WARNING: no '## ' directions found in $analysis; skipping module"
    echo "- module $module: no directions extracted" >> "$SUMMARY"
    fail_count=$((fail_count+1))
    continue
  fi
  echo "   directions (${#directions[@]}):"
  printf '      - %s\n' "${directions[@]}"

  # --- Phase D: one full SDLC pipeline per direction ----------------------
  for direction in "${directions[@]}"; do
    echo ""
    echo "== Phase D: full SDLC for '$direction' =="
    pipeline="/tmp/full-auto-$(date +%Y%m%d-%H%M%S)-${module_slug}.yaml"
    python3 - "$module" "$direction" "$analysis" "$pipeline" <<'EOF'
import os
import sys
import yaml

module, direction, analysis, out = sys.argv[1:5]
with open("ai-dev/examples/full-sdlc-implement.yaml", encoding="utf-8") as f:
    data = yaml.safe_load(f)
for s in data["stages"]:
    if s.get("name") == "requirements":
        s["from_prompt"] = (
            "Analyze the snaplink codebase and produce a requirements "
            f"specification for module '{module}', expansion direction "
            f"'{direction[:200]}' (from {analysis}). Exactly 3 evidence-"
            "backed improvements: for each, name, problem, evidence "
            "(file/symbol), proposed behavior, acceptance check. Use "
            "markdown headings (## ...) for each decision."
        )
    if s.get("role_dir"):
        s["role_dir"] = os.path.abspath(s["role_dir"])
with open(out, "w", encoding="utf-8") as f:
    yaml.safe_dump(data, f, sort_keys=False)
EOF

    if [ "$DRY_RUN" -eq 1 ]; then
      echo "   (dry-run) would run $pipeline"
      echo "- module $module / direction '$direction': (dry-run)" >> "$SUMMARY"
      continue
    fi
    if python ./ai-dev/pi-batch.py "$pipeline" --log-file logs/full-auto.log; then
      echo "   OK: $module / $direction"
      echo "- module $module / direction '$direction': PASS" >> "$SUMMARY"
      ok_count=$((ok_count+1))
    else
      echo "   FAILED: $module / $direction (see logs/full-auto.log)"
      echo "- module $module / direction '$direction': FAIL" >> "$SUMMARY"
      fail_count=$((fail_count+1))
    fi
  done
done

# --- Phase E: summary -----------------------------------------------------
echo ""
echo "== Summary: $ok_count passed, $fail_count failed =="
echo "" >> "$SUMMARY"
echo "Passed: $ok_count, failed: $fail_count" >> "$SUMMARY"
echo "Full report: $SUMMARY"
echo "Decision log: docs/DECISIONS.md"
echo "Run log:      logs/full-auto.log"
