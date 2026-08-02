#!/usr/bin/env bash
# Full-auto: module-by-module analysis -> auto-extract directions -> full
# SDLC implementation for every direction, with no human in the loop.
#
# Cost control (the naive double loop explodes: 30 modules x 3 directions x
# ~20min per full pipeline is tens of hours):
#   --jobs N              parallel module analyses (default 4; analyses are
#                         independent, this divides analysis wall time by N)
#   --max-directions N    directions per module (default 1: the highest-value
#                         one, the analysis lists directions by value)
#   --top-only            extract only the first "## " heading (highest value)
#   --skip-passed         skip module/direction combos already PASS in
#                         docs/auto/SUMMARY.md (resume after interruption)
#   --parallel-pipelines N  run up to N full SDLC pipelines concurrently
#                         (each pipeline is independent; concurrent git
#                         commits are advisory, DECISIONS.md appends may
#                         interleave -- prefer serial for audits)
#   --dry-run             print the plan and the estimated wall time
#
# Usage:
#   ai-dev/scripts/full-auto.sh [options]
#
# Requires: pi in PATH with API access, git repository, go toolchain.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

MODULES=""
MAX_DIRECTIONS=1
TOP_ONLY=1
SKIP_PASSED=0
JOBS=4
PARALLEL_PIPELINES=1
DRY_RUN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --modules) MODULES="$2"; shift 2 ;;
    --max-directions) MAX_DIRECTIONS="$2"; TOP_ONLY=0; shift 2 ;;
    --top-only) TOP_ONLY=1; shift ;;
    --skip-passed) SKIP_PASSED=1; shift ;;
    --jobs) JOBS="$2"; shift 2 ;;
    --parallel-pipelines) PARALLEL_PIPELINES="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) echo "usage: full-auto.sh [--modules m1,m2] [--max-directions N] [--top-only] [--skip-passed] [--jobs N] [--parallel-pipelines N] [--dry-run]"; exit 1 ;;
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

mkdir -p docs/auto logs
SUMMARY="docs/auto/SUMMARY.md"
[ -f "$SUMMARY" ] || : > "$SUMMARY"

# Direction cap: --top-only means exactly the first (highest-value) heading.
if [ "$TOP_ONLY" -eq 1 ]; then
  MAX_DIRECTIONS=1
fi

# --- dry-run: print the plan and the cost estimate ------------------------
ANALYSIS_MIN=3        # observed: ~2.5 min per module analysis
PIPELINE_MIN=20       # observed: ~15-40 min per direction pipeline
if [ "$DRY_RUN" -eq 1 ]; then
  est_analysis=$(echo "scale=0; ${#MODULE_DIRS[@]} * $ANALYSIS_MIN / $JOBS" | bc 2>/dev/null || echo "?")
  est_pipeline=$(echo "scale=0; ${#MODULE_DIRS[@]} * $MAX_DIRECTIONS * $PIPELINE_MIN / $PARALLEL_PIPELINES" | bc 2>/dev/null || echo "?")
  echo "== Plan: ${#MODULE_DIRS[@]} module(s) x up to $MAX_DIRECTIONS direction(s) =="
  printf '   %s\n' "${MODULE_DIRS[@]}"
  echo "== Estimated wall time (order of magnitude) =="
  echo "   analysis:  ~${est_analysis} min  (${#MODULE_DIRS[@]} modules, $JOBS parallel)"
  echo "   pipelines: ~${est_pipeline} min  (${#MODULE_DIRS[@]} x $MAX_DIRECTIONS directions, $PARALLEL_PIPELINES parallel)"
  echo "   total:     ~$((est_analysis + est_pipeline)) min"
  echo "   (real runs vary widely; --skip-passed resumes, --max-directions/--top-only shrink scope)"
  exit 0
fi

echo "== Modules: ${#MODULE_DIRS[@]} | directions/module: $MAX_DIRECTIONS | analysis jobs: $JOBS | pipeline parallelism: $PARALLEL_PIPELINES =="
printf '   %s\n' "${MODULE_DIRS[@]}"

ANALYZE_PROMPT='基于目前已经实现的功能，以资深架构师/产品经理的角度分析 %s 模块（目录 %s/ 及其在代码库中的相关接口），全局扫描一次当前代码库作为上下文。列出最多 %s 个高价值的扩展方向/改进点：每个方向用 "## " 开头（标题即方向名，便于自动提取），按价值从高到低排列（第一个最高价值）。下面说明问题、证据（文件/符号）、为什么需要。不要编写任何代码。'

# --- Phase B: per-module analysis (parallel) ------------------------------
echo ""
echo "== Phase B: analyzing ${#MODULE_DIRS[@]} module(s), $JOBS parallel =="
analyze_one() {
  local module="$1"
  local module_slug=${module//\//-}
  local analysis="docs/auto/${module_slug}-analysis.md"
  local n_directions=$((MAX_DIRECTIONS + 2))
  if [ -s "$analysis" ]; then
    echo "   REUSE analysis: $analysis"
    return 0
  fi
  if python ./ai-dev/pi-batch.py -p "$(printf "$ANALYZE_PROMPT" "$module" "$module" "$n_directions")" \
      --output "$analysis" --retries 2 --log-file logs/full-auto.log; then
    echo "   analysis: $analysis"
    return 0
  fi
  echo "   WARNING: analysis failed for $module"
  return 1
}
export -f analyze_one
export ANALYZE_PROMPT MAX_DIRECTIONS
if [ "$JOBS" -gt 1 ]; then
  printf '%s\n' "${MODULE_DIRS[@]}" | xargs -P "$JOBS" -I{} bash -c 'analyze_one "$@"' _ {} || true
else
  for module in "${MODULE_DIRS[@]}"; do analyze_one "$module" || true; done
fi

# --- Phase C+D: extract directions, run one pipeline per direction --------
ok_count=0
fail_count=0
pipeline_jobs=()
declare -A SUMMARY_PASS  # module/direction -> 1 when already passed

if [ "$SKIP_PASSED" -eq 1 ] && [ -f "$SUMMARY" ]; then
  while IFS='|' read -r mod dir; do
    SUMMARY_PASS["$mod|$dir"]=1
  done < <(grep -E "^- module .+ / direction '.*': PASS$" "$SUMMARY" \
           | sed -E "s/^- module (.+) \/ direction '(.*)': PASS$/\1|\2/")
  echo "== skip-passed: ${#SUMMARY_PASS[@]} completed combo(s) already in SUMMARY =="
fi

run_pipeline() {
  local module="$1" direction="$2" analysis="$3" module_slug="$4" idx="$5"
  local pipeline="/tmp/full-auto-$(date +%Y%m%d-%H%M%S)-${module_slug}-${idx}.yaml"
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
  local logfile="logs/full-auto-${module_slug}-${idx}.log"
  if python ./ai-dev/pi-batch.py "$pipeline" --log-file "$logfile"; then
    echo "   OK: $module / $direction"
    echo "- module $module / direction '$direction': PASS" >> "$SUMMARY"
    return 0
  fi
  echo "   FAILED: $module / $direction (see $logfile)"
  echo "- module $module / direction '$direction': FAIL" >> "$SUMMARY"
  return 1
}
export -f run_pipeline
export SUMMARY

for module in "${MODULE_DIRS[@]}"; do
  module_slug=${module//\//-}
  analysis="docs/auto/${module_slug}-analysis.md"
  if [ ! -s "$analysis" ]; then
    echo "   WARNING: no analysis for $module; skipping"
    fail_count=$((fail_count+1))
    continue
  fi
  mapfile -t directions < <(grep -E "^## " "$analysis" | sed 's/^## *//' | head -n "$MAX_DIRECTIONS" || true)
  if [ ${#directions[@]} -eq 0 ]; then
    echo "   WARNING: no '## ' directions in $analysis; skipping module"
    echo "- module $module: no directions extracted" >> "$SUMMARY"
    fail_count=$((fail_count+1))
    continue
  fi
  echo ""
  echo "== $module: ${#directions[@]} direction(s) =="
  printf '      - %s\n' "${directions[@]}"
  for direction in "${directions[@]}"; do
    key="$module|$direction"
    if [ "$SKIP_PASSED" -eq 1 ] && [ "${SUMMARY_PASS[$key]:-}" = "1" ]; then
      echo "   SKIP (already PASS): $direction"
      ok_count=$((ok_count+1))
      continue
    fi
    if [ "$PARALLEL_PIPELINES" -gt 1 ]; then
      run_pipeline "$module" "$direction" "$analysis" "$module_slug" "${#pipeline_jobs[@]}" \
        & pipeline_jobs+=("$!")
    else
      if run_pipeline "$module" "$direction" "$analysis" "$module_slug" "0"; then
        ok_count=$((ok_count+1))
      else
        fail_count=$((fail_count+1))
      fi
    fi
    # bound the parallel pipeline pool
    if [ "$PARALLEL_PIPELINES" -gt 1 ] && [ "${#pipeline_jobs[@]}" -ge "$PARALLEL_PIPELINES" ]; then
      for j in "${pipeline_jobs[@]}"; do wait "$j" || true; done
      pipeline_jobs=()
    fi
  done
done
# drain remaining parallel pipelines
for j in "${pipeline_jobs[@]}"; do wait "$j" || true; done

# --- Phase E: summary -----------------------------------------------------
echo ""
echo "== Summary: $ok_count passed, $fail_count failed =="
echo "" >> "$SUMMARY"
echo "Passed: $ok_count, failed: $fail_count (run $(date '+%Y-%m-%d %H:%M:%S'))" >> "$SUMMARY"
echo "Full report: $SUMMARY"
echo "Decision log: docs/DECISIONS.md"
echo "Run log:      logs/full-auto.log (+ per-pipeline logs/full-auto-*.log)"
