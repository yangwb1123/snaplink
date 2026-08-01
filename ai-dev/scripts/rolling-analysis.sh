#!/usr/bin/env bash
# Rolling analysis: the complete workflow for
#   for i in {1..N}; do pi-batch -p "analyze expansion directions"; done
#
# Each round: (1) references the previous round's conclusion so the agent
# corrects stale parts and deepens, (2) continues one shared session,
# (3) appends a structured decision record, (4) commits the deliverable,
# (5) archives it so the runs dir keeps only the latest. Rate-limit safe
# via --min-interval and the inter-round sleep.
#
# Usage:
#   ai-dev/scripts/rolling-analysis.sh [ROUNDS] [INTERVAL_SECONDS] [PROMPT_FILE]
#   ROUNDS=5 INTERVAL=300  (defaults: 5 rounds, 300s rest)
#
# Outputs:
#   docs/requirements/runs/run-<ts>.md   per-round deliverables (latest kept)
#   docs/DECISIONS.md                    decision history (append-only)
#   docs/archive/batch-<ts>/             archived rounds (git history retains all)
#   logs/ext.log                         24x7 run log
#
# Requires: pi in PATH with API access; git repository.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"   # always run from the repo root

ROUNDS=${1:-5}
INTERVAL=${2:-300}
PROMPT_FILE=${3:-}
DEFAULT_PROMPT='基于目前已经实现的功能，请你以资深架构师/产品经理的角度，帮我思考这个项目还有哪些可以扩展的核心功能点、边界情况（Edge cases）处理或性能优化点。要求：全局扫描一次当前代码库。不要编写任何代码。列出 3-5 个高价值的扩展方向，并说明为什么需要它们。'

if [ -n "$PROMPT_FILE" ]; then
  PROMPT="$(cat "$PROMPT_FILE")"
else
  PROMPT="$DEFAULT_PROMPT"
fi

# --- 0. environment checks -------------------------------------------------
command -v pi >/dev/null 2>&1 || { echo "ERROR: 'pi' not found in PATH"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: 'python3' not found"; exit 1; }
mkdir -p docs/requirements/runs docs/archive logs

echo "== Rolling analysis: $ROUNDS round(s), ${INTERVAL}s rest between rounds =="

for i in $(seq 1 "$ROUNDS"); do
  latest=$(ls -t docs/requirements/runs/*.md 2>/dev/null | head -1 || true)
  ref=""
  if [ -n "$latest" ]; then
    ref="上一轮结论（$latest）已附加。先指出其中过时或错误的部分，再基于当前代码库深化："
  fi

  echo ""
  echo "== Round $i/$ROUNDS =="
  python ./ai-dev/pi-batch.py -p "${ref}${PROMPT}" \
    --output "docs/requirements/runs/run-$(date +%Y%m%d-%H%M%S).md" \
    --session-mode shared --session-name ext-rolling \
    --retries 3 --log-file logs/ext.log \
    --decision-log docs/DECISIONS.md \
    --git-commit --archive-dir docs/archive \
    || { echo "WARNING: round $i failed (see logs/ext.log); continuing"; }

  if [ "$i" -lt "$ROUNDS" ]; then
    echo "  -- resting ${INTERVAL}s before round $((i+1)) --"
    sleep "$INTERVAL"
  fi
done

# --- summary: commit the decision log, point at the final conclusion ------
if [ -f docs/DECISIONS.md ] && [ -n "$(git status --porcelain docs/DECISIONS.md)" ]; then
  git add docs/DECISIONS.md
  git commit -m "docs(ai-dev): decision log for rolling analysis ($ROUNDS rounds)" >/dev/null 2>&1 || true
fi

final=$(ls -t docs/archive/batch-*/run-*.md 2>/dev/null | head -1 || true)
echo ""
echo "== Done: $ROUNDS round(s) =="
[ -n "$final" ] && echo "Final conclusion : $final"
echo "Decision history : docs/DECISIONS.md"
echo "Run log          : logs/ext.log"
echo "Archives         : docs/archive/"
