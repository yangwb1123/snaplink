#!/usr/bin/env bash
# Full flow: rolling analysis -> pick a direction -> full SDLC implementation.
#
# Phase 1: rolling analysis discovers high-value expansion directions
#          (ai-dev/scripts/rolling-analysis.sh: shared session, decision
#          log, git commit, archive, rate-limit safe).
# Phase 2: show the latest analysis; you pick one direction (or pass it
#          as an argument to skip the prompt).
# Phase 3: generate a pipeline from ai-dev/examples/full-sdlc-implement.yaml
#          with the chosen direction injected into the requirements stage,
#          then run the full loop: requirements -> design -> adversarial
#          review -> gate -> real implementation (gated by go build/vet)
#          -> QA acceptance gate -> git commit -> archive -> decision log.
#
# Usage:
#   ai-dev/scripts/full-flow.sh [ROUNDS] [INTERVAL] [DIRECTION]
#     ROUNDS    analysis rounds (default 3)
#     INTERVAL  seconds of rest between rounds (default 120)
#     DIRECTION chosen expansion direction; empty = interactive prompt
#   Non-interactive: DIRECTION="device trust" ai-dev/scripts/full-flow.sh 2 10
#
# Requires: pi in PATH with API access, git repository, go toolchain.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

ROUNDS=${1:-3}
INTERVAL=${2:-120}
DIRECTION=${3:-}

# --- Phase 1: rolling analysis ------------------------------------------
echo ""
echo "== Phase 1: rolling analysis ($ROUNDS rounds, ${INTERVAL}s rest) =="
bash ai-dev/scripts/rolling-analysis.sh "$ROUNDS" "$INTERVAL"

# --- Phase 2: pick the direction ----------------------------------------
latest=$(ls -t docs/archive/batch-*/run-*.md 2>/dev/null | head -1 || true)
if [ -z "$latest" ]; then
  echo "ERROR: no analysis deliverables found under docs/archive/"; exit 1
fi
echo ""
echo "== Phase 2: latest analysis ($latest) =="
echo "--- 候选扩展方向（标题）---"
grep -E "^## " "$latest" || { echo "(no headings; showing head)"; head -40 "$latest"; }

if [ -z "$DIRECTION" ]; then
  echo ""
  echo "输入要实现的扩展方向（一句话主题；直接回车 = 采用第一个标题）:"
  read -r DIRECTION
fi
if [ -z "$DIRECTION" ]; then
  DIRECTION=$(grep -m1 "^## " "$latest" | sed 's/^## *//' || true)
fi
if [ -z "$DIRECTION" ]; then
  echo "ERROR: no direction given"; exit 1
fi
echo "选定方向: $DIRECTION"

# --- Phase 3: full SDLC implementation ----------------------------------
pipeline="/tmp/full-flow-$(date +%Y%m%d-%H%M%S).yaml"
python3 - "$DIRECTION" "$latest" "$pipeline" <<'EOF'
import os
import sys
import yaml

direction, latest, out = sys.argv[1], sys.argv[2], sys.argv[3]
with open("ai-dev/examples/full-sdlc-implement.yaml", encoding="utf-8") as f:
    data = yaml.safe_load(f)
for s in data["stages"]:
    if s.get("name") == "requirements":
        s["from_prompt"] = (
            "Analyze the snaplink codebase and produce a requirements "
            "specification for the selected expansion direction: "
            f"'{direction}' (candidate from the rolling analysis in "
            f"{latest}). Exactly 3 evidence-backed improvements: for each, "
            "name, problem, evidence (file/symbol), proposed behavior, "
            "acceptance check. Use markdown headings (## ...) for each "
            "decision so it can be indexed in the decision log."
        )
    if s.get("role_dir"):  # resolve so the temp pipeline works from any cwd
        s["role_dir"] = os.path.abspath(s["role_dir"])
with open(out, "w", encoding="utf-8") as f:
    yaml.safe_dump(data, f, sort_keys=False)
print(f"generated pipeline: {out}")
EOF

echo ""
echo "== Phase 3: full SDLC loop for '$DIRECTION' =="
python ./ai-dev/pi-batch.py "$pipeline" --log-file logs/full-flow.log

echo ""
echo "== Done =="
echo "Deliverables   : docs/proposals/ (archived into docs/archive/ on success)"
echo "Decision log   : docs/DECISIONS.md"
echo "Run log        : logs/full-flow.log"
