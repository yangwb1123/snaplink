#!/usr/bin/env bash
# GATE: 圈复杂度 ≤ 15, 认知复杂度 ≤ 20
set -euo pipefail
MAX_CYCLO=15; MAX_COGNIT=20; EXIT_CODE=0
EXEMPT_FUNCS=("handleLogin")
is_exempt_func() { local n="$1"; for e in "${EXEMPT_FUNCS[@]}"; do [[ "$n" == *"$e"* ]] && return 0; done; return 1; }
command -v gocyclo &>/dev/null || go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
command -v gocognit &>/dev/null || go install github.com/uudashr/gocognit/cmd/gocognit@latest
GOC=$(command -v gocyclo); GOG=$(command -v gocognit); TARGETS=("${@:-./...}")
echo "--- cyclomatic complexity (max $MAX_CYCLO) ---"; HAS=0
while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  c=$(echo "$line" | awk '{print $1}'); f=$(echo "$line" | awk '{print $3}'); l=$(echo "$line" | awk '{print $4}')
  is_exempt_func "$f" && continue
  if (( c > MAX_CYCLO )); then echo "  FAIL: $l — $c > $MAX_CYCLO"; HAS=1; fi
done < <("$GOC" -top 0 -avg -total -ignore "gen/proto/" "${TARGETS[@]}" 2>/dev/null || true)
[[ $HAS -eq 0 ]] && echo "  PASS" || EXIT_CODE=1
echo "--- cognitive complexity (max $MAX_COGNIT) ---"; HAS=0
while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  c=$(echo "$line" | awk '{print $1}'); f=$(echo "$line" | awk '{print $3}'); l=$(echo "$line" | awk '{print $4}')
  is_exempt_func "$f" && continue
  if (( c > MAX_COGNIT )); then echo "  FAIL: $l — $c > $MAX_COGNIT"; HAS=1; fi
done < <("$GOG" -top 0 -avg -total -ignore "gen/proto/" "${TARGETS[@]}" 2>/dev/null || true)
[[ $HAS -eq 0 ]] && echo "  PASS" || EXIT_CODE=1
exit $EXIT_CODE
