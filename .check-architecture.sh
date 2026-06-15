#!/usr/bin/env bash
# GATE: 包依赖方向
set -euo pipefail
EXIT_CODE=0; ROOT="$(cd "$(dirname "$0")" && pwd)"
RULES_SRC=("oauth" "oidc" "admin" "core")
RULES_DST=("oidc" "admin" "cmd" ".")
EXCLUDE="gen/proto|proto|vendor|.git|.claude|examples|cmd/sso-server"
check_pkg() {
  local dir="$1"; local rel="${dir#$ROOT/}"; rel="${rel%/}"
  echo "$rel" | grep -qE "^($EXCLUDE)" && return 0
  for i in "${!RULES_SRC[@]}"; do
    local src="${RULES_SRC[$i]}"; local forbid="${RULES_DST[$i]}"
    case "$rel" in "$src"|"$src/"*) ;; *) continue ;; esac
    local files=$(find "$dir" -maxdepth 1 -name '*.go' ! -name '*_test.go' 2>/dev/null || true)
    [[ -n "$files" ]] || continue
    local imports=$(grep -h '"github.com/snaplink/sso/[^"]*"' $files 2>/dev/null || true)
    [[ -n "$imports" ]] || continue
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      local pkg=$(echo "$line" | sed -n 's/.*"github.com\/snaplink\/sso\/\([^"]*\)".*/\1/p')
      [[ -n "$pkg" ]] || continue
      case "$pkg" in "$forbid"|"$forbid/"*) echo "  FAIL: $rel imports $pkg (forbidden)"; EXIT_CODE=1 ;; esac
    done <<< "$imports"
  done
}
echo "--- architecture check ---"
if [[ $# -gt 0 ]]; then for p in "$@"; do check_pkg "$(cd "$p" && pwd)"; done
else while IFS= read -r -d '' d; do ls "$d"/*.go &>/dev/null 2>&1 && check_pkg "$d"; done < <(find "$ROOT" -type d -not -path '*/.git/*' -not -path '*/.claude/*' -not -path '*/gen/*' -not -path '*/proto/*' -not -path '*/vendor/*' -not -path '*/kms/*' -not -path '*/redis/*' -not -path '*/saml/*' -not -path '*/ldap/*' -not -path '*/kerberos/*' -not -path '*/radius/*' -not -path '*/extauthz/*' -not -path '*/examples/*' -print0); fi
[[ $EXIT_CODE -eq 0 ]] && echo "  PASS" || exit $EXIT_CODE
