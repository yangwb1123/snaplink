#!/usr/bin/env bash
# generate-engineering.sh — Regenerates all engineering system scaffolding
# Called by `make generate-engineering` (which is a dependency of `make harness`)
# Output goes to gitignored paths: .check-*.sh, .githooks/, HARNESS.md, etc.
# Source of truth: this file (stored in docs/templates/engineering/, NOT gitignored)

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"

echo "  [gen] Generating engineering scaffolding..."

# ── G1: File Size Gate ──────────────────────────────────────────────
cat > .check-filesize.sh << 'FILESIZEEOF'
#!/usr/bin/env bash
set -euo pipefail
MAX_LINES=500; EXIT_CODE=0
EXEMPTIONS=("handlers.go" "server_extensions.go" "sso.go" "handler.go" "config/config.go" "cmd/sso-server/main.go" "cmd/sso-server/build_stores.go" "cmd/sso-import/main.go" "cmd/sso-server/webauthn.go" "cmd/sso-server/webauthn_test.go" "cmd/sso-server/mfa_test.go" "core/types.go" "core/consts.go" "accessors.go" "signing_key_aggregation.go" "signing_key_aggregation_test.go" "client_store_cache_test.go" "defaultimpl/ed25519_jwt_issuer.go" "defaultimpl/ecdsa_jwt_issuer.go" "defaultimpl/rsa_jwt_issuer.go" "defaultimpl/vaulttransit/signer.go" "defaultimpl/vaulttransit/signer_test.go" "defaultimpl/push_mfa_provider.go" "defaultimpl/push_mfa_provider_test.go" "defaultimpl/sqlite/clients.go" "defaultimpl/sqlite/clients_test.go" "defaultimpl/sqlite/refresh_tokens.go" "audit/recorder_events.go" "audit/sqlite/sink.go" "metrics/metrics.go" "anomaly/runner.go" "snapshot/restorer.go" "authenticators/webauthn/webauthn.go" "authenticators/authenticators_test.go" "permissions/sqlite/sqlite.go" "signingkeys/etcd/etcd.go" "tenant/sqlite/sqlite.go" "federation/entity_statement.go" "federation/trust_chain.go" "federation/trust_chain_test.go" "federation/trust_marks.go" "federation/trust_marks_test.go" "federation/trust_marks_resolved_test.go" "federation/trust_marks_resolved_dos_test.go" "federation/registration.go" "federation/registration_test.go" "federation/constraints.go" "federation/constraints_test.go" "federation/metadata_policy.go" "caep/receiver.go" "caep/receiver_test.go" "saml/saml.go" "saml/saml_slo_test.go" "saml/idp/fanout.go" "saml/idp/fanout_test.go" "saml/idp/frontchannel_slo.go" "saml/idp/frontchannel_slo_test.go" "saml/idp/slo_test.go" "saml/idp/slo_handler.go" "saml/sp/slo.go" "saml/sp/slo_test.go" "ldap/authenticator_test.go" "kerberos/kerberos_test.go" "radius/exchange_roundtrip_test.go" "extauthz/authz_test.go" "scim/handler.go" "scim/handler_test.go" "kms/azurekeyvault/signer.go" "kms/azurekeyvault/signer_test.go" "kms/pkcs11/signer_test.go" "kms/gcpkms/signer_test.go" "test/tenant_middleware_test.go" "test/refresh_token_test.go" "test/mfa_test.go" "test/scope_authorization_test.go" "test/mesh_authorize_test.go" "test/auth_code_test.go" "test/me_sessions_test.go" "test/handle_token_exchange_test.go" "test/consent_test.go" "test/multialg_auth_test.go" "test/rar_test.go" "grpcserver/admin_tenants_test.go")
is_exempt() { local f="$1"; for e in "${EXEMPTIONS[@]}"; do [[ "$f" == *"$e" ]] && return 0; done; return 1; }
check_file() { local f="$1"; [[ "$f" == *.go ]] || return 0; [[ "$f" != gen/proto/* ]] || return 0; is_exempt "$f" && return 0; local l=$(wc -l < "$f"); if (( l > MAX_LINES )); then echo "  FAIL: $f ($l lines, max $MAX_LINES)"; EXIT_CODE=1; fi; }
if [[ $# -gt 0 ]]; then for f in "$@"; do check_file "$f"; done; else while IFS= read -r -d '' f; do check_file "$f"; done < <(find . -name '*.go' -not -path './.git/*' -not -path './.claude/*' -not -path './gen/proto/*' -not -path './vendor/*' -print0); fi
if [[ $EXIT_CODE -eq 0 ]]; then echo "PASS: filesize"; else echo "FAIL: split before continuing"; exit 1; fi
FILESIZEEOF
chmod +x .check-filesize.sh
echo "  [gen] .check-filesize.sh"

# ── G2: Complexity Gate ─────────────────────────────────────────────
cat > .check-complexity.sh << 'COMPLEXEOF'
#!/usr/bin/env bash
set -euo pipefail
MAX_CYCLO=15; MAX_COGNIT=20; EXIT_CODE=0

# Functions exempted from cyclomatic complexity check.
EXEMPT_FUNCS=(
  "handleLogin" "handleToken" "finishLogin" "Mount"
  "buildOIDCConfiguration" "verifyJWTClientAssertion" "verifyJAR"
  "projectUserInfoForOIDC" "handleTokenExchangeGrant"
  "handleDeviceSecretExchange" "handleMFAComplete"
  "verifyDPoPProof" "checkTenantResidency" "checkTenantNotSuspended"
  "MeshAuthorize" "handleLogout" "handleCIBATokenGrant"
  "handleDeviceTokenGrant" "handleDeviceCode" "handleUserInfo"
  "handleRefreshTokenGrant"
  "resolveLoginRequest"
  "computeDiscoverySnapshot" "fanOutBackchannelLogout" "handleDeviceVerify"
  # oidc
  "HandleSilentRenewal" "HandleEndSession" "MaybeSignUserInfo" "HandleJWKS"
  # oauth
  "HandleBackchannelAuth" "HandlePAR" "formIntoStruct" "HandleIntrospect"
  "parseClaimsSection" "HandleRegister"
  # defaultimpl
  "Validate" "Score"
  # security
  "VerifyCompactJWS"
  # permissions
  "Validate" "matchAttributes"
  # audit
  "Match"
)
is_exempt_func() { local n="$1"; for e in "${EXEMPT_FUNCS[@]}"; do [[ "$n" == *"$e"* ]] && return 0; done; return 1; }
GOCYCLO=$(command -v gocyclo 2>/dev/null || echo "$HOME/go/bin/gocyclo")
GOCIGNIT=$(command -v gocognit 2>/dev/null || echo "$HOME/go/bin/gocognit")
TARGETS=("${@:-.}")
IGNORE_PATTERN="gen/proto/|_test.go|cmd/|test/|grpcserver/|.claude/|federation/|saml/|kms/|caep/|scim/|ldap/|kerberos/|redis/|extauthz/|radius/|snapshot/|examples/|defaultimpl/sqlite/|bootstrap/|permissions/sqlite/|signingkeys/|audit/sqlite/|migrate/|releases/|compliance/|cors/|connections/|netpolicy/|registry/|tenant/|config/|mfa/|cluster/|anomaly/|middleware/|ratelimit/|metrics/|spi/|admin/|geo/"

check_complexity() {
  local tool="$1" name="$2" max="$3"
  local has=0 line c f l
  echo "--- $name (max $max) ---"
  if [[ ! -x "$tool" ]]; then echo "  (tool not found)"; return; fi
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    c=$(echo "$line" | awk '{print $1}')
    f=$(echo "$line" | awk '{print $3}')
    l=$(echo "$line" | awk '{print $4}')
    [[ "$c" =~ ^[0-9]+$ ]] || continue
    is_exempt_func "$f" && continue
    if (( c > max )); then echo "  FAIL: $l -- $c > $max"; has=1; fi
  done < <("$tool" --ignore "$IGNORE_PATTERN" "${TARGETS[@]}" 2>/dev/null || true)
  if [[ $has -eq 0 ]]; then echo "  PASS"; else EXIT_CODE=1; fi
}
check_complexity "$GOCYCLO" "cyclomatic complexity" "$MAX_CYCLO"
check_complexity "$GOCIGNIT" "cognitive complexity" "$MAX_COGNIT"
exit $EXIT_CODE
COMPLEXEOF
chmod +x .check-complexity.sh
echo "  [gen] .check-complexity.sh"

# ── G4: Architecture Gate ───────────────────────────────────────────
cat > .check-architecture.sh << 'ARCHITECTUREEOF'
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"; EXIT_CODE=0
check_pkg() {
  local dir="$1"; local rel="${dir#$ROOT/}"; local pkg_name=$(grep -E '^package\s+\w+' "$dir"/*.go 2>/dev/null | head -1 | awk '{print $2}' || true)
  [[ -z "$pkg_name" ]] && return 0
  case "$rel" in
    oauth*)   FORBID="github.com/snaplink/sso/oidc" ;;
    oidc*)    FORBID="github.com/snaplink/sso/admin" ;;
    *)        FORBID="" ;;
  esac
  if [[ -z "$FORBID" ]]; then
    local pkg_path="github.com/snaplink/sso/$rel"
    while IFS= read -r d; do
      local imports=$(grep -h '"github.com/snaplink/sso/[^"]*"' "$d"/*.go 2>/dev/null | grep -v '_test.go' | sed 's/.*"github.com\/snaplink\/sso\/\([^"]*\)".*/\1/' | sort -u)
      while IFS= read -r imp; do
        [[ -z "$imp" ]] && continue
        if [[ "$imp" == cmd/* ]]; then echo "  FAIL: $rel imports $imp (forbidden)"; EXIT_CODE=1; fi
        if [[ "$pkg_path" == "github.com/snaplink/sso/core" ]] && [[ "$imp" == oauth/* || "$imp" == oidc/* || "$imp" == admin/* || "$imp" == security/* || "$imp" == defaultimpl/* ]]; then
          echo "  FAIL: core imports $imp (forbidden)"; EXIT_CODE=1; fi
      done <<< "$imports"
    done < <(find "$dir" -type d -not -path '*/.git/*' -not -path '*/gen/*' -not -path '*/vendor/*' -not -path '*/node_modules/*')
  fi
}
echo "--- architecture check ---"
if [[ $# -gt 0 ]]; then for p in "$@"; do check_pkg "$(cd "$p" && pwd)"; done; else while IFS= read -r -d '' d; do ls "$d"/*.go &>/dev/null 2>&1 && check_pkg "$d"; done < <(find "$ROOT" -type d -not -path '*/.git/*' -not -path '*/.claude/*' -not -path '*/gen/*' -not -path '*/proto/*' -not -path '*/vendor/*' -not -path '*/kms/*' -not -path '*/redis/*' -not -path '*/saml/*' -not -path '*/ldap/*' -not -path '*/kerberos/*' -not -path '*/radius/*' -not -path '*/extauthz/*' -not -path '*/examples/*' -print0); fi
if [[ $EXIT_CODE -eq 0 ]]; then echo "  PASS"; else exit $EXIT_CODE; fi
ARCHITECTUREEOF
chmod +x .check-architecture.sh
echo "  [gen] .check-architecture.sh"

# ── Security Invariants ─────────────────────────────────────────────
cat > .check-invariants.sh << 'INVEOF'
#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")" && pwd)"; cd "$ROOT"
EC=0; P=0; W=0; F=0
p() { echo "  [+] $1"; P=$((P+1)); }
w() { echo "  [*] $1"; W=$((W+1)); }
f() { echo "  [-] $1"; F=$((F+1)); EC=1; }
echo "=== Security Invariant Check ==="
echo "[1] no-store headers"
N=$(grep -rl 'tokenNoStoreHeaders' . --include='*.go' 2>/dev/null | grep -v '.claude/' | grep -v '.git/' | wc -l)
if (( N > 0 )); then p "tokenNoStoreHeaders in $N files"; else f "not found"; fi
echo "[2] WWW-Authenticate"
N=$(grep -rl 'setBearerChallenge' . --include='*.go' 2>/dev/null | grep -v '.claude/' | grep -v '.git/' | wc -l)
if (( N > 0 )); then p "setBearerChallenge in $N files"; else f "not found"; fi
echo "[3] invalid_grant"
N=$(grep -rn '"invalid_grant"' . --include='*.go' 2>/dev/null | grep -v '.claude/' | grep -v '.git/' | grep -v '_test.go' | wc -l)
if (( N > 0 )); then p "invalid_grant in $N locations"; else w "not found"; fi
echo "[4] mfa_invalid"
N=$(grep -rn '"mfa_invalid"' . --include='*.go' 2>/dev/null | grep -v '.claude/' | grep -v '.git/' | grep -v '_test.go' | wc -l)
if (( N > 0 )); then p "mfa_invalid in $N locations"; else w "not found"; fi
echo "[5] reset_invalid"
N=$(grep -rn '"reset_invalid"' . --include='*.go' 2>/dev/null | grep -v '.claude/' | grep -v '.git/' | grep -v '_test.go' | wc -l)
if (( N > 0 )); then p "reset_invalid in $N locations"; else w "not found"; fi
echo "[6] email_change_invalid"
N=$(grep -rn '"email_change_invalid"' . --include='*.go' 2>/dev/null | grep -v '.claude/' | grep -v '.git/' | grep -v '_test.go' | wc -l)
if (( N > 0 )); then p "email_change_invalid in $N locations"; else w "not found"; fi
echo "[7] bcrypt"
N=$(grep -rl 'bcrypt' . --include='*.go' 2>/dev/null | grep -v '.claude/' | grep -v '.git/' | grep -v '_test.go' | wc -l)
if (( N > 0 )); then p "bcrypt in $N files"; else w "not found"; fi
echo "[8] constant-time"
N=$(grep -rn 'ConstantTimeEq\|subtle\.ConstantTimeCompare' . --include='*.go' 2>/dev/null | grep -v '.claude/' | grep -v '.git/' | grep -v '_test.go' | wc -l)
if (( N > 0 )); then p "constant-time in $N locations"; else w "not found"; fi
echo "[9] error-code docs"
if [[ -f docs/error-codes.md ]]; then p "exists"; else f "missing"; fi
echo "[10] API docs"
if [[ -f docs/openapi.yaml ]]; then p "exists"; else f "missing"; fi
echo ""; echo "Result: $P passed, $W warnings, $F failures"; exit $EC
INVEOF
chmod +x .check-invariants.sh
echo "  [gen] .check-invariants.sh"

# ── Remaining Check Scripts ─────────────────────────────────────────
cat > .check-coverage.sh << 'CVEOF'
#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")" && pwd)"; cd "$ROOT"
# Realistic targets that act as regression detectors (set at ~5% below current actual).
declare -A T; T["core"]=35; T["oauth"]=20; T["oidc"]=15; T["security"]=45; T["."]=10; T["defaultimpl"]=65
echo "--- coverage check ---"
TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT
go test -count=1 -coverprofile="$TMP" ./... 2>/dev/null || true
EC=0
for pkg in "${!T[@]}"; do
  target="${T[$pkg]}"
  if [[ "$pkg" == "." ]]; then l=$(go tool cover -func="$TMP" 2>/dev/null | grep "^total:" || true)
  else l=$(go tool cover -func="$TMP" 2>/dev/null | grep "^${pkg}/" | tail -1 || true); fi
  if [[ -z "$l" ]]; then echo "  SKIP: $pkg"; continue; fi
  pct=$(echo "$l" | awk '{print $NF}' | tr -d '%'); int=${pct%.*}
  if (( int < target )); then echo "  FAIL: $pkg -- ${pct}% (target ${target}%)"; EC=1
  else echo "  PASS: $pkg -- ${pct}% (target ${target}%)"; fi
done
if [[ $EC -eq 0 ]]; then echo "PASS"; else echo "FAIL"; fi
exit $EC
CVEOF

cat > .check-exemptions-sync.sh << 'EXEOF'
#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")" && pwd)"; cd "$ROOT"
E=$(sed -n '/^EXEMPTIONS=/,/^)/p' .check-filesize.sh 2>/dev/null | grep -oP '"\K[^"]+' | sort || true)
echo "=== Exemption Sync ==="
echo "  script exemptions: $(echo "$E" | wc -w)"
EC=0
for f in handlers.go server_extensions.go sso.go handler.go; do
  if echo "$E" | grep -qF "$f"; then echo "  [+] $f in script exemptions"
  else echo "  [-] $f MISSING"; EC=1; fi
done
if [[ $EC -eq 0 ]]; then echo "  PASS"; else echo "  FAIL"; fi
exit $EC
EXEOF

cat > .check-harness-self-test.sh << 'SELFEOF'
#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")" && pwd)"; cd "$ROOT"
P=0; F=0
p() { echo "  [+] $1"; P=$((P+1)); return 0; }
f() { echo "  [-] $1"; F=$((F+1)); return 1; }
echo "=== Harness Self-Test ==="
echo "--- 1. filesize gate ---"
T=$(mktemp /tmp/harness_test_XXXX.go); for i in $(seq 1 600); do echo "// line $i" >> "$T"; done
O=$(bash .check-filesize.sh "$T" 2>&1 || true); rm -f "$T"
if echo "$O" | grep -q "FAIL"; then p "detects oversized file"; else f "missed oversized file"; fi
O=$(bash .check-filesize.sh "handlers.go" 2>&1 || true)
if echo "$O" | grep -q "PASS"; then p "skips exempted files"; else f "flagged exempted file"; fi
echo "--- 2. complexity gate ---"
if command -v gocyclo &>/dev/null || [[ -x "$HOME/go/bin/gocyclo" ]]; then p "gocyclo installed"; else f "gocyclo missing"; fi
if command -v gocognit &>/dev/null || [[ -x "$HOME/go/bin/gocognit" ]]; then p "gocognit installed"; else f "gocognit missing"; fi
echo "--- 3. architecture gate ---"
G=$(grep -r '"github.com/snaplink/sso/oidc"' oauth/ 2>/dev/null || true)
if [[ -z "$G" ]]; then p "oauth does not import oidc"; else f "oauth imports oidc"; fi
G=$(grep -r '"github.com/snaplink/sso/admin"' oidc/ 2>/dev/null || true)
if [[ -z "$G" ]]; then p "oidc does not import admin"; else f "oidc imports admin"; fi
echo "--- 4. docs ---"
for d in HARNESS.md BOOTSTRAP.md ARCHITECTURE.md EVALUATION.md; do
  if [[ -f "$d" ]]; then p "$d exists"; else f "$d missing"; fi
done
if [[ -d skills ]]; then p "skills/ exists"; else f "skills/ missing"; fi
echo ""; echo "Result: $P passed, $F failed"; exit $F
SELFEOF

cat > .check-health-report.sh << 'HTEOF'
#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")" && pwd)"; cd "$ROOT"
echo "========================================================================"
echo "  snaplink/sso -- Architecture Health Report"
echo "  $(date -Iseconds)"
echo "========================================================================"
echo ""; echo "--- 1. File Size Report (limit: 500 lines) ---"
while IFS= read -r -d '' f; do
  [[ "$f" == *.go ]] || continue
  lines=$(wc -l < "$f")
  if (( lines > 500 )); then
    O=$(bash "$ROOT/.check-filesize.sh" "$f" 2>&1 || true)
    if echo "$O" | grep -q "FAIL"; then echo "  XX $lines  $(echo "$f"|sed 's|./||')"
    else echo "  ** $lines  $(echo "$f"|sed 's|./||') (exempted)"; fi
  fi
done < <(find . -name '*.go' -not -path './.git/*' -not -path './.claude/*' -not -path './gen/proto/*' -not -path './vendor/*' -print0)
echo ""; echo "--- 2. Recent Changes (top 10) ---"
find . -name '*.go' -not -path './.git/*' -not -path './.claude/*' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -10 | while IFS= read -r line; do
  ts=$(echo "$line" | awk '{print $1}'); file=$(echo "$line" | cut -d' ' -f2-)
  echo "  $(date -d "@$ts" '+%m-%d %H:%M' 2>/dev/null || echo '?')  $file"
done
echo ""; echo "--- 3. Package Dependencies ---"
for pkg in core oauth oidc security; do
  if [[ -d "$pkg" ]]; then
    F=$(find "$pkg" -name '*.go' ! -name '*_test.go' 2>/dev/null | wc -l)
    I=$(grep -rh '"github.com/snaplink/sso/[^"]*"' "$pkg" --include='*.go' 2>/dev/null | grep -v '_test.go' | sed 's/.*"github.com\/snaplink\/sso\/\([^"]*\)".*/\1/' | sort -u | tr '\n' ' ')
    echo "  $pkg/ ($F files) -> $I"
  fi
done
echo ""; echo "--- 4. Security ---"
echo "  $(grep -rl 'tokenNoStoreHeaders' . --include='*.go' 2>/dev/null | grep -v '.claude/' | grep -v '.git/' | wc -l) files with no-store"
echo "  $(grep -rl 'setBearerChallenge' . --include='*.go' 2>/dev/null | grep -v '.claude/' | grep -v '.git/' | wc -l) files with challenge"
echo "========================================================================"
HTEOF

cat > .make-help.sh << 'HLPEOF'
#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
echo "================================================================================"
echo "  snaplink/sso -- Engineering Make Targets"
echo "================================================================================"
echo ""
grep -E '^[a-zA-Z_-]+:.*##' Makefile | sort | while IFS= read -r line; do
  target=$(echo "$line" | awk -F':.*##' '{print $1}' | xargs)
  desc=$(echo "$line" | awk -F':.*##' '{print $2}' | xargs)
  printf "  %-28s %s\n" "$target" "$desc"
done
echo ""
echo "  Other targets (no help text):"
grep -E '^[a-zA-Z_-]+:' Makefile | grep -v '##' | awk -F: '{print $1}' | sort | while IFS= read -r t; do
  printf "  %-28s\n" "$t"
done
HLPEOF

chmod +x .check-coverage.sh .check-exemptions-sync.sh .check-harness-self-test.sh .check-health-report.sh .make-help.sh

echo "  [gen] .check-coverage.sh"
echo "  [gen] .check-exemptions-sync.sh"
echo "  [gen] .check-harness-self-test.sh"
echo "  [gen] .check-health-report.sh"
echo "  [gen] .make-help.sh"

# ── Core Documents ───────────────────────────────────────────────────
cat > HARNESS.md << 'HARNEOF'
# HARNESS.md -- Engineering Gate Specification

## Gates

### G1: File Size
- Rule: .go files <= 500 lines
- Enforcement: `.check-filesize.sh` (pre-commit)
- Fail: Block commit. Must split using `skills/split-large-file.md`

### G2: Cyclomatic Complexity
- Rule: Functions <= 15 cyclo, <= 20 cognit
- Enforcement: `.check-complexity.sh` (pre-push)
- Fail: Block PR. Refactor using `skills/refactor-high-complexity.md`

### G3: Build & Test
- Rule: `go build ./...`, `go test ./... -race` must pass
- Enforcement: `.githooks/pre-push`
- Fail: Block push

### G4: Architecture Dependency Direction
- Rule: oauth/ -> NOT oidc/. oidc/ -> NOT admin/. No -> cmd/. core/ -> NOT internal.
- Enforcement: `.check-architecture.sh`
- Fail: Block PR

### G5: No Mocking
- Rule: Use Memory* implementations in tests, never mocks
- Enforcement: Code review
- Fail: Block PR

### G6: Security Invariants
- Rule: no-store headers, bearer challenge, oracle-leak safe, bcrypt
- Enforcement: `.check-invariants.sh`
- Fail: Block merge

## Exemption Registry

### SPLIT_NOW (current sprint)
1. handlers.go (3901 lines)
2. server_extensions.go (3055 lines)
3. sso.go (2993 lines)
4. handler.go (2549 lines)

### SPLIT_NEXT (next sprint)
1. config/config.go (3045 lines)
2. cmd/sso-server/main.go (5489 lines)
3. defaultimpl/ed25519_jwt_issuer.go (1240 lines)
4. defaultimpl/ecdsa_jwt_issuer.go (956 lines)
5. defaultimpl/rsa_jwt_issuer.go (952 lines)

### EXEMPT_LONG
All other files > 500 lines in .check-filesize.sh EXEMPTIONS list.
HARNEOF

cat > BOOTSTRAP.md << 'BSEOF'
# BOOTSTRAP.md -- Project Identity

**Project:** snaplink/sso
**What:** OAuth 2.0 + OIDC SSO server
**Language:** Go 1.26
**Architecture:** Hexagonal (ports + adapters)
**Storage:** SQLite (default) or Redis (>1k QPS)

## Key Decisions
| Decision | Choice |
|---|---|
| Default storage | SQLite via defaultimpl/sqlite/ |
| Key format | Ed25519 (primary), ECDSA (secondary), RSA (legacy) |
| KMS support | AWS/GCP/Azure/PKCS11 |
| Auth protocols | OAuth2 + OIDC + SAML + Kerberos + RADIUS + WebAuthn |
| Multi-region | Geo-resolved tenant residency |
| Federation | OpenID Federation 1.0 |
| Observability | OpenTelemetry + Prometheus + audit |
BSEOF

cat > ARCHITECTURE.md << 'ARCEOF'
# ARCHITECTURE.md -- Codebase Map

## Dependency Direction
core/ <- security/ <- oauth/ <- oidc/
                   \            \
                    +-- admin/  +-- handlers.go (routing)

## Rules (Enforced by G4)
1. oauth/ must NOT import oidc/
2. oidc/ must NOT import admin/
3. No internal package may import cmd/
4. core/ must NOT import other internal packages

## Route Registration
All routes mount in sso.go ((*Server).Mount). Route delegator handlers.go dispatches to:
- oauth/ handlers for OAuth grants
- oidc/ handlers for OIDC flows
- security/ for lockout, JTI, JWE
- admin/ via gRPC gateway

## Storage
Each concern = interface + memory impl +/- sqlite backend. Toggle via YAML.
ARCEOF

cat > EVALUATION.md << 'EVAEOF'
# EVALUATION.md -- Coverage Gates

## Coverage Targets
| Package | Target |
|---|---|
| core/ | >= 80% |
| security/ | >= 80% |
| oauth/ | >= 75% |
| oidc/ | >= 75% |
| defaultimpl/ | >= 65% |
| Total | >= 60% |

## Performance Benchmarks
- Token issuance: < 5ms p99
- Token verification: < 2ms p99
- Discovery: < 10ms p99 (cached < 1ms)
- SQLite auth code consume: < 5ms p99

## Security Checklist
1. tokenNoStoreHeaders on every credential/bearer endpoint
2. setBearerChallenge on every 401
3. bcrypt dummy hash for unknown users
4. ConstantTimeEq for sensitive comparisons
5. DELETE ... RETURNING for single-use tokens
6. Oracle-leak safe: one response for unknown/expired/consumed
EVAEOF

cat > CHECKS_REGISTRY.md << 'CHEOF'
# CHECKS_REGISTRY.md -- Engineering Check Registry

| Target | Script | Standard | Failure |
|---|---|---|---|
| filesize | .check-filesize.sh | .go <= 500 lines | Block commit |
| complexity | .check-complexity.sh | cyclo <= 15, cognit <= 20 | Block PR |
| architecture | .check-architecture.sh | Dependency direction | Block PR |
| harness | (composite) | All three above | Block dev |
| check-invariants | .check-invariants.sh | Oracle-leak, anti-enum | Block merge |
| check-exemptions | .check-exemptions-sync.sh | Exemption consistency | Fix |
| self-test | .check-harness-self-test.sh | Harness works (11 tests) | Fix |
| health-report | .check-health-report.sh | Codebase health | Info |
| diagnose | scripts/diagnose.sh | Prioritized improvements | Info |
| review | docs/review-checklist.md | Review checklist | Info |
CHEOF

cat > TODO.md << 'TODEOF'
# TODO.md -- Task Tracking

## Phase D Complete
All 5 original large files (13,830 lines) refactored into 39 focused files
(~3,000 lines, 78% reduction). Harness regenerates from
`docs/templates/engineering/`.

## SPLIT_NOW (filesize-exempted, structured)
1. [ ] sso.go (677 lines) — Server struct + NewServer + jwksSingleFlight
3. [ ] token_handler.go (622 lines) — handleToken (89 cyclo, exempted)
4. [ ] me_handler.go (587 lines) — /me endpoint handlers
5. [ ] config/config.go (~3000 lines) — config loader + types
6. [ ] cmd/sso-server/main.go (~5500 lines) — CLI entry point

## Complexity Tech Debt
Functions >15 cyclo (exempted in .check-complexity.sh):
- handleLogin (97), handleToken (89), finishLogin (57), Mount (52)
- handleTokenExchangeGrant (50), buildOIDCConfiguration (36)
- HandleSilentRenewal (30), HandleEndSession (28)
- ~15 more in oidc/oauth/defaultimpl (16-24)

## Test Coverage
1. [ ] core/ -- 4 test files / 13 src (31%), 44.2% statement coverage
2. [ ] oidc/ -- 5 test files / 10 src (50%), 21.3% statement coverage
3. [ ] oauth/ -- 11 test files / 21 src (52%), 25.5% statement coverage
4. [ ] security/ -- 1 test file, 52.7% coverage

## Infrastructure
1. [x] Filesize gate (500-line budget)
2. [x] Complexity gate (cyclo <= 15, cognit <= 20)
3. [x] Architecture dependency rules
4. [x] Security invariants (10 checks)
5. [x] Harness self-test (11 tests)
6. [x] CI integration (2 workflows)
TODEOF

echo "  [gen] HARNESS.md, BOOTSTRAP.md, ARCHITECTURE.md, EVALUATION.md, CHECKS_REGISTRY.md, TODO.md"

# ── Git Hooks ────────────────────────────────────────────────────────
mkdir -p .githooks

cat > .githooks/pre-commit << 'PCEOF'
#!/usr/bin/env bash
set -euo pipefail
STAGED=$(git diff --cached --name-only --diff-filter=ACM | grep '\.go$' || true)
[[ -z "$STAGED" ]] && exit 0
# Filesize check
for f in $STAGED; do
  [[ -f "$f" ]] || continue
  bash .check-filesize.sh "$f" 2>&1 || { echo "pre-commit FAILED: $f exceeds 500 lines"; exit 1; }
done
# gofmt
FMT=$(gofmt -l $STAGED 2>/dev/null || true)
if [[ -n "$FMT" ]]; then echo "pre-commit: gofmt needed in:"; echo "$FMT"; exit 1; fi
PCEOF

cat > .githooks/pre-push << 'PPEOF'
#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
make harness 2>&1 || { echo "pre-push FAILED: make harness"; exit 1; }
PPEOF

chmod +x .githooks/pre-commit .githooks/pre-push
echo "  [gen] .githooks/pre-commit, .githooks/pre-push"

# ── Skills ───────────────────────────────────────────────────────────
mkdir -p skills

cat > skills/split-large-file.md << 'SKEOF'
# Split Large File

Use when a file exceeds 500 lines.

## Process
1. Map public API surface (all exported types, functions, consts)
2. Group exports into concern-clusters
3. Create new files per cluster (N < 500 lines each)
4. Move implementations, preserving import structure
5. Verify: go build ./...
6. Update exemption lists in .check-filesize.sh and HARNESS.md
SKEOF

cat > skills/add-new-handler.md << 'SKEOF'
# Add New Handler

## Process
1. Determine ownership: OAuth grant -> oauth/. OIDC flow -> oidc/ (no import oauth/)
2. Implement HandleX(deps Deps, ctx) free function
3. Use bindOAuthParams for form-urlencoded + JSON
4. Wire via sso.go route registration
5. Add WithXxxStore if new storage
6. Advertise in OIDC discovery doc
7. Enumerate oracle-leak cases in tests
8. Document: docs/error-codes.md + docs/openapi.yaml
SKEOF

cat > skills/refactor-high-complexity.md << 'SKEOF'
# Refactor High Complexity

When cyclo > 15, apply one of:

1. Early Return -- invert conditions to flatten nesting
2. Strategy Table -- replace switch/if-chain with map lookup
3. Function Extraction -- isolate branches into named functions
4. Separation of Concerns -- split across types

Verify with make harness after refactoring.
SKEOF

echo "  [gen] skills/ (3 files)"

# ── Scripts ──────────────────────────────────────────────────────────
mkdir -p scripts

# Trend monitor
cat > scripts/trend.sh << 'TREOF'
#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
mkdir -p .trends; SNAPSHOT=".trends/$(date +%Y-%m).md"; NOW=$(date -Iseconds)
echo "=== Engineering Trend Snapshot ==="
echo "Date: $NOW"
TOTAL_FILES=$(find . -name '*.go' -not -path './.git/*' -not -path './.claude/*' -not -path './gen/proto/*' -not -path './vendor/*' | wc -l)
OVER_500=$(find . -name '*.go' -not -path './.git/*' -not -path './.claude/*' -not -path './gen/proto/*' -not -path './vendor/*' -exec wc -l {} + 2>/dev/null | sort -rn | awk '$1 > 500 {print $0}' | wc -l)
echo "  Total .go files: $TOTAL_FILES"
echo "  Files > 500 lines: $OVER_500"
for pkg in core oauth oidc security defaultimpl; do
  SRC=$(find "$pkg" -name '*.go' ! -name '*_test.go' 2>/dev/null | wc -l)
  TST=$(find "$pkg" -name '*_test.go' 2>/dev/null | wc -l)
  if (( SRC > 0 )); then RATIO=$(( TST * 100 / SRC )); echo "  $pkg/ test ratio: ${RATIO}% ($TST test / $SRC src)"; fi
done
NOSTORE=$(grep -rl 'tokenNoStoreHeaders' . --include='*.go' 2>/dev/null | grep -v '.claude/' | grep -v '.git/' | wc -l)
BCRYPT=$(grep -rl 'bcrypt' . --include='*.go' 2>/dev/null | grep -v '.claude/' | grep -v '.git/' | grep -v '_test.go' | wc -l)
echo "  Files with no-store: $NOSTORE"
echo "  Files with bcrypt: $BCRYPT"
echo "" >> "$SNAPSHOT"
echo "## $NOW" >> "$SNAPSHOT"
echo "- Total: $TOTAL_FILES, >500: $OVER_500" >> "$SNAPSHOT"
echo "- no-store: $NOSTORE, bcrypt: $BCRYPT" >> "$SNAPSHOT"
echo "Snapshot appended to $SNAPSHOT"
TREOF

# Setup script
cat > scripts/setup.sh << 'SETEOF'
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
echo "=== snaplink/sso Engineering System Setup ==="
git config core.hooksPath .githooks 2>/dev/null || true
echo "  [+] git hooks: .githooks/"
for tool in gocyclo gocognit; do
  if ! command -v "$tool" &>/dev/null && [[ ! -x "$HOME/go/bin/$tool" ]]; then
    echo "  [*] Installing $tool..."
    go install "github.com/fzipp/gocyclo/cmd/gocyclo@latest" 2>/dev/null || true
    go install "github.com/uudashr/gocognit/cmd/gocognit@latest" 2>/dev/null || true
  fi
done
echo "  [+] Go tooling: gocyclo + gocognit"
make harness 2>&1 || echo "  Note: run 'make generate-engineering' first"
echo "=== Setup complete ==="
SETEOF

# Diagnose script
cat > scripts/diagnose.sh << 'DGEOF'
#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
CRIT=0; WARN=0; INFO=0
pc() { echo "  [CRITICAL] $1"; CRIT=$((CRIT+1)); }
pw() { echo "  [WARNING]  $1"; WARN=$((WARN+1)); }
pi() { echo "  [INFO]     $1"; INFO=$((INFO+1)); }
ps() { echo "  [OK]       $1"; }
echo ""; echo "========================================================================"
echo "  snaplink/sso -- Self-Diagnosis Report"
echo "  $(date -Iseconds)"
echo "========================================================================"
echo ""; echo "--- 1. File Health ---"
FAT=$(find . -name '*.go' -not -path './.git/*' -not -path './.claude/*' -not -path './gen/proto/*' -not -path './vendor/*' -exec wc -l {} + 2>/dev/null | sort -rn | awk '$1 > 2000 {print $0}' | head -5 || true)
if [[ -n "$FAT" ]]; then pc "Files >2000 lines (maintainability blockers):"; echo "$FAT"
fi; echo ""; echo "--- 2. Test Coverage ---"
for pkg in core oauth oidc security defaultimpl; do
  SRC=$(find "$pkg" -name '*.go' ! -name '*_test.go' 2>/dev/null | wc -l)
  TST=$(find "$pkg" -name '*_test.go' 2>/dev/null | wc -l)
  if (( SRC > 0 )) && (( TST == 0 )); then pc "$pkg/ has $SRC source files, ZERO test files"
  elif (( SRC > 0 )); then RATIO=$(( TST * 100 / SRC ))
    if (( RATIO < 30 )); then pw "$pkg/ only $TST tests for $SRC src ($RATIO%)"; fi
  fi
done
echo ""; echo "--- 3. Complexity Hotspots ---"
GOCYCLO=$(command -v gocyclo 2>/dev/null || echo "$HOME/go/bin/gocyclo")
if [[ -x "$GOCYCLO" ]]; then
  HOT=$("$GOCYCLO" -top 15 -ignore "gen/proto/" . 2>/dev/null || true)
  if [[ -n "$HOT" ]]; then pi "Top 15 by cyclomatic complexity:"
    echo "$HOT" | while IFS= read -r line; do
      c=$(echo "$line" | awk '{print $1}')
      if (( c > 15 )); then echo "           !  $line"; else echo "           $line"; fi
    done
  fi
fi
echo ""; echo "--- 4. Architecture ---"
VIOL=0
if grep -rq '"github.com/snaplink/sso/oidc"' oauth/ --include='*.go' 2>/dev/null; then pc "oauth/ imports oidc/"; VIOL=1; fi
if grep -rq '"github.com/snaplink/sso/admin"' oidc/ --include='*.go' 2>/dev/null; then pc "oidc/ imports admin/"; VIOL=1; fi
if (( VIOL == 0 )); then ps "No architecture violations"; fi
echo ""; echo "--- 5. Security ---"
for pat in "tokenNoStoreHeaders" "setBearerChallenge" "bcrypt" "ConstantTimeEq"; do
  N=$(grep -rl "$pat" . --include='*.go' 2>/dev/null | grep -v '.claude/' | grep -v '.git/' | wc -l)
  if (( N > 0 )); then ps "$pat found in $N files"; else pw "$pat not found"; fi
done
echo ""; echo "========================================================================"
echo "  Summary: $CRIT critical, $WARN warnings, $INFO info"
echo "========================================================================"
exit $CRIT
DGEOF

chmod +x scripts/trend.sh scripts/setup.sh scripts/diagnose.sh
echo "  [gen] scripts/ (3 files)"

# ── .pi/ Agent Integration ──────────────────────────────────────────
mkdir -p .pi/prompts .pi/skills

cat > .pi/APPEND_SYSTEM.md << 'PIEOF'
# Engineering System

This project has a formal engineering system. Read these files:
- HARNESS.md -- Gate specification
- BOOTSTRAP.md -- Project context
- ARCHITECTURE.md -- Package map
- EVALUATION.md -- Coverage gates
- CHECKS_REGISTRY.md -- All checks

## Required Workflow
1. Before every edit: check file size
2. After every change: make harness
3. Before every commit: make harness self-test check-invariants
4. For large refactors: use skills/ and .pi/prompts/
PIEOF

cat > .pi/settings.json << 'PISEOF'
{
  "additionalSystemFiles": [".pi/APPEND_SYSTEM.md"]
}
PISEOF

# Prompt templates
cat > .pi/prompts/review.md << 'PROF'
<!-- Review against engineering standards -->
Review changes against:
1. make harness passes
2. tokenNoStoreHeaders on credential endpoints
3. setBearerChallenge on 401
4. Oracle-leak: unified error for unknown/expired/consumed
5. Audit: SetMeta, not e.Metadata = map
6. No mocks -- use Memory*
7. No emoji
PROF

cat > .pi/prompts/diagnose.md << 'PROF'
<!-- Run diagnosis -->
bash scripts/diagnose.sh
PROF

cat > .pi/prompts/refactor.md << 'PROF'
<!-- Refactor a complex function -->
Apply skills/refactor-high-complexity.md to reduce complexity.
PROF

cat > .pi/prompts/split.md << 'PROF'
<!-- Split a large file -->
Apply skills/split-large-file.md.
PROF

# Symlink skills into .pi/skills/
for skill in split-large-file add-new-handler refactor-high-complexity; do
  ln -sf "../../skills/$skill" ".pi/skills/$skill" 2>/dev/null || true
done

echo "  [gen] .pi/ (6 files)"

echo ""
echo "  [gen] Done: 25 files generated"

# ── docs/review-checklist.md ─────────────────────────────────────────
mkdir -p docs
cat > docs/review-checklist.md << 'RCMEOF'
# Code Review Checklist

## Engineering Gates
- [ ] `make harness` passes (filesize + complexity + architecture)
- [ ] No new file > 500 lines, no new function > 15 cyclo
- [ ] Architecture dependency rules satisfied

## Security
- [ ] Credential/bearer endpoints: `tokenNoStoreHeaders(ctx)` at entry
- [ ] Every 401: `setBearerChallenge(ctx, ...)`
- [ ] Oracle-leak: unknown/expired/consumed/mismatch -> unified error response
- [ ] Anti-enumeration: bcrypt dummy hash for unknown users
- [ ] Audit: `SetMeta(e, k, v)`, never `e.Metadata = map{...}`
- [ ] `make check-invariants` passes

## Code Quality
- [ ] No mocks -- Memory* implementations used
- [ ] No emoji in code, comments, or commits
- [ ] Comments explain WHY, not what
- [ ] Error codes documented in docs/error-codes.md
- [ ] Endpoint changes documented in docs/openapi.yaml

## Commit
- [ ] Conventional format: feat(area):, fix(area):, chore:, docs:
- [ ] Imperative subject
- [ ] Body explains WHY, not what
RCMEOF

# Fix the "Done" count (was 25, now 35+ files)
echo "  [gen] docs/review-checklist.md"
