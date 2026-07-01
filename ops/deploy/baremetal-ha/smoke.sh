#!/usr/bin/env sh
# End-to-end smoke through the edge. Proves the app is reachable via HAProxy and
# that every replica it round-robins to is ready (each backed by the same Redis
# Cluster + Postgres, so state minted on one replica is visible on another).
# Enhanced: also validates token issuance, userinfo, introspection, and revocation.
# Usage: sh smoke.sh [BASE_URL] [CLIENT_ID] [CLIENT_SECRET]
set -eu
BASE="${1:-https://localhost:8080}"
CID="${2:-smoke-test-client}"
SEC="${3:-smoke-test-secret}"

echo "=== 1/6: Discovery document ==="
curl -ks "$BASE/.well-known/openid-configuration" | grep -q '"issuer"' \
  || { echo "FAIL: discovery not served"; exit 1; }
echo "  OK"

echo "=== 2/6: Readiness probe ==="
code=$(curl -ks -o /dev/null -w '%{http_code}' "$BASE/readyz")
test "$code" = "200" || { echo "FAIL: /readyz returned $code"; exit 1; }
echo "  OK"

echo "=== 3/6: Replica round-robin ==="
i=0
while [ "$i" -lt 6 ]; do
  c=$(curl -ks -o /dev/null -w '%{http_code}' "$BASE/readyz")
  test "$c" = "200" || { echo "FAIL: readyz=$c on call $i"; exit 1; }
  i=$((i + 1))
done
echo "  OK"

echo "=== 4/6: Token issuance (client_credentials) ==="
TOKEN_RESP=*** -ks -X POST "$BASE/token" \
  -u "$CID:$SEC" \
  -d "grant_type=client_credentials&scope=openid")
AT=*** "$TOKEN_RESP" | sed 's/.*"access_token":"\([^"]*\)".*/\1/')
test -n "$AT" || { echo "FAIL: no access_token"; exit 1; }
echo "$TOKEN_RESP" | grep -q '"token_type"' || { echo "FAIL: no token_type"; exit 1; }
echo "  OK (token=$(echo "$AT" | cut -c1-20)...)"

echo "=== 5/6: Userinfo ==="
UI=$(curl -ks -H "Authorization: Bearer *** "$BASE/userinfo")
echo "$UI" | grep -q '"sub"' || { echo "FAIL: userinfo missing sub"; exit 1; }
echo "  OK"

echo "=== 6/6: Revocation + Introspection ==="
curl -ks -X POST "$BASE/token/revoke" \
  -u "$CID:$SEC" \
  -d "token=${AT}" -o /dev/null
INACTIVE=$(curl -ks -X POST "$BASE/token/introspect" \
  -u "$CID:$SEC" \
  -d "token=${AT}")
echo "$INACTIVE" | grep -q '"active":false' || { echo "FAIL: introspect not inactive"; exit 1; }
echo "  OK"

echo ""
echo "smoke OK: all 6 checks passed"
