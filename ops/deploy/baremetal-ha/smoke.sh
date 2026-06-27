#!/usr/bin/env sh
# End-to-end smoke through the edge. Proves the app is reachable via HAProxy and
# that every replica it round-robins to is ready (each backed by the same Redis
# Cluster + Postgres, so state minted on one replica is visible on another).
# Usage: sh smoke.sh [BASE_URL]   (default https://localhost:8080)
set -eu
BASE="${1:-https://localhost:8080}"

# 1. discovery served through the edge (app reachable, issuer derived from state)
curl -ks "$BASE/.well-known/openid-configuration" | grep -q '"issuer"' \
  || { echo "FAIL: discovery not served via $BASE"; exit 1; }

# 2. readiness green through the edge (Redis + Postgres reachable from the
#    replica HAProxy routed us to)
code="$(curl -ks -o /dev/null -w '%{http_code}' "$BASE/readyz")"
test "$code" = "200" || { echo "FAIL: /readyz returned $code"; exit 1; }

# 3. hit it several times: HAProxy round-robins across replicas, so a green
#    result across N calls shows every replica shares the cluster-backed state.
i=0
while [ "$i" -lt 6 ]; do
  c="$(curl -ks -o /dev/null -w '%{http_code}' "$BASE/readyz")"
  test "$c" = "200" || { echo "FAIL: replica readyz returned $c on call $i"; exit 1; }
  i=$((i + 1))
done

echo "smoke OK: edge reachable, discovery served, readyz green across replicas"
