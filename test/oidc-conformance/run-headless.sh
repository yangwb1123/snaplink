#!/usr/bin/env bash
# Headless OIDC conformance run for the snaplink sso-server.
#
# Builds the harness, registers the suite's OIDC login client + admin user
# against the server under test, creates the Basic-certification plan with
# the discovery configuration, runs the oidcc-server module through a
# headless Chrome (auto-fulfilling the JSON logins), and archives the result
# under results/<commit>/.
#
# Usage: ./run-headless.sh [--module oidcc-server] [--timeout 450]
#
# Requires: docker compose v2, google-chrome, python3 (websocket-client).
set -euo pipefail
cd "$(dirname "$0")"

MODULE="${MODULE:-oidcc-server}"
TIMEOUT="${TIMEOUT:-450}"
COMPOSE=(docker compose --env-file config.env)
ISSUER_HOST="sso-issuer"
ISSUER_URL="http://${ISSUER_HOST}:8180"
DISCOVERY_URL="${ISSUER_URL}/.well-known/openid-configuration"
ADMIN_USER="openid-conformance-suite-admins"
ADMIN_PASS="S3cure-admin-pass!"
SUITE_BASE="https://localhost:8443"
SERVER_HTTP="http://127.0.0.1:8180"

say() { printf '\n== %s\n' "$*"; }

say "validating pinned server config"
"${COMPOSE[@]}" run --rm --no-deps sso-server --validate-only >/dev/null

say "starting harness"
"${COMPOSE[@]}" up -d --build >/dev/null
for i in $(seq 1 60); do
  if curl -sf "$SERVER_HTTP/health" >/dev/null 2>&1; then break; fi
  sleep 2
done
curl -sf "$SERVER_HTTP/health" >/dev/null || { echo "sso-server not healthy"; exit 1; }

say "registering suite login client (DCR)"
REG="$(curl -sf -X POST "$SERVER_HTTP/register" -H 'Content-Type: application/json' \
  -d '{"client_name":"conformance-suite","redirect_uris":["https://localhost:8443/login/oauth2/code/gitlab"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_post"}')"
CLIENT_ID="$(python3 -c "import json,sys; print(json.loads('''$REG''')['client_id'])")"
CLIENT_SECRET="$(python3 -c "import json,sys; print(json.loads('''$REG''')['client_secret'])")"

say "creating admin signup user (idempotent)"
curl -sf -X POST "$SERVER_HTTP/auth/register" -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\",\"email\":\"admin@conformance.local\"}" \
  -o /dev/null || true

say "updating suite login config and restarting the suite"
sed -i.bak -E \
  "s/^(\s*- OIDC_GITLAB_CLIENTID=).*/\1${CLIENT_ID}/; s/^(\s*- OIDC_GITLAB_SECRET=).*/\1${CLIENT_SECRET}/" \
  docker-compose.yml
"${COMPOSE[@]}" up -d --force-recreate conformance-suite >/dev/null

# The suite needs a moment to boot; wait for its login page.
for i in $(seq 1 90); do
  if curl -sk -o /dev/null "$SUITE_BASE/login.html" 2>/dev/null; then break; fi
  sleep 2
done

say "logging into the suite via the server under test (OIDC)"
COOKIE_JAR="$(mktemp)"
login_flow() {
  local auth state nonce challenge login code
  auth="$(curl -sk -b "$COOKIE_JAR" -c "$COOKIE_JAR" -o /dev/null -w '%{redirect_url}' \
    "$SUITE_BASE/oauth2/authorization/gitlab")"
  state="$(python3 - <<PY
import urllib.parse
print(urllib.parse.parse_qs(urllib.parse.urlparse('''$auth''').query).get('state',[''])[0])
PY
)"
  nonce="$(python3 - <<PY
import urllib.parse
print(urllib.parse.parse_qs(urllib.parse.urlparse('''$auth''').query).get('nonce',[''])[0])
PY
)"
  challenge="$(python3 - <<PY
import urllib.parse
print(urllib.parse.parse_qs(urllib.parse.urlparse('''$auth''').query).get('code_challenge',[''])[0])
PY
)"
  login="$(curl -sk --resolve "${ISSUER_HOST}:8180:127.0.0.1" -X POST "$ISSUER_URL/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"provider\":\"password\",\"client_id\":\"${CLIENT_ID}\",\"redirect_uri\":\"https://localhost:8443/login/oauth2/code/gitlab\",\"response_type\":\"code\",\"scope\":[\"openid\",\"email\"],\"state\":\"${state}\",\"nonce\":\"${nonce}\",\"code_challenge\":\"${challenge}\",\"code_challenge_method\":\"S256\",\"credential\":{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}}")"
  code="$(python3 -c "import json,sys; print(json.loads('''$login''').get('code',''))")"
  curl -sk -b "$COOKIE_JAR" -c "$COOKIE_JAR" -L -o /dev/null \
    "https://localhost:8443/login/oauth2/code/gitlab?code=${code}&state=${state}"
}
login_flow
curl -sk -b "$COOKIE_JAR" "$SUITE_BASE/api/currentuser" | python3 -c \
  "import json,sys; assert json.load(sys.stdin).get('isAdmin'), 'suite login failed: not admin'"

say "creating the Basic certification plan (discovery + dynamic client)"
PLAN_BODY="$(python3 - <<PY
import json, urllib.request, ssl
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request("$SUITE_BASE/api/plan/info/oidcc-basic-certification-test-plan",
    headers={"Cookie": open("$COOKIE_JAR").read()})
info = json.load(urllib.request.urlopen(req, context=ctx))
body = {
  "modules": info["modules"],
  "override": {"oidcc-server": {"server": {"discoveryUrl": "$DISCOVERY_URL"}}},
}
print(json.dumps(body))
PY
)"
PLAN_ID="$(curl -sk -b "$COOKIE_JAR" -X POST \
  "$SUITE_BASE/api/plan?planName=oidcc-basic-certification-test-plan&variant=%7B%22server_metadata%22%3A%22discovery%22%2C%22client_registration%22%3A%22dynamic_client%22%7D" \
  -H 'Content-Type: application/json' -d "$PLAN_BODY" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")"
say "plan id: $PLAN_ID"

say "starting test module ${MODULE}"
TEST_ID="$(curl -sk -b "$COOKIE_JAR" -X POST \
  "$SUITE_BASE/api/runner?test=${MODULE}&plan=${PLAN_ID}" -H 'Content-Type: application/json' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")"
say "test id: ${TEST_ID}"

COOKIE_STR="$(python3 - "$COOKIE_JAR" <<'PY'
import http.cookiejar, sys
cj = http.cookiejar.MozillaCookieJar(sys.argv[1])
cj.load(ignore_discard=True, ignore_expires=True)
print('; '.join(f'{c.name}={c.value}' for c in cj))
PY
)"
say "driving the browser (headless Chrome auto-login)"
python3 "$(dirname "$0")/drive_test.py" "$TEST_ID" "$COOKIE_STR" "$TIMEOUT" || true

say "archiving evidence"
COMMIT="$(cd ../.. && git rev-parse --short HEAD)"
OUT="results/${COMMIT}"
mkdir -p "$OUT"
curl -sk -b "$COOKIE_JAR" "$SUITE_BASE/api/log/${TEST_ID}" > "$OUT/oidcc-server.log.json"
curl -sk -b "$COOKIE_JAR" "$SUITE_BASE/api/info/${TEST_ID}" > "$OUT/oidcc-server.info.json"
curl -sk -b "$COOKIE_JAR" "$SUITE_BASE/api/plan/${PLAN_ID}" > "$OUT/plan.json"
cp config.yaml "$OUT/config.yaml"
(
  cd ../..
  git rev-parse HEAD > "$OUT/commit.txt"
  git status --porcelain > "$OUT/worktree.txt" || true
) || true
echo "artifacts in results/${COMMIT}/"

say "final test state"
curl -sk -b "$COOKIE_JAR" "$SUITE_BASE/api/info/${TEST_ID}" | python3 -c \
  "import json,sys; d=json.load(sys.stdin); print('status:', d.get('status'), '| result:', d.get('result'))"
