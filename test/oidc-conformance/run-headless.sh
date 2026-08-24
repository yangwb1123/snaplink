#!/usr/bin/env bash
# Headless OIDC conformance run for the snaplink sso-server.
#
# Builds the harness, registers the suite's OIDC login client + admin user
# against the server under test, creates the certification plan with the
# discovery configuration, runs the requested test module through a headless
# Chrome (auto-fulfilling the JSON logins), and archives the result under
# results/<commit>[-https][-fapi]/.
#
# Usage: ./run-headless.sh [--module oidcc-server] [--timeout 450]
#                          [--issuer-https] [--fapi]
#
# --issuer-https runs the HTTPS issuer topology: an nginx issuer-proxy
# terminates the self-signed cert on host 8181 and the issuer URL becomes
# https://sso-issuer:8181, so the OIDF suite's https-only checks (e.g.
# VerifyClientManagementCredentials) apply. The default (no flag) keeps the
# HTTP topology byte-identical to the committed behavior. Evidence is
# archived under results/<commit>[-https]/.
#
# --fapi runs the FAPI 2.0 Security Profile variant: mounts config-fapi.yaml
# (oauth.compliance.profile=fapi_2 inspection + PAR + es256 signing), creates
# the fapi2-security-profile-final-test-plan with the plain_fapi /
# private_key_jwt / DPoP / unsigned-PAR / plain-response variant, runs the
# fapi2-security-profile-final-happy-flow module and archives under
# results/<commit>-fapi/. The default basic topology is unchanged.
#
# Requires: docker compose v2, google-chrome, python3 (websocket-client),
# openssl; --issuer-https additionally requires keytool (JDK) to build the
# suite JVM truststore for the self-signed cert.
set -euo pipefail
cd "$(dirname "$0")"

MODULE="${MODULE:-oidcc-server}"
TIMEOUT="${TIMEOUT:-450}"
ISSUER_HTTPS=""
FAPI=""
ARCHIVE_SUFFIX=""
# CONFORMANCE_CONFIG selects the server config variant mounted at
# /etc/sso/conformance.yaml (default config.yaml — byte-identical to the
# committed behavior; --fapi switches it to config-fapi.yaml).
CONFIG_FILE="${CONFIG_FILE:-config.yaml}"
# PLAN_NAME + PLAN_VARIANT select the OIDF plan and its variant; the basic
# defaults reproduce the committed discovery+dynamic-client Basic plan.
PLAN_NAME="${PLAN_NAME:-oidcc-basic-certification-test-plan}"
PLAN_VARIANT="${PLAN_VARIANT:-{\"server_metadata\":\"discovery\",\"client_registration\":\"dynamic_client\"}}"
while [ $# -gt 0 ]; do
  case "$1" in
    --module) MODULE="$2"; shift 2 ;;
    --module=*) MODULE="${1#*=}"; shift ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --timeout=*) TIMEOUT="${1#*=}"; shift ;;
    --issuer-https) ISSUER_HTTPS=1; shift ;;
    --fapi) FAPI=1; shift ;;
    --config) CONFIG_FILE="$2"; shift 2 ;;
    --config=*) CONFIG_FILE="${1#*=}"; shift ;;
    --plan) PLAN_NAME="$2"; shift 2 ;;
    --plan=*) PLAN_NAME="${1#*=}"; shift ;;
    --variant) PLAN_VARIANT="$2"; shift 2 ;;
    --variant=*) PLAN_VARIANT="${1#*=}"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -n "${FAPI:-}" ]; then
  # FAPI 2.0 Security Profile variant: independent server config + the
  # OIDF FAPI2 SP final plan (plain_fapi, private_key_jwt client auth,
  # DPoP sender-constraining, unsigned PAR, plain response mode) and its
  # happy-flow module. The OIDF plan's DEFAULT request method is unsigned
  # PAR; snaplink's compliance profile runs in inspection mode so the run
  # proceeds while every FAPI violation is audited (see config-fapi.yaml).
  CONFIG_FILE="config-fapi.yaml"
  PLAN_NAME="fapi2-security-profile-final-test-plan"
  # fapi_request_method/fapi_response_mode are INTENTIONALLY absent: the
  # FAPI2 SP planinfo already bakes unsigned-PAR + plain-response into every
  # module's variant, so repeating them here makes the suite reject the plan
  # with 400 "Variant 'fapi_request_method' has been set by user, but test
  # plan already sets this variant for module ...". The remaining keys pick
  # plain_fapi / private_key_jwt / DPoP / simple authorization-request type.
  PLAN_VARIANT='{"fapi_profile":"plain_fapi","openid":"openid_connect","client_auth_type":"private_key_jwt","sender_constrain":"dpop","authorization_request_type":"simple"}'
  MODULE="fapi2-security-profile-final-happy-flow"
  export FAPI_CLIENT_CONFIG="$(jq -c '.client' fapi-static-clients.json)"
  export FAPI_CLIENT2_CONFIG="$(jq -c '.client2' fapi-static-clients.json)"
  ARCHIVE_SUFFIX="${ARCHIVE_SUFFIX}-fapi"
fi
# Compose interpolation picks up the config variant for the sso-server
# mount (./${CONFORMANCE_CONFIG:-config.yaml}).
export CONFORMANCE_CONFIG="${CONFIG_FILE}"

ISSUER_HOST="sso-issuer"
ISSUER_PORT="8180"
ISSUER_SCHEME="http"
# Must stay in sync with the pinned tag in docker-compose.yml (used to
# extract the JVM default truststore for the --issuer-https run).
SUITE_IMAGE="registry.gitlab.com/openid/conformance-suite:release-v5.2.1"
COMPOSE=(docker compose --env-file config.env)
if [ -n "${ISSUER_HTTPS:-}" ]; then
  ISSUER_PORT="8181"
  ISSUER_SCHEME="https"
  ARCHIVE_SUFFIX="${ARCHIVE_SUFFIX}-https"
  # Compose interpolation picks these up for the sso-server issuer and the
  # suite's OIDC provider config + JVM TLS truststore.
  export ISSUER_URL="${ISSUER_SCHEME}://${ISSUER_HOST}:${ISSUER_PORT}"
  export ISSUER_TLS_JVM_ARGS="-Djavax.net.ssl.trustStore=/certs/truststore.jks -Djavax.net.ssl.trustStorePassword=changeit"
  COMPOSE=(docker compose --env-file config.env --profile issuer-https)
fi
ISSUER_URL="${ISSUER_SCHEME}://${ISSUER_HOST}:${ISSUER_PORT}"
DISCOVERY_URL="${ISSUER_URL}/.well-known/openid-configuration"
ADMIN_USER="openid-conformance-suite-admins"
ADMIN_PASS="S3cure-admin-pass!"
SUITE_BASE="https://localhost:8443"
SERVER_HTTP="http://127.0.0.1:8180"

say() { printf '\n== %s\n' "$*"; }

# The suite JVM validates the issuer's TLS cert: the self-signed cert must
# carry the sso-issuer SAN and the suite container must trust it. Regenerate
# the (gitignored) cert only when the SAN is missing; in HTTPS mode build a
# truststore that keeps the JVM's default CAs AND the local cert (the suite
# resolves its hardcoded Google login provider's discovery at startup, so a
# bare truststore would break accounts.google.com and abort startup).
prepare_tls() {
  mkdir -p certs
  if ! openssl x509 -in certs/server.crt -noout -ext subjectAltName 2>/dev/null | grep -q "sso-issuer"; then
    say "generating self-signed cert with the sso-issuer SAN"
    openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt \
      -days 3650 -nodes -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,DNS:sso-issuer,IP:127.0.0.1"
  fi
  if [ -n "${ISSUER_HTTPS:-}" ]; then
    say "building suite JVM truststore (default CAs + self-signed cert)"
    # SUITE_IMAGE must stay in sync with the pinned tag in docker-compose.yml.
    cid="$(docker create "${SUITE_IMAGE}")"
    docker cp "${cid}:/opt/java/openjdk/lib/security/cacerts" certs/truststore.jks >/dev/null
    docker rm "${cid}" >/dev/null
    keytool -importcert -noprompt -alias snaplink -file certs/server.crt \
      -keystore certs/truststore.jks -storepass changeit
  fi
}
prepare_tls

say "validating pinned server config"
"${COMPOSE[@]}" run --rm --no-deps sso-server --validate-only -grpc-listen "" --config /etc/sso/conformance.yaml >/dev/null

say "starting harness"
"${COMPOSE[@]}" up -d --build >/dev/null
if [ -n "${ISSUER_HTTPS:-}" ]; then
  # The issuer proxy bind-mounts this config. Force recreation so a reused
  # container cannot keep an older TLS cipher policy in its nginx process.
  say "reloading issuer TLS proxy configuration"
  "${COMPOSE[@]}" up -d --force-recreate issuer-proxy >/dev/null
fi
for i in $(seq 1 60); do
  if curl -sf "$SERVER_HTTP/health" >/dev/null 2>&1; then break; fi
  sleep 2
done
curl -sf "$SERVER_HTTP/health" >/dev/null || { echo "sso-server not healthy"; exit 1; }
if [ -n "${ISSUER_HTTPS:-}" ]; then
  for i in $(seq 1 30); do
    if curl -skf "https://127.0.0.1:8181/health" >/dev/null 2>&1; then break; fi
    sleep 2
  done
  curl -skf "https://127.0.0.1:8181/health" >/dev/null || { echo "issuer proxy not healthy"; exit 1; }
fi

say "registering suite login client (DCR)"
# Only the FAPI variant declares id_token_signed_response_alg: RS256 — the
# suite's own admin-login decoder is Spring Security's hard-coded-RS256
# OidcIdTokenDecoderFactory (see results/39ecdf7a-fapi/BLOCKER.md), and the
# FAPI variant wires a dedicated RS256 id_token signing key (keys.id_token_algs
# in config-fapi.yaml) so this plain-OIDC client is served RS256 while the
# FAPI test clients stay on the ES256 primary — RS256 is forbidden only for
# the FAPI clients themselves, never for this login client. The default
# (basic) run keeps the byte-identical payload (no per-client alg, which its
# EdDSA signing cannot serve anyway).
IDTOKEN_ALG_FIELD=""
if [ -n "${FAPI:-}" ]; then IDTOKEN_ALG_FIELD=',"id_token_signed_response_alg":"RS256"'; fi
REG="$(curl -sf -X POST "$SERVER_HTTP/register" -H 'Content-Type: application/json' \
  -d "{\"client_name\":\"conformance-suite\",\"redirect_uris\":[\"https://localhost:8443/login/oauth2/code/gitlab\"],\"grant_types\":[\"authorization_code\"],\"response_types\":[\"code\"],\"token_endpoint_auth_method\":\"client_secret_post\"${IDTOKEN_ALG_FIELD}}")"
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
"${COMPOSE[@]}" up -d --force-recreate conformance-suite suite-proxy >/dev/null

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
  login="$(curl -sk --resolve "${ISSUER_HOST}:${ISSUER_PORT}:127.0.0.1" -X POST "$ISSUER_URL/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"provider\":\"password\",\"client_id\":\"${CLIENT_ID}\",\"redirect_uri\":\"https://localhost:8443/login/oauth2/code/gitlab\",\"response_type\":\"code\",\"scope\":[\"openid\",\"email\"],\"state\":\"${state}\",\"nonce\":\"${nonce}\",\"code_challenge\":\"${challenge}\",\"code_challenge_method\":\"S256\",\"credential\":{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}}")"
  code="$(python3 -c "import json,sys; print(json.loads('''$login''').get('code',''))")"
  curl -sk -b "$COOKIE_JAR" -c "$COOKIE_JAR" -L -o /dev/null \
    "https://localhost:8443/login/oauth2/code/gitlab?code=${code}&state=${state}"
}
for attempt in $(seq 1 8); do
  login_flow || true
  if curl -sk -b "$COOKIE_JAR" "$SUITE_BASE/api/currentuser" | python3 -c \
    "import json,sys; assert json.load(sys.stdin).get('isAdmin'), 'not admin'" 2>/dev/null; then
    break
  fi
  echo "  login attempt $attempt failed; retrying in 10s"
  sleep 10
done
curl -sk -b "$COOKIE_JAR" "$SUITE_BASE/api/currentuser" | python3 -c \
  "import json,sys; assert json.load(sys.stdin).get('isAdmin'), 'suite login failed: not admin'"

say "creating the ${PLAN_NAME} plan"
curl -sk -b "$COOKIE_JAR" "$SUITE_BASE/api/plan/info/${PLAN_NAME}" \
  > /tmp/planinfo.json
# Per-module config override: the FAPI 2.0 SP plan needs a discovery URL and
# a resource URL for the sender-constrained access-token call; the Basic plan
# needs only the discovery URL.
if [ "${PLAN_NAME}" = "fapi2-security-profile-final-test-plan" ]; then
  OVERRIDE_JSON="$(DISCOVERY_URL="${DISCOVERY_URL}" RESOURCE_URL="${ISSUER_URL}/userinfo" python3 - <<'PY'
import json
import os

override = {
  "server": {"discoveryUrl": os.environ["DISCOVERY_URL"]},
  "resource": {"resourceUrl": os.environ["RESOURCE_URL"]},
  "client": json.loads(os.environ["FAPI_CLIENT_CONFIG"]),
  "client2": json.loads(os.environ["FAPI_CLIENT2_CONFIG"]),
}
print(json.dumps({"fapi2-security-profile-final-happy-flow": override}, separators=(",", ":")))
PY
)"
else
  OVERRIDE_JSON="{\"oidcc-server\": {\"server\": {\"discoveryUrl\": \"${DISCOVERY_URL}\"}}}"
fi
export OVERRIDE_JSON
PLAN_BODY="$(python3 - <<PY
import json, os
info = json.load(open("/tmp/planinfo.json"))
body = {
  "modules": info["modules"],
  "override": json.loads(os.environ["OVERRIDE_JSON"]),
}
print(json.dumps(body))
PY
)"
VARIANT_ENC="$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "${PLAN_VARIANT}")"
PLAN_ID="$(curl -sk -b "$COOKIE_JAR" -X POST \
  "$SUITE_BASE/api/plan?planName=${PLAN_NAME}&variant=${VARIANT_ENC}" \
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
python3 "$(dirname "$0")/drive_test.py" "$TEST_ID" "$COOKIE_STR" "$TIMEOUT" "$ISSUER_URL" || true

say "archiving evidence"
COMMIT="$(cd ../.. && git rev-parse --short HEAD)"
OUT="$(pwd)/results/${COMMIT}${ARCHIVE_SUFFIX}"
mkdir -p "$OUT"
curl -sk -b "$COOKIE_JAR" "$SUITE_BASE/api/log/${TEST_ID}" > "$OUT/${MODULE}.log.json"
curl -sk -b "$COOKIE_JAR" "$SUITE_BASE/api/info/${TEST_ID}" > "$OUT/${MODULE}.info.json"
curl -sk -b "$COOKIE_JAR" "$SUITE_BASE/api/plan/${PLAN_ID}" > "$OUT/plan.json"
cp "${CONFIG_FILE}" "$OUT/config.yaml"
(cd ../.. && git rev-parse HEAD > "$OUT/commit.txt" 2>/dev/null || true)
(cd ../.. && git status --porcelain > "$OUT/worktree.txt" 2>/dev/null || true)
echo "artifacts in results/${COMMIT}${ARCHIVE_SUFFIX}/"

say "final test state"
curl -sk -b "$COOKIE_JAR" "$SUITE_BASE/api/info/${TEST_ID}" | python3 -c \
  "import json,sys; d=json.load(sys.stdin); print('status:', d.get('status'), '| result:', d.get('result'))"
