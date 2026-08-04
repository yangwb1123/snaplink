#!/usr/bin/env sh
# End-to-end smoke through the TLS edge. Credentials are operator-provisioned;
# the script never creates a client or prints a bearer token.
set -eu

base_url="${1:-https://localhost:8443}"
client_id="${2:-}"
client_secret="${3:-}"
curl_tls_args=""
if [ "${SNAPLINK_SMOKE_INSECURE_TLS:-false}" = "true" ]; then
  curl_tls_args="-k"
fi

request() {
  # shellcheck disable=SC2086 -- one controlled optional -k argument.
  curl --fail --silent --show-error $curl_tls_args "$@"
}

echo "1/3 discovery"
request "$base_url/.well-known/openid-configuration" | grep -q '"issuer"'

echo "2/3 readiness and replica routing"
i=0
while [ "$i" -lt 6 ]; do
  request "$base_url/readyz" >/dev/null
  i=$((i + 1))
done

if [ -z "$client_id" ] || [ -z "$client_secret" ]; then
  echo "3/3 credential flow skipped: pass CLIENT_ID and CLIENT_SECRET to enable it"
  echo "smoke OK: TLS discovery/readiness passed"
  exit 0
fi

echo "3/3 client_credentials, introspection, and revocation"
token_response=$(request -X POST "$base_url/token" \
  -u "$client_id:$client_secret" \
  -d "grant_type=client_credentials")
access_token=$(printf '%s' "$token_response" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
test -n "$access_token" || { echo "FAIL: token response has no access_token" >&2; exit 1; }

active=$(request -X POST "$base_url/token/introspect" \
  -u "$client_id:$client_secret" \
  --data-urlencode "token=$access_token")
printf '%s' "$active" | grep -q '"active":true'

request -X POST "$base_url/token/revoke" \
  -u "$client_id:$client_secret" \
  --data-urlencode "token=$access_token" >/dev/null
inactive=$(request -X POST "$base_url/token/introspect" \
  -u "$client_id:$client_secret" \
  --data-urlencode "token=$access_token")
printf '%s' "$inactive" | grep -q '"active":false'

echo "smoke OK: token was issued, introspected, revoked, and became inactive"
