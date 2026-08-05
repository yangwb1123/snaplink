// k6 load test for /token/introspect — the resource-server hot path. The
// scenario interleaves a FRESH token per iteration (cold: full JWS
// validation, no cache entry) with repeated introspection of the SAME token
// (hot: cached verdict when an introspection cache is wired), so both the
// uncached floor and the cache hit rate stay under budget.
//
// Prereqs: a running sso-server with a client that allows
// client_credentials and introspection enabled.
//
// Run:
//   k6 run ops/deploy/loadtest/introspect.js
//   BASE_URL=... CLIENT_ID=... CLIENT_SECRET=... \
//     VUS=50 DURATION=30s k6 run ops/deploy/loadtest/introspect.js
import http from "k6/http";
import { check } from "k6";

const BASE = __ENV.BASE_URL || "http://127.0.0.1:8080";
const CLIENT_ID = __ENV.CLIENT_ID || "loadtest";
const CLIENT_SECRET = __ENV.CLIENT_SECRET || "loadtest-secret";
const SCOPE = __ENV.SCOPE || "openid";

export const options = {
  scenarios: {
    introspect: {
      executor: "constant-vus",
      vus: Number(__ENV.VUS || 50),
      duration: __ENV.DURATION || "30s",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<250", "p(99)<500"],
  },
};

function mintToken() {
  const res = http.post(
    `${BASE}/token`,
    {
      grant_type: "client_credentials",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      scope: SCOPE,
    },
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );
  check(res, { "mint 200": (r) => r.status === 200 });
  return res.json("access_token");
}

export default function () {
  // Cold: introspect a freshly minted token (no cache entry yet).
  const fresh = mintToken();
  const cold = http.post(
    `${BASE}/token/introspect`,
    {
      token: fresh,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    },
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );
  check(cold, { "cold introspection active": (r) => r.status === 200 && r.json("active") === true });

  // Hot: re-introspect the same token (cache hit when a cache is wired).
  const hot = http.post(
    `${BASE}/token/introspect`,
    {
      token: fresh,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    },
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );
  check(hot, { "hot introspection active": (r) => r.status === 200 && r.json("active") === true });
}
