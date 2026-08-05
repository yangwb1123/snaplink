// k6 load test for the OIDC discovery-document endpoint — the cold cache
// path the direction names: the discovery document is TTL-cached server-side
// with a client-store fingerprint, and every cache miss triggers a full
// client enumeration + re-projection. This scenario deliberately uses a LOW
// VU count over a LONG window so the cache expires mid-run and the miss path
// is exercised (the miss cost is the regression the fingerprint gate
// protects).
//
// Prereqs: a running sso-server (discovery is always mounted).
//
// Run:
//   k6 run ops/deploy/loadtest/discovery.js
//   BASE_URL=... VUS=5 DURATION=120s k6 run ops/deploy/loadtest/discovery.js
import http from "k6/http";
import { check } from "k6";

const BASE = __ENV.BASE_URL || "http://127.0.0.1:8080";

export const options = {
  scenarios: {
    discovery: {
      executor: "constant-vus",
      vus: Number(__ENV.VUS || 5),
      duration: __ENV.DURATION || "120s",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    // The miss path (client enumeration + projection) is heavier than the
    // hot cache read; the budget guards the FINGERPRINT decision — a
    // regression back to per-request full re-projection shows up here.
    http_req_duration: ["p(95)<300", "p(99)<600"],
  },
};

export default function () {
  const res = http.get(`${BASE}/.well-known/openid-configuration`);
  check(res, {
    "discovery 200": (r) => r.status === 200,
    "issuer present": (r) => typeof r.json("issuer") === "string",
  });
}
