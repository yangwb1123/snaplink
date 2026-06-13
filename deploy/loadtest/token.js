// k6 load test for the /token client_credentials hot path — the cheapest
// high-throughput signing path (no interactive flow, one bcrypt-free client
// auth + one JWT mint per request). Gives the ">1k QPS / hot-path" claim a
// runnable number and a regression guardrail.
//
// Prereqs: a running sso-server with a client that allows client_credentials.
// Seed one in config.yaml (a confidential client with grant client_credentials)
// then point this at it.
//
// Run:
//   k6 run deploy/loadtest/token.js
//   BASE_URL=http://127.0.0.1:8080 CLIENT_ID=svc CLIENT_SECRET=... \
//     VUS=100 DURATION=60s k6 run deploy/loadtest/token.js
//
// Profile the server under load by enabling server.pprof in config.yaml and
// capturing `go tool pprof http://127.0.0.1:6060/debug/pprof/profile` mid-run.
import http from "k6/http";
import { check } from "k6";

const BASE = __ENV.BASE_URL || "http://127.0.0.1:8080";
const CLIENT_ID = __ENV.CLIENT_ID || "loadtest";
const CLIENT_SECRET = __ENV.CLIENT_SECRET || "loadtest-secret";
const SCOPE = __ENV.SCOPE || "openid";

export const options = {
  scenarios: {
    token: {
      executor: "constant-vus",
      vus: Number(__ENV.VUS || 50),
      duration: __ENV.DURATION || "30s",
    },
  },
  // Fail the run if the hot path regresses past these — turns the load test
  // into a CI-able guardrail rather than a one-off measurement.
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<250", "p(99)<500"],
  },
};

export default function () {
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
  check(res, {
    "status is 200": (r) => r.status === 200,
    "has access_token": (r) => {
      try {
        return typeof r.json("access_token") === "string";
      } catch (_e) {
        return false;
      }
    },
  });
}
