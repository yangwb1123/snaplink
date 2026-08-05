// k6 load test for the FULL authorization-code login chain — the
// user-perceivable SLO the token-only scenario cannot see: password
// authentication -> PKCE code issuance -> /token exchange -> /userinfo.
// Guards against whole-login regressions (store fan-out, session creation,
// code single-use) that micro-benchmarks miss.
//
// Prereqs: a running sso-server seeded with a confidential client
// (redirect_uri http://localhost:9999/callback) AND a login user
// (authenticators.password). Each VU reuses its own fresh code per
// iteration (codes are single-use by design).
//
// Run:
//   k6 run ops/deploy/loadtest/authcode.js
//   BASE_URL=... CLIENT_ID=... CLIENT_SECRET=... USERNAME=... PASSWORD=... \
//     VUS=20 DURATION=30s k6 run ops/deploy/loadtest/authcode.js
import http from "k6/http";
import { check, sleep } from "k6";
import crypto from "k6/crypto";
import encoding from "k6/encoding";

const BASE = __ENV.BASE_URL || "http://127.0.0.1:8080";
const CLIENT_ID = __ENV.CLIENT_ID || "loadtest";
const CLIENT_SECRET = __ENV.CLIENT_SECRET || "loadtest-secret";
const USERNAME = __ENV.USERNAME || "alice";
const PASSWORD = __ENV.PASSWORD || "wonderland";
const REDIRECT = __ENV.REDIRECT_URI || "http://localhost:9999/callback";
const SCOPE = __ENV.SCOPE || "openid";

// RFC 7636 S256 challenge over a per-iteration random verifier.
function pkcePair() {
  const verifier = encoding.b64encode(crypto.randomBytes(32), "rawurl");
  const challenge = encoding.b64encode(crypto.sha256(verifier, "binary"), "rawurl");
  return { verifier, challenge };
}

export const options = {
  scenarios: {
    authcode: {
      executor: "constant-vus",
      vus: Number(__ENV.VUS || 20),
      duration: __ENV.DURATION || "30s",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    // The full chain is slower than the bare /token path; the budget is
    // deliberately looser but still a regression guardrail.
    http_req_duration: ["p(95)<500", "p(99)<1000"],
  },
};

export default function () {
  const pkce = pkcePair();

  // 1. Password login issuing an authorization code (PKCE-bound).
  const login = http.post(
    `${BASE}/auth/login`,
    JSON.stringify({
      provider: "password",
      client_id: CLIENT_ID,
      credential: { username: USERNAME, password: PASSWORD },
      response_type: "code",
      redirect_uri: REDIRECT,
      code_challenge: pkce.challenge,
      code_challenge_method: "S256",
    }),
    { headers: { "Content-Type": "application/json" } }
  );
  check(login, { "login 200": (r) => r.status === 200 });
  const code = login.json("code");
  check(login, { "code issued": () => typeof code === "string" && code.length > 0 });

  // 2. Exchange the code (PKCE verifier) for tokens.
  const exchange = http.post(
    `${BASE}/token`,
    {
      grant_type: "authorization_code",
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT,
      code_verifier: pkce.verifier,
    },
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );
  check(exchange, { "exchange 200": (r) => r.status === 200 });
  const access = exchange.json("access_token");
  check(exchange, { "access_token minted": () => typeof access === "string" && access.length > 0 });

  // 3. /userinfo round-trip with the minted token (read gate).
  const userinfo = http.get(`${BASE}/userinfo`, {
    headers: { Authorization: `Bearer ${access}` },
  });
  check(userinfo, { "userinfo 200": (r) => r.status === 200 });

  sleep(0.1);
}
