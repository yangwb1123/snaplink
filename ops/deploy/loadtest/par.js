// k6 load test for the PAR + authorization-code path — the pushed
// authorization request flow (RFC 9126): PAR at /par, then the login
// consumes the request_uri and issues a code, exchanged at /token. Covers
// the PAR store write + single-use consume on the login path.
//
// Prereqs: a running sso-server with PAR enabled (WithPARStore) and a
// seeded password user + confidential client.
//
// Run:
//   k6 run ops/deploy/loadtest/par.js
//   BASE_URL=... CLIENT_ID=... CLIENT_SECRET=... USERNAME=... PASSWORD=... \
//     VUS=20 DURATION=30s k6 run ops/deploy/loadtest/par.js
import http from "k6/http";
import { check } from "k6";

const BASE = __ENV.BASE_URL || "http://127.0.0.1:8080";
const CLIENT_ID = __ENV.CLIENT_ID || "loadtest";
const CLIENT_SECRET = __ENV.CLIENT_SECRET || "loadtest-secret";
const USERNAME = __ENV.USERNAME || "alice";
const PASSWORD = __ENV.PASSWORD || "wonderland";
const REDIRECT = __ENV.REDIRECT_URI || "http://localhost:9999/callback";

export const options = {
  scenarios: {
    par: {
      executor: "constant-vus",
      vus: Number(__ENV.VUS || 20),
      duration: __ENV.DURATION || "30s",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<500", "p(99)<1000"],
  },
};

export default function () {
  // 1. Push the authorization request.
  const par = http.post(
    `${BASE}/par`,
    {
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      response_type: "code",
      redirect_uri: REDIRECT,
      scope: "openid",
    },
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );
  check(par, { "par 201": (r) => r.status === 201 });
  const requestUri = par.json("request_uri");
  check(par, { "request_uri issued": () => typeof requestUri === "string" && requestUri.length > 0 });

  // 2. Login consuming the request_uri (single-use PAR store read).
  const login = http.post(
    `${BASE}/auth/login`,
    JSON.stringify({
      provider: "password",
      client_id: CLIENT_ID,
      credential: { username: USERNAME, password: PASSWORD },
      request_uri: requestUri,
    }),
    { headers: { "Content-Type": "application/json" } }
  );
  check(login, { "login 200": (r) => r.status === 200 });
  const code = login.json("code");
  check(login, { "code issued": () => typeof code === "string" && code.length > 0 });

  // 3. Exchange the code.
  const exchange = http.post(
    `${BASE}/token`,
    {
      grant_type: "authorization_code",
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT,
    },
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );
  check(exchange, { "exchange 200": (r) => r.status === 200 });
}
