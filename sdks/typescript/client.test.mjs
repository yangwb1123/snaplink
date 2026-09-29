import assert from "node:assert/strict";
import test from "node:test";

import { SSOClient, SSOError } from "./index.ts";

function response(status, body) {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test("login captures a token and attaches it to userinfo", async () => {
  const calls = [];
  const client = new SSOClient({
    baseUrl: "https://sso.example.test",
    clientId: "web",
    fetch: async (input, init) => {
      calls.push({ url: String(input), init });
      if (String(input).endsWith("/auth/login")) {
        return response(200, { access_token: "access-1", token_type: "Bearer" });
      }
      return response(200, { sub: "alice", email: "alice@example.test" });
    },
  });

  const login = await client.login("alice", "secret");
  assert.equal(login.access_token, "access-1");
  assert.equal(client.isLoggedIn, true);
  const user = await client.getUserInfo();
  assert.equal(user.sub, "alice");
  assert.equal(calls[1].init.headers.Authorization, "Bearer access-1");
});

test("confidential token calls use HTTP Basic and send form-urlencoded bodies", async () => {
  let seen;
  const client = new SSOClient({
    baseUrl: "https://sso.example.test",
    clientId: "backend",
    clientSecret: "secret",
    fetch: async (_input, init) => {
      seen = init;
      return response(200, { access_token: "access-2", token_type: "Bearer" });
    },
  });

  await client.postToken({
    grant_type: "client_credentials",
    client_id: "body-id",
    client_secret: "body-secret",
  });
  assert.equal(seen.headers.Authorization, "Basic YmFja2VuZDpzZWNyZXQ=");
  // The credential family sends application/x-www-form-urlencoded bodies
  // (the RFC-mandated wire; B4-4 Content-Type enforcement). Credentials are
  // stripped to the Basic header BEFORE serialization.
  assert.equal(seen.headers["Content-Type"], "application/x-www-form-urlencoded");
  assert.equal(seen.body, "grant_type=client_credentials");
});

test("form serialization: bools, repeated string-array keys, JSON-string objects", async () => {
  const calls = [];
  const client = new SSOClient({
    baseUrl: "https://sso.example.test",
    clientId: "backend",
    clientSecret: "secret",
    fetch: async (_input, init) => {
      calls.push(init);
      return response(200, { request_uri: "urn:ietf:params:oauth:request_uri:abc", expires_in: 90 });
    },
  });

  await client.postDeviceVerify({ approve: true, user_code: "WXYZ-1234" });
  assert.equal(calls[0].headers["Content-Type"], "application/x-www-form-urlencoded");
  assert.equal(calls[0].body, "approve=true&user_code=WXYZ-1234");

  await client.postPAR({
    client_id: "backend",
    response_type: "code",
    redirect_uri: "https://app.example/cb",
    resource: ["https://rs1.example", "https://rs2.example"],
    claims: { userinfo: { email: null } },
  });
  const params = new URLSearchParams(calls[1].body);
  assert.equal(calls[1].headers["Content-Type"], "application/x-www-form-urlencoded");
  assert.equal(calls[1].headers.Authorization, "Basic YmFja2VuZDpzZWNyZXQ=");
  // Basic-strip runs BEFORE serialization: credentials never reach the form body.
  assert.equal(params.get("client_id"), null);
  assert.equal(params.get("client_secret"), null);
  assert.equal(params.get("response_type"), "code");
  assert.deepEqual(params.getAll("resource"), ["https://rs1.example", "https://rs2.example"]);
  assert.equal(params.get("claims"), '{"userinfo":{"email":null}}');
});

test("postMFAComplete rejects the params map client-side (no wire attempt)", async () => {
  let calls = 0;
  const client = new SSOClient({
    baseUrl: "https://sso.example.test",
    fetch: async (_input, _init) => {
      calls += 1;
      return response(200, { status: "ok" });
    },
  });

  await assert.rejects(
    client.postMFAComplete({ params: {}, mfa_challenge_id: "c", mfa_method: "totp" }),
    (err) => err instanceof SSOError && err.error === "invalid_request" && err.status === 0,
  );
  assert.equal(calls, 0, "no wire attempt when params is present");
});
