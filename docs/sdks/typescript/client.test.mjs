import assert from "node:assert/strict";
import test from "node:test";

import { SSOClient } from "./index.ts";

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

test("confidential token calls use HTTP Basic and remove body credentials", async () => {
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
  assert.deepEqual(JSON.parse(seen.body), { grant_type: "client_credentials" });
});
