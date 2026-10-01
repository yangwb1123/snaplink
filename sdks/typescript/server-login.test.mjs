import assert from "node:assert/strict";
import test from "node:test";

import { MemoryStateStore, SSOError, SnaplinkServerClient } from "./index.ts";

const BASE = "https://sso.example.com";
const REDIRECT = "https://app.example.com/api/auth/callback";

/** Captures the token request the client makes and answers with `tokens`. */
function fakeFetch(tokens = { access_token: "at", token_type: "Bearer", expires_in: 3600 }) {
  const calls = [];
  const impl = async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    calls.push({ url, body: String(init?.body ?? "") });
    return new Response(JSON.stringify(tokens), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  return { impl, calls };
}

function options(overrides = {}) {
  return { baseUrl: BASE, clientId: "my-app", redirectUri: REDIRECT, ...overrides };
}

async function startLogin(client, overrides = {}) {
  const result = await client.login(options(overrides));
  assert.equal(result.kind, "redirect");
  return result;
}

test("start phase returns a 302 URL carrying state and S256 PKCE", async () => {
  const client = new SnaplinkServerClient();
  const result = await startLogin(client);

  const url = new URL(result.redirectUrl);
  assert.equal(url.origin + url.pathname, `${BASE}/login/`);
  assert.equal(url.searchParams.get("client_id"), "my-app");
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("redirect_uri"), REDIRECT);
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.match(url.searchParams.get("code_challenge") ?? "", /^[A-Za-z0-9_-]{43}$/);
  assert.ok(url.searchParams.get("state"));
  assert.equal(result.returnTo, REDIRECT);
});

test("the transaction is persisted so only its own client can resume it", async () => {
  const store = new MemoryStateStore();
  const client = new SnaplinkServerClient({ store });
  const started = await startLogin(client);

  const saved = store.take("snaplink:server-login:my-app");
  assert.ok(saved, "transaction stored");
  assert.equal(saved?.state, new URL(started.redirectUrl).searchParams.get("state"));
});

test("callback phase exchanges the code with the stored verifier", async () => {
  const { impl, calls } = fakeFetch();
  const store = new MemoryStateStore();
  const client = new SnaplinkServerClient({ store, fetch: impl });
  const started = await startLogin(client);
  const state = new URL(started.redirectUrl).searchParams.get("state");
  const verifier = store.take("snaplink:server-login:my-app")?.codeVerifier;
  store.save("snaplink:server-login:my-app", {
    baseUrl: BASE,
    clientId: "my-app",
    codeVerifier: verifier,
    redirectUri: REDIRECT,
    returnTo: REDIRECT,
    state,
    createdAt: Date.now(),
  });

  const done = await client.login(
    options({
      callbackUrl: `${REDIRECT}?code=ac_1&state=${state}&iss=${encodeURIComponent(BASE)}`,
    }),
  );

  assert.equal(done.kind, "tokens");
  assert.equal(done.tokens.access_token, "at");
  const form = new URLSearchParams(calls[0].body);
  assert.equal(calls[0].url, `${BASE}/token`);
  assert.equal(form.get("grant_type"), "authorization_code");
  assert.equal(form.get("code"), "ac_1");
  assert.equal(form.get("code_verifier"), verifier);
  assert.equal(form.get("client_id"), "my-app");
});

test("a callback without an RFC 9207 issuer is refused", async () => {
  const { impl, calls } = fakeFetch();
  const client = new SnaplinkServerClient({ fetch: impl });
  const started = await startLogin(client);
  const state = new URL(started.redirectUrl).searchParams.get("state");

  await assert.rejects(
    () => client.login(options({ callbackUrl: `${REDIRECT}?code=ac_1&state=${state}` })),
    (e) => e.message.includes("issuer did not match"),
  );
  assert.equal(calls.length, 0);
});

test("a replayed callback finds no transaction", async () => {
  const client = new SnaplinkServerClient({ fetch: fakeFetch().impl });
  const started = await startLogin(client);
  const state = new URL(started.redirectUrl).searchParams.get("state");
  const callback = options({ callbackUrl: `${REDIRECT}?code=ac_1&state=${state}&iss=${encodeURIComponent(BASE)}` });

  await client.login(callback);
  await assert.rejects(() => client.login(callback), (e) => {
    assert.equal(e.error, "invalid_request");
    assert.match(e.message, /missing or expired/);
    return true;
  });
});

test("state mismatch is refused before any token request", async () => {
  const { impl, calls } = fakeFetch();
  const client = new SnaplinkServerClient({ fetch: impl });
  await startLogin(client);

  await assert.rejects(
    () => client.login(options({ callbackUrl: `${REDIRECT}?code=ac_1&state=forged&iss=${encodeURIComponent(BASE)}` })),
    (e) => e.message.includes("state did not match"),
  );
  assert.equal(calls.length, 0, "no token request for a bad state");
});

test("the TTL in force at start also bounds the callback, even if not repeated", async () => {
  const { impl, calls } = fakeFetch();
  const client = new SnaplinkServerClient({ fetch: impl });
  const started = await startLogin(client, { transactionTtlMs: 1 });
  const state = new URL(started.redirectUrl).searchParams.get("state");
  await new Promise((r) => setTimeout(r, 5));

  // No transactionTtlMs here: the stored one must win over the default.
  await assert.rejects(
    () => client.login(options({ callbackUrl: `${REDIRECT}?code=ac_1&state=${state}&iss=${encodeURIComponent(BASE)}` })),
    (e) => e.message.includes("missing or expired"),
  );
  assert.equal(calls.length, 0);
});

test("an authorization response from another issuer is refused (RFC 9207)", async () => {
  const { impl, calls } = fakeFetch();
  const client = new SnaplinkServerClient({ fetch: impl });
  const started = await startLogin(client);
  const state = new URL(started.redirectUrl).searchParams.get("state");

  await assert.rejects(
    () =>
      client.login(
        options({
          callbackUrl: `${REDIRECT}?code=ac_1&state=${state}&iss=${encodeURIComponent("https://evil.example.com")}`,
        }),
      ),
    (e) => e.message.includes("issuer did not match"),
  );
  assert.equal(calls.length, 0);
});

test("an error response surfaces the server's OAuth error code", async () => {
  const client = new SnaplinkServerClient();
  const started = await startLogin(client);
  const state = new URL(started.redirectUrl).searchParams.get("state");

  await assert.rejects(
    () =>
      client.login(
        options({
          callbackUrl: `${REDIRECT}?error=access_denied&error_description=${encodeURIComponent("nope")}&state=${state}&iss=${encodeURIComponent(BASE)}`,
        }),
      ),
    (e) => {
      assert.equal(e.error, "access_denied");
      assert.equal(e.errorDescription, "nope");
      return true;
    },
  );
});

test("a callback without a code is refused", async () => {
  const client = new SnaplinkServerClient();
  const started = await startLogin(client);
  const state = new URL(started.redirectUrl).searchParams.get("state");
  await assert.rejects(
    () => client.login(options({ callbackUrl: `${REDIRECT}?state=${state}&iss=${encodeURIComponent(BASE)}` })),
    (e) => e.message.includes("did not contain a code"),
  );
});

test("a callback URL that does not address redirectUri is a configuration error", async () => {
  const client = new SnaplinkServerClient();
  await assert.rejects(
    () => client.login(options({ callbackUrl: "https://evil.example.com/api/auth/callback?code=x" })),
    (e) => e.message.includes("does not match redirectUri"),
  );
});

test("returnTo must stay on the redirect URI origin", async () => {
  const client = new SnaplinkServerClient();
  await assert.rejects(
    () => startLogin(client, { returnTo: "https://evil.example.com/landing" }),
    (e) => e.message.includes("returnTo must use the redirectUri origin"),
  );
});

test("a returnTo on the same origin is honored", async () => {
  const client = new SnaplinkServerClient();
  const started = await startLogin(client, { returnTo: "https://app.example.com/dashboard" });
  assert.equal(started.returnTo, "https://app.example.com/dashboard");
});

test("no orphan transaction is stored when the login URL cannot be built", async () => {
  const store = new MemoryStateStore();
  const client = new SnaplinkServerClient({ store });
  await assert.rejects(() =>
    startLogin(client, { loginPageUrl: "http://login.example.com/login/" }),
  );
  assert.equal(store.take("snaplink:server-login:my-app"), undefined);
});

test("the token endpoint error is passed through unchanged", async () => {
  const impl = async () =>
    new Response(JSON.stringify({ error: "invalid_grant", error_description: "expired" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  const client = new SnaplinkServerClient({ fetch: impl });
  const started = await startLogin(client);
  const state = new URL(started.redirectUrl).searchParams.get("state");

  await assert.rejects(
    () => client.login(options({ callbackUrl: `${REDIRECT}?code=ac_1&state=${state}&iss=${encodeURIComponent(BASE)}` })),
    (e) => {
      assert.equal(e.status, 400);
      assert.equal(e.error, "invalid_grant");
      return true;
    },
  );
});

test("the store contract requires single-use take", () => {
  // A store that returns without consuming would allow callback replay.
  const store = new MemoryStateStore();
  const transaction = {
    baseUrl: BASE,
    clientId: "my-app",
    codeVerifier: "v",
    redirectUri: REDIRECT,
    returnTo: REDIRECT,
    state: "s",
    createdAt: Date.now(),
  };
  store.save("k", transaction);
  assert.deepEqual(store.take("k"), transaction);
  assert.equal(store.take("k"), undefined);
});