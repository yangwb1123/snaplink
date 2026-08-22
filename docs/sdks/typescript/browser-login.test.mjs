import assert from "node:assert/strict";
import test from "node:test";

import { SnaplinkBrowserClient, SSOError } from "./index.ts";

class MemoryStorage {
  values = new Map();

  getItem(key) {
    return this.values.get(key) ?? null;
  }

  setItem(key, value) {
    this.values.set(key, value);
  }

  removeItem(key) {
    this.values.delete(key);
  }
}

class RedirectStarted extends Error {
  constructor(url) {
    super("redirect started");
    this.url = url;
  }
}

function response(status, body) {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function harness(fetch) {
  const location = {
    href: "https://app.example.test/callback",
    assign(url) {
      throw new RedirectStarted(url);
    },
  };
  const storage = new MemoryStorage();
  const history = {
    replaceState(_data, _unused, url) {
      location.href = String(url);
    },
  };
  return { location, storage, history, fetch };
}

function options(harness) {
  return {
    baseUrl: "https://sso.example.test",
    clientId: "spa-client",
    location: harness.location,
    history: harness.history,
    storage: harness.storage,
    fetch: harness.fetch,
  };
}

test("login redirects to Console and completes the same flow with code + PKCE", async () => {
  const calls = [];
  const h = harness(async (input, init) => {
    calls.push({ input: String(input), init });
    if (String(input).endsWith("/token")) {
      return response(200, {
        access_token: "access-1",
        expires_in: 900,
        refresh_token: "refresh-1",
        token_type: "Bearer",
      });
    }
    return response(200, { sub: "alice" });
  });
  const client = new SnaplinkBrowserClient();
  const first = options(h);

  let redirect;
  try {
    await client.login(first);
    assert.fail("login should navigate before returning");
  } catch (error) {
    assert.ok(error instanceof RedirectStarted);
    redirect = error;
  }
  const loginURL = new URL(redirect.url);
  assert.equal(loginURL.pathname, "/login/");
  assert.equal(loginURL.searchParams.get("client_id"), "spa-client");
  assert.equal(loginURL.searchParams.get("response_type"), "code");
  assert.equal(loginURL.searchParams.get("code_challenge_method"), "S256");
  assert.match(loginURL.searchParams.get("code_challenge"), /^[A-Za-z0-9_-]{43}$/);
  h.location.href = `https://app.example.test/callback?code=code-1&state=${encodeURIComponent(loginURL.searchParams.get("state"))}&iss=${encodeURIComponent("https://sso.example.test")}`;

  const tokens = await client.login(first);
  assert.equal(tokens.access_token, "access-1");
  assert.equal(client.isLoggedIn, true);
  const tokenBody = new URLSearchParams(calls[0].init.body);
  assert.equal(tokenBody.get("grant_type"), "authorization_code");
  assert.equal(tokenBody.get("code"), "code-1");
  assert.match(tokenBody.get("code_verifier"), /^[A-Za-z0-9_-]{43,128}$/);
  assert.equal(tokenBody.get("client_secret"), null);

  const user = await client.api.getUserInfo();
  assert.equal(user.sub, "alice");
  assert.equal(calls[1].init.headers.Authorization, "Bearer access-1");
  assert.equal(h.location.href, "https://app.example.test/callback");
});

test("callback state and issuer are validated before the token exchange", async () => {
  const h = harness(async () => response(200, { access_token: "should-not-be-issued" }));
  const client = new SnaplinkBrowserClient();
  const first = options(h);
  let loginURL;

  await assert.rejects(
    client.login({
      ...first,
      navigate(url) {
        loginURL = new URL(url);
        throw new RedirectStarted(url);
      },
    }),
    (error) => error instanceof RedirectStarted,
  );
  h.location.href = `https://app.example.test/callback?code=code-2&state=wrong&iss=${encodeURIComponent("https://sso.example.test")}`;

  await assert.rejects(
    client.login(first),
    (error) => error instanceof SSOError && error.error === "invalid_request",
  );
  assert.equal(loginURL.searchParams.get("code_challenge_method"), "S256");
});

test("dedicated callback routes return to the original page through a one-time handoff", async () => {
  const h = harness(async (input) => {
    if (String(input).endsWith("/token")) {
      return response(200, { access_token: "access-handoff", expires_in: 900, token_type: "Bearer" });
    }
    return response(200, {});
  });
  h.location.href = "https://app.example.test/dashboard?tab=home";
  const client = new SnaplinkBrowserClient();
  const first = options({ ...h, location: h.location });
  first.redirectUri = "https://app.example.test/auth/callback";
  let loginURL;

  try {
    await client.login({
      ...first,
      navigate(url) {
        loginURL = new URL(url);
        throw new RedirectStarted(url);
      },
    });
    assert.fail("login should navigate to Console");
  } catch (error) {
    assert.ok(error instanceof RedirectStarted);
  }

  h.location.href = `https://app.example.test/auth/callback?code=code-handoff&state=${encodeURIComponent(loginURL.searchParams.get("state"))}&iss=${encodeURIComponent("https://sso.example.test")}`;
  try {
    await client.login({
      ...first,
      navigate(url) {
        throw new RedirectStarted(url);
      },
    });
    assert.fail("callback should navigate back to the original page");
  } catch (error) {
    assert.ok(error instanceof RedirectStarted);
    assert.equal(error.url, "https://app.example.test/dashboard?tab=home");
  }

  h.location.href = "https://app.example.test/dashboard?tab=home";
  const resumed = await client.login(first);
  assert.equal(resumed.access_token, "access-handoff");
  assert.equal(client.isLoggedIn, true);
});

test("browser hosted login rejects confidential-client options", async () => {
  const h = harness(async () => response(200, {}));
  const client = new SnaplinkBrowserClient();

  await assert.rejects(
    client.login({ ...options(h), clientSecret: "must-not-enter-browser" }),
    /does not accept client secrets/,
  );
});
