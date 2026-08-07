import assert from "node:assert/strict";
import test from "node:test";

import { buildHostedLoginURL, SSOClient } from "./index.ts";

const challenge = "A".repeat(43);

test("package entry point exports both the generated client and hosted-login helper", () => {
  assert.equal(typeof SSOClient, "function");
  assert.equal(typeof buildHostedLoginURL, "function");
});

function required(overrides = {}) {
  return {
    loginPageUrl: "https://login.example.com/login/?theme=dark&client_id=stale&resource=stale&prompt=none",
    clientId: "sverp-web",
    redirectUri: "https://erp.example.com/api/auth/callback?from=login",
    responseType: "code",
    scope: ["openid", "profile", "offline_access"],
    state: "csrf-state",
    codeChallenge: challenge,
    codeChallengeMethod: "S256",
    ...overrides,
  };
}

test("builds a code + S256 hosted-login URL and preserves presentation query", () => {
  const built = new URL(buildHostedLoginURL(required({
    nonce: "oidc-nonce",
    prompt: ["login", "consent"],
    maxAge: 60,
    loginHint: "alice@example.com",
    acrValues: ["urn:example:loa:2", "urn:example:loa:3"],
    uiLocales: ["zh-CN", "en"],
    responseMode: "query",
    resource: ["https://api.example.com/a", "https://api.example.com/b"],
    claims: { userinfo: { email: { essential: true } } },
    authorizationDetails: [{ type: "payment" }],
  })));

  assert.equal(built.origin, "https://login.example.com");
  assert.equal(built.pathname, "/login/");
  assert.equal(built.searchParams.get("theme"), "dark");
  assert.equal(built.searchParams.getAll("client_id").length, 1);
  assert.equal(built.searchParams.get("client_id"), "sverp-web");
  assert.equal(built.searchParams.get("redirect_uri"), "https://erp.example.com/api/auth/callback?from=login");
  assert.equal(built.searchParams.get("response_type"), "code");
  assert.equal(built.searchParams.get("scope"), "openid profile offline_access");
  assert.equal(built.searchParams.get("state"), "csrf-state");
  assert.equal(built.searchParams.get("code_challenge"), challenge);
  assert.equal(built.searchParams.get("code_challenge_method"), "S256");
  assert.equal(built.searchParams.get("nonce"), "oidc-nonce");
  assert.equal(built.searchParams.get("prompt"), "login consent");
  assert.equal(built.searchParams.get("max_age"), "60");
  assert.equal(built.searchParams.get("login_hint"), "alice@example.com");
  assert.equal(built.searchParams.get("acr_values"), "urn:example:loa:2 urn:example:loa:3");
  assert.equal(built.searchParams.get("ui_locales"), "zh-CN en");
  assert.equal(built.searchParams.get("response_mode"), "query");
  assert.deepEqual(built.searchParams.getAll("resource"), [
    "https://api.example.com/a",
    "https://api.example.com/b",
  ]);
  assert.deepEqual(JSON.parse(built.searchParams.get("claims")), {
    userinfo: { email: { essential: true } },
  });
  assert.deepEqual(JSON.parse(built.searchParams.get("authorization_details")), [{ type: "payment" }]);
});

test("does not inherit security-sensitive optional OIDC parameters from the login-page URL", () => {
  const built = new URL(buildHostedLoginURL(required()));
  assert.equal(built.searchParams.get("theme"), "dark");
  assert.equal(built.searchParams.has("resource"), false);
  assert.equal(built.searchParams.has("prompt"), false);
});

test("allows HTTP only for loopback by default", () => {
  const built = new URL(buildHostedLoginURL(required({
    loginPageUrl: "http://localhost:13015/login/",
    redirectUri: "http://127.0.0.1:5175/api/auth/callback",
  })));
  assert.equal(built.protocol, "http:");
});

test("requires an explicit development opt-in for LAN HTTP", () => {
  assert.throws(
    () => buildHostedLoginURL(required({
      loginPageUrl: "http://192.168.123.52:13015/login/",
      redirectUri: "http://192.168.123.52:13014/api/auth/callback",
    })),
    /allowInsecureHttpForDevelopment/,
  );

  const built = new URL(buildHostedLoginURL(required({
    loginPageUrl: "http://192.168.123.52:13015/login/",
    redirectUri: "http://192.168.123.52:13014/api/auth/callback",
    allowInsecureHttpForDevelopment: true,
  })));
  assert.equal(built.hostname, "192.168.123.52");
});

test("rejects unsafe URL shapes and PKCE downgrade attempts", () => {
  for (const overrides of [
    { loginPageUrl: "/login/" },
    { loginPageUrl: "ftp://login.example.com/login/" },
    { loginPageUrl: "https://user:password@login.example.com/login/" },
    { loginPageUrl: "https://login.example.com/login/#token" },
    { redirectUri: "https://erp.example.com/callback#fragment" },
    { responseType: "token" },
    { codeChallengeMethod: "plain" },
    { codeChallenge: "too-short" },
    { scope: [] },
    { scope: ["openid profile"] },
    { maxAge: -1 },
  ]) {
    assert.throws(() => buildHostedLoginURL(required(overrides)));
  }
});

test("refuses client secrets and PKCE verifiers from properties or existing query", () => {
  assert.throws(
    () => buildHostedLoginURL(required({ clientSecret: "must-not-leak" })),
    /clientSecret must never be included/,
  );
  assert.throws(
    () => buildHostedLoginURL(required({ code_verifier: "must-not-leak" })),
    /code_verifier must never be included/,
  );
  assert.throws(
    () => buildHostedLoginURL(required({
      loginPageUrl: "https://login.example.com/login/?client_secret=must-not-leak",
    })),
    /must not contain client_secret/,
  );

  const built = buildHostedLoginURL(required());
  assert.doesNotMatch(built, /client_secret|clientSecret|code_verifier|codeVerifier/);
});
