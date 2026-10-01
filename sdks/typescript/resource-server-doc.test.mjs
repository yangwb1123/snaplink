// The README's resource-server examples, executed rather than trusted: the
// documented middleware shape and the documented validator shape must both
// compile and run as written.

import assert from "node:assert/strict";
import test from "node:test";

import {
  checkScope,
  createJWKSCache,
  issuerJwksUrl,
  requireSubject,
  RSError,
  rsMiddleware,
  validateToken,
} from "./index.ts";

const ISSUER = "https://sso.example.com";
const KID = "doc-kid";
const NOW_SEC = 1_700_000_000;
const T0 = NOW_SEC * 1000;

function b64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const CURVE = { name: "ECDSA", namedCurve: "P-256" };
const SIGN = { name: "ECDSA", hash: "SHA-256" };

async function fixture() {
  const keys = await crypto.subtle.generateKey(CURVE, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
  const header = b64url(
    new TextEncoder().encode(JSON.stringify({ alg: "ES256", typ: "at+jwt", kid: KID })),
  );
  const payload = b64url(
    new TextEncoder().encode(
      JSON.stringify({
        iss: ISSUER,
        sub: "user-1",
        aud: ["domain-panel-api"],
        scope: "domain:read domain:write",
        exp: NOW_SEC + 300,
        iat: NOW_SEC - 5,
      }),
    ),
  );
  const raw = new Uint8Array(
    await crypto.subtle.sign(SIGN, keys.privateKey, new TextEncoder().encode(`${header}.${payload}`)),
  );
  const cache = createJWKSCache(issuerJwksUrl(ISSUER), {
    refreshIntervalMs: 0,
    now: () => T0,
    fetch: async () =>
      new Response(JSON.stringify({ keys: [{ ...jwk, kid: KID, use: "sig", alg: "ES256" }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  });
  return { token: `${header}.${payload}.${b64url(raw)}`, jwks: cache };
}

test("README: the documented rsMiddleware example runs as written", async () => {
  const { token, jwks } = await fixture();

  const guarded = rsMiddleware(
    { issuer: ISSUER, jwks, expectedAud: "domain-panel-api", now: () => T0 },
    (request, claims) =>
      Response.json({ sub: claims.subject, scopes: claims.scopes(), path: new URL(request.url).pathname }),
  );

  const response = await guarded(
    new Request("https://panel.example.test/proxies", {
      headers: { authorization: `Bearer ${token}` },
    }),
  );

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    sub: "user-1",
    scopes: ["domain:read", "domain:write"],
    path: "/proxies",
  });
});

test("README: the documented validator + helper example runs as written", async () => {
  const { token, jwks } = await fixture();
  const issuer = ISSUER;
  let handled = "";

  try {
    const claims = await validateToken(token, {
      issuer,
      jwks,
      expectedAud: "domain-panel-api",
      now: () => T0,
    });
    checkScope(claims, "domain:write");
    handled = requireSubject(claims);
  } catch (failure) {
    if (failure instanceof RSError && failure.code === "rs_token_expired") handled = "expired";
    else throw failure;
  }

  assert.equal(handled, "user-1");
});

test("README: the documented error branch is reachable", async () => {
  const { jwks } = await fixture();
  let seen;
  try {
    await validateToken("not.a.token", { issuer: ISSUER, jwks, now: () => T0 });
  } catch (failure) {
    seen = failure instanceof RSError ? failure.code : "not-an-RSError";
  }
  assert.ok(typeof seen === "string" && seen.startsWith("rs_"));
});
