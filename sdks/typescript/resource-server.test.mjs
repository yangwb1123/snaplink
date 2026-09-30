// Resource-server validation: the gate order, the claim gates, and the
// anti-oracle collapses that keep a 401 from becoming a token oracle.
//
// Tokens are minted here with a real WebCrypto key so signature verification is
// genuinely exercised; the signing helper is test-local and not part of the SDK.

import assert from "node:assert/strict";
import test from "node:test";

import {
  checkAnyScope,
  checkScope,
  createJWKSCache,
  DEFAULT_MAX_CLOCK_SKEW_SEC,
  extractToken,
  hasScope,
  issuerJwksUrl,
  requireSubject,
  RSClaims,
  RSError,
  rsMiddleware,
  validateToken,
  validateTokenByMode,
  validateTokenWithIntrospect,
  wwwAuthenticate,
} from "./index.ts";

const ISSUER = "https://sso.example.test";
const KID = "k1";
const NOW_MS = 1_700_000_000_000;
const NOW_SEC = Math.floor(NOW_MS / 1000);

function b64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const ECDSA_CURVE = { name: "ECDSA", namedCurve: "P-256" };
const ECDSA_SIGN = { name: "ECDSA", hash: "SHA-256" };

async function signingKey() {
  return crypto.subtle.generateKey(ECDSA_CURVE, true, ["sign", "verify"]);
}

async function publicJwk(key, kid) {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  return { ...jwk, kid, use: "sig", alg: "ES256" };
}

/** Mint an ES256 access token stamped the way this authorization server stamps
 * one: `typ: at+jwt`, an asymmetric alg, and the RFC 9068 §2.2 claim set. */
async function mintToken(key, claims, header = {}) {
  const protectedHeader = b64url(
    new TextEncoder().encode(JSON.stringify({ alg: "ES256", typ: "at+jwt", kid: KID, ...header })),
  );
  const payload = b64url(new TextEncoder().encode(JSON.stringify(claims)));
  const signingInput = new TextEncoder().encode(`${protectedHeader}.${payload}`);
  const raw = new Uint8Array(await crypto.subtle.sign(ECDSA_SIGN, key, signingInput));
  return `${protectedHeader}.${payload}.${b64url(raw)}`;
}

function baseClaims(overrides = {}) {
  return {
    iss: ISSUER,
    sub: "user-1",
    aud: ["domain-panel-api"],
    client_id: "sso-admin-console",
    scope: "domain:read domain:write",
    jti: "jti-1",
    exp: NOW_SEC + 300,
    iat: NOW_SEC - 10,
    ...overrides,
  };
}

function cacheFor(keys, init = {}) {
  let calls = 0;
  const cache = createJWKSCache(`${ISSUER}/.well-known/jwks.json`, {
    refreshIntervalMs: 0,
    now: () => NOW_MS,
    fetch: async () => {
      calls += 1;
      return new Response(JSON.stringify({ keys }), {
        status: 200,
        headers: { "content-type": "application/json" },
        ...init,
      });
    },
  });
  return { cache, calls: () => calls };
}

const config = (cache, overrides = {}) => ({
  issuer: ISSUER,
  jwks: cache,
  expectedAud: "domain-panel-api",
  now: () => NOW_MS,
  ...overrides,
});

test("a well-formed ES256 access token validates and projects its claims", async () => {
  const key = await signingKey();
  const { cache } = cacheFor([await publicJwk(key.publicKey, KID)]);
  const token = await mintToken(key.privateKey, baseClaims({ tenant_id: "acme", serving_region: "eu" }));

  const claims = await validateToken(token, config(cache));

  assert.ok(claims instanceof RSClaims);
  assert.equal(claims.subject, "user-1");
  assert.equal(claims.clientId, "sso-admin-console");
  assert.ok(claims.hasAudience("domain-panel-api"));
  assert.deepEqual([...claims.audience], ["domain-panel-api"]);
  assert.equal(claims.tenantId, "acme");
  assert.equal(claims.servingRegion, "eu");
  assert.ok(claims.hasTenantId());
  assert.ok(claims.hasServingRegion());
  assert.deepEqual(claims.scopes(), ["domain:read", "domain:write"]);
});

test("a string aud claim is normalized to a list", async () => {
  const key = await signingKey();
  const { cache } = cacheFor([await publicJwk(key.publicKey, KID)]);
  const token = await mintToken(key.privateKey, baseClaims({ aud: "domain-panel-api" }));

  const claims = await validateToken(token, config(cache));

  assert.deepEqual([...claims.audience], ["domain-panel-api"]);
});

test("the typ gate rejects a misrouted ID token before any signature work", async () => {
  const key = await signingKey();
  const { cache, calls } = cacheFor([await publicJwk(key.publicKey, KID)]);
  const token = await mintToken(key.privateKey, baseClaims(), { typ: "JWT" });

  await assert.rejects(validateToken(token, config(cache)), (error) => {
    assert.ok(error instanceof RSError);
    assert.equal(error.code, "rs_token_type_mismatch");
    return true;
  });
  // Rejected before the JWKS was ever consulted: a misrouted token must not be
  // able to induce a key fetch.
  assert.equal(calls(), 0);
});

test("alg none is refused even when the caller allowlists it", async () => {
  const key = await signingKey();
  const { cache } = cacheFor([await publicJwk(key.publicKey, KID)]);
  const header = b64url(
    new TextEncoder().encode(JSON.stringify({ alg: "none", typ: "at+jwt", kid: KID })),
  );
  const payload = b64url(new TextEncoder().encode(JSON.stringify(baseClaims())));
  const token = `${header}.${payload}.${b64url(new Uint8Array([1, 2, 3]))}`;

  await assert.rejects(
    validateToken(token, config(cache, { allowedAlgs: ["none", "ES256"] })),
    (error) => {
      assert.ok(error instanceof RSError);
      assert.equal(error.code, "rs_signature_invalid");
      return true;
    },
  );
});

test("an HMAC alg is refused even when the caller allowlists it", async () => {
  const key = await signingKey();
  const { cache } = cacheFor([await publicJwk(key.publicKey, KID)]);
  const header = b64url(
    new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: "at+jwt", kid: KID })),
  );
  const payload = b64url(new TextEncoder().encode(JSON.stringify(baseClaims())));
  const token = `${header}.${payload}.${b64url(new Uint8Array([4, 5, 6]))}`;

  await assert.rejects(
    validateToken(token, config(cache, { allowedAlgs: ["HS256"] })),
    (error) => {
      assert.ok(error instanceof RSError);
      assert.equal(error.code, "rs_signature_invalid");
      return true;
    },
  );
});

test("an unknown kid and a bad signature are indistinguishable", async () => {
  const key = await signingKey();
  const { cache } = cacheFor([await publicJwk(key.publicKey, KID)]);

  // Signed by a key that was never published.
  const stranger = await signingKey();
  const forged = await mintToken(stranger.privateKey, baseClaims());
  const forgedError = await validateToken(forged, config(cache)).catch((error) => error);

  // A kid the JWKS does not carry.
  const unknownKid = await mintToken(key.privateKey, baseClaims(), { kid: "other" });
  const unknownKidError = await validateToken(unknownKid, config(cache)).catch((error) => error);

  assert.ok(forgedError instanceof RSError);
  assert.ok(unknownKidError instanceof RSError);
  assert.equal(forgedError.code, "rs_signature_invalid");
  assert.equal(unknownKidError.code, "rs_signature_invalid");
});

test("claim gates reject issuer, audience, expiry, nbf and iat", async () => {
  const key = await signingKey();
  const { cache } = cacheFor([await publicJwk(key.publicKey, KID)]);

  const cases = [
    ["issuer mismatch", { iss: "https://evil.test" }],
    ["audience mismatch", { aud: ["billing-api"] }],
    ["expired", { exp: NOW_SEC - DEFAULT_MAX_CLOCK_SKEW_SEC - 1 }],
    ["not yet valid", { nbf: NOW_SEC + DEFAULT_MAX_CLOCK_SKEW_SEC + 1 }],
    ["iat in the future", { iat: NOW_SEC + DEFAULT_MAX_CLOCK_SKEW_SEC + 1 }],
  ];

  for (const [label, claims, overrides] of cases) {
    const token = await mintToken(key.privateKey, baseClaims(claims));
    await assert.rejects(
      validateToken(token, config(cache, overrides ?? {})),
      (error) => {
        assert.ok(error instanceof RSError, label);
        assert.notEqual(error.code, "rs_config", label);
        return true;
      },
      label,
    );
  }
});

test("a missing exp is malformed, not expired", async () => {
  const key = await signingKey();
  const { cache } = cacheFor([await publicJwk(key.publicKey, KID)]);
  const claims = baseClaims();
  delete claims.exp;
  const token = await mintToken(key.privateKey, claims);

  await assert.rejects(validateToken(token, config(cache)), (error) => {
    assert.ok(error instanceof RSError);
    assert.equal(error.code, "rs_token_malformed");
    return true;
  });
});

test("clock skew tolerates a just-expired token up to the tolerance", async () => {
  const key = await signingKey();
  const { cache } = cacheFor([await publicJwk(key.publicKey, KID)]);
  const token = await mintToken(key.privateKey, baseClaims({ exp: NOW_SEC - 5 }));

  const claims = await validateToken(token, config(cache));
  assert.ok(claims.expiresAt > 0);
});

test("a missing issuer or key source is a config error, distinct from a token error", async () => {
  await assert.rejects(validateToken("a.b.c", { issuer: "" }), (error) => {
    assert.ok(error instanceof RSError);
    assert.equal(error.code, "rs_config");
    return true;
  });
  await assert.rejects(validateToken("a.b.c", { issuer: ISSUER }), (error) => {
    assert.ok(error instanceof RSError);
    assert.equal(error.code, "rs_config");
    return true;
  });
});

test("a non-compact token is malformed", async () => {
  const { cache } = cacheFor([]);
  for (const token of ["", "a.b", "a.b.c.d", "a..c"]) {
    await assert.rejects(validateToken(token, config(cache)), (error) => {
      assert.ok(error instanceof RSError);
      assert.equal(error.code, "rs_token_malformed");
      return true;
    });
  }
});

test("region governance is opt-in and fail-closed when configured", async () => {
  const key = await signingKey();
  const { cache } = cacheFor([await publicJwk(key.publicKey, KID)]);

  // Opt-out: a token with no region claim passes.
  const noRegion = await mintToken(key.privateKey, baseClaims());
  await validateToken(noRegion, config(cache));

  // Opt-in: that same token is denied, because an unverifiable mint provenance
  // cannot satisfy a region-pinned deployment.
  await assert.rejects(
    validateToken(noRegion, config(cache, { allowedServingRegions: ["eu"] })),
    (error) => {
      assert.ok(error instanceof RSError);
      assert.equal(error.code, "rs_serving_region_mismatch");
      return true;
    },
  );

  const eu = await mintToken(key.privateKey, baseClaims({ serving_region: "eu" }));
  await validateToken(eu, config(cache, { allowedServingRegions: ["eu", "us"] }));
});

test("scope helpers read only the token's own claim", async () => {
  const key = await signingKey();
  const { cache } = cacheFor([await publicJwk(key.publicKey, KID)]);
  const claims = await validateToken(
    await mintToken(key.privateKey, baseClaims()),
    config(cache),
  );

  assert.ok(hasScope(claims, "domain:read"));
  assert.ok(!hasScope(claims, "domain:admin"));
  checkScope(claims, "domain:read", "domain:write");
  assert.throws(() => checkScope(claims, "domain:read", "domain:admin"), (error) => {
    assert.ok(error instanceof RSError);
    assert.equal(error.code, "rs_insufficient_scope");
    return true;
  });
  checkAnyScope(claims, "domain:admin", "domain:write");
  assert.throws(() => checkAnyScope(claims), (error) => {
    assert.ok(error instanceof RSError);
    assert.equal(error.code, "rs_insufficient_scope");
    return true;
  });
  assert.equal(requireSubject(claims), "user-1");
});

test("a machine token without sub cannot satisfy a user-only guard", async () => {
  const key = await signingKey();
  const { cache } = cacheFor([await publicJwk(key.publicKey, KID)]);
  const claims = await validateToken(
    await mintToken(key.privateKey, baseClaims({ sub: undefined })),
    config(cache),
  );

  assert.throws(() => requireSubject(claims), (error) => {
    assert.ok(error instanceof RSError);
    assert.equal(error.code, "rs_subject_missing");
    return true;
  });
});

test("the challenge stays opaque: invalid_token carries no gate detail", () => {
  assert.equal(wwwAuthenticate(new RSError("rs_issuer_mismatch", "iss")), 'Bearer error="invalid_token"');
  assert.equal(wwwAuthenticate(new RSError("rs_token_expired", "exp")), 'Bearer error="invalid_token"');
  assert.equal(wwwAuthenticate(new RSError("rs_token_malformed", "x")), 'Bearer error="invalid_token"');
  assert.equal(
    wwwAuthenticate(new RSError("rs_insufficient_scope", "domain:write"), ["domain:write"]),
    'Bearer error="insufficient_scope", scope="domain:write"',
  );
  assert.equal(
    wwwAuthenticate(new RSError("rs_insufficient_scope", "x")),
    'Bearer error="insufficient_scope"',
  );
});

test("introspection separates an inactive token from an endpoint outage", async () => {
  const inactive = {
    introspectUrl: `${ISSUER}/token/introspect`,
    introspectCreds: { id: "rs", secret: "s" },
    issuer: ISSUER,
    expectedAud: "domain-panel-api",
    now: () => NOW_MS,
    fetch: async () =>
      new Response(JSON.stringify({ active: false }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  };
  await assert.rejects(validateTokenWithIntrospect("opaque", inactive), (error) => {
    assert.ok(error instanceof RSError);
    assert.equal(error.code, "rs_token_inactive");
    return true;
  });

  const outage = { ...inactive, fetch: async () => { throw new Error("connection refused"); } };
  await assert.rejects(validateTokenWithIntrospect("opaque", outage), (error) => {
    assert.ok(error instanceof RSError);
    assert.equal(error.code, "rs_introspection_failed");
    return true;
  });
});

test("introspection refuses to run unauthenticated", async () => {
  await assert.rejects(
    validateTokenWithIntrospect("opaque", {
      issuer: ISSUER,
      introspectUrl: `${ISSUER}/token/introspect`,
    }),
    (error) => {
      assert.ok(error instanceof RSError);
      assert.equal(error.code, "rs_config");
      return true;
    },
  );
});

test("an active introspection response validates through the same claim gates", async () => {
  const active = {
    introspectUrl: `${ISSUER}/token/introspect`,
    introspectCreds: { id: "rs", secret: "s" },
    issuer: ISSUER,
    expectedAud: "domain-panel-api",
    now: () => NOW_MS,
    fetch: async () =>
      new Response(
        JSON.stringify({
          active: true,
          iss: ISSUER,
          sub: "user-1",
          aud: ["domain-panel-api"],
          scope: "domain:read",
          exp: NOW_SEC + 300,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
  };

  const claims = await validateTokenByMode("opaque", active);
  assert.equal(claims.subject, "user-1");
  assert.deepEqual(claims.scopes(), ["domain:read"]);
});

test("the middleware answers a missing token with a bare challenge", async () => {
  const guarded = rsMiddleware({ issuer: ISSUER, jwks: cacheFor([]).cache }, () => new Response("never"));
  const response = await guarded(new Request("https://rs.example.test/proxies"));

  assert.equal(response.status, 401);
  assert.equal(response.headers.get("www-authenticate"), "Bearer");
  assert.equal(response.headers.get("cache-control"), "no-store");
});

test("the middleware hands validated claims to the handler and never leaks a gate", async () => {
  const key = await signingKey();
  const { cache } = cacheFor([await publicJwk(key.publicKey, KID)]);
  const token = await mintToken(key.privateKey, baseClaims());
  const guarded = rsMiddleware(config(cache), (request, claims) =>
    new Response(JSON.stringify({ path: new URL(request.url).pathname, sub: claims.subject }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
  );

  const ok = await guarded(
    new Request("https://rs.example.test/proxies", { headers: { authorization: `Bearer ${token}` } }),
  );
  assert.equal(ok.status, 200);
  assert.deepEqual(await ok.json(), { path: "/proxies", sub: "user-1" });

  const denied = await guarded(
    new Request("https://rs.example.test/proxies", {
      headers: { authorization: "Bearer not-a-token" },
    }),
  );
  assert.equal(denied.status, 401);
  assert.equal(denied.headers.get("www-authenticate"), 'Bearer error="invalid_token"');
});

test("a DPoP-scheme request is refused rather than downgraded to bearer", () => {
  const request = new Request("https://rs.example.test/proxies", {
    headers: { authorization: "DPoP some-proof-token" },
  });
  assert.throws(() => extractToken(request), (error) => {
    assert.ok(error instanceof RSError);
    assert.equal(error.code, "rs_signature_invalid");
    return true;
  });
});

test("the issuer JWKS URL is derived without a double slash", () => {
  assert.equal(issuerJwksUrl(ISSUER), `${ISSUER}/.well-known/jwks.json`);
  assert.equal(issuerJwksUrl(`${ISSUER}/`), `${ISSUER}/.well-known/jwks.json`);
});
