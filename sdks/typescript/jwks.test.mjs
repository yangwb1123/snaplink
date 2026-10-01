// JWKS cache behavior: ETag revalidation, rotation via an unknown kid, the
// singleflight collapse, and the fail-soft rule that a broken refresh must not
// empty an already-published key set.

import assert from "node:assert/strict";
import test from "node:test";

import {
  base64UrlToBytes,
  createJWKSCache,
  issuerJwksUrl,
  JWKSCacheError,
  NATIVE_ALGS,
} from "./index.ts";

const URL_JWKS = "https://sso.example.test/.well-known/jwks.json";
const T0 = 1_700_000_000_000;

function jwkFor(kid) {
  return { kty: "RSA", kid, use: "sig", alg: "RS256", n: "AQAB", e: "AQAB" };
}

/** A JWKS server whose document and status are swapped per response. */
function jwksServer() {
  const state = {
    calls: 0,
    etag: '"v1"',
    keys: [jwkFor("k1")],
    status: 200,
    lastIfNoneMatch: undefined,
  };
  return {
    state,
    fetch: async (_url, init) => {
      state.calls += 1;
      state.lastIfNoneMatch = init?.headers?.["if-none-match"];
      // A failing server answers with its status, not a 304 — check it first so
      // an outage is not masked by a still-valid ETag.
      if (state.status !== 200) {
        return new Response("nope", { status: state.status });
      }
      if (init?.headers?.["if-none-match"] === state.etag) {
        return new Response(null, { status: 304, headers: { etag: state.etag } });
      }
      return new Response(JSON.stringify({ keys: state.keys }), {
        status: 200,
        headers: { "content-type": "application/json", etag: state.etag },
      });
    },
  };
}

function cacheFor(fetchImpl, options = {}) {
  return createJWKSCache(URL_JWKS, {
    refreshIntervalMs: 0,
    now: () => T0,
    fetch: fetchImpl,
    ...options,
  });
}

test("a published key is returned and the document is fetched once", async () => {
  const server = jwksServer();
  const cache = cacheFor(server.fetch);

  const found = await cache.getJWK("k1");
  assert.equal(found.kid, "k1");
  assert.equal(found.kty, "RSA");
  assert.equal(server.state.calls, 1);

  // A hit for the same kid must not revalidate inside the min-refresh window.
  await cache.getJWK("k1");
  assert.equal(server.state.calls, 1);
  cache.close();
});

test("an unknown kid triggers one immediate refresh and is then found", async () => {
  const server = jwksServer();
  const cache = cacheFor(server.fetch);
  await cache.getJWK("k1");
  assert.equal(server.state.calls, 1);

  // Rotation: the new key appears upstream.
  server.state.keys = [jwkFor("k1"), jwkFor("k2")];
  server.state.etag = '"v2"';
  const rotated = await cache.getJWK("k2");

  assert.equal(rotated.kid, "k2");
  assert.equal(server.state.calls, 2);
  cache.close();
});

test("a kid miss is rate-limited by the cooldown", async () => {
  const server = jwksServer();
  let clock = T0;
  const cache = cacheFor(server.fetch, { cooldownMs: 30_000, now: () => clock });
  await cache.getJWK("k1");

  // Three misses inside one cooldown window must not become three fetches.
  assert.equal(await cache.getJWK("absent"), undefined);
  assert.equal(server.state.calls, 2);
  assert.equal(await cache.getJWK("absent"), undefined);
  assert.equal(await cache.getJWK("absent"), undefined);
  assert.equal(server.state.calls, 2);

  // Past the cooldown, one more miss may revalidate.
  clock += 31_000;
  assert.equal(await cache.getJWK("absent"), undefined);
  assert.equal(server.state.calls, 3);
  cache.close();
});

test("concurrent misses collapse into a single round-trip", async () => {
  const server = jwksServer();
  const cache = cacheFor(server.fetch);

  const results = await Promise.all([
    cache.getJWK("k1"),
    cache.getJWK("k1"),
    cache.getJWK("k1"),
    cache.getJWK("k1"),
  ]);

  assert.equal(server.state.calls, 1);
  assert.ok(results.every((key) => key && key.kid === "k1"));
  cache.close();
});

test("a concurrent miss for an unpublished kid stays a miss without a second fetch", async () => {
  const server = jwksServer();
  const cache = cacheFor(server.fetch);

  const [present, absent] = await Promise.all([cache.getJWK("k1"), cache.getJWK("k2")]);

  // Both ride the one round-trip the first caller started; the unpublished kid
  // is still reported as a miss rather than as a fetch of its own.
  assert.equal(server.state.calls, 1);
  assert.equal(present.kid, "k1");
  assert.equal(absent, undefined);
  cache.close();
});

test("a 304 revalidates without republishing keys", async () => {
  const server = jwksServer();
  const cache = cacheFor(server.fetch, { minRefreshIntervalMs: 0 });
  await cache.getJWK("k1");

  // Min refresh 0 means every hit revalidates; the server answers 304.
  const refreshed = await cache.refresh();
  assert.equal(refreshed, false);
  assert.equal(server.state.lastIfNoneMatch, '"v1"');
  assert.equal((await cache.getJWK("k1")).kid, "k1");
  cache.close();
});

test("an explicit refresh picks up a rotated document", async () => {
  const server = jwksServer();
  const cache = cacheFor(server.fetch);
  await cache.getJWK("k1");

  server.state.keys = [jwkFor("k9")];
  server.state.etag = '"v9"';
  assert.equal(await cache.refresh(), true);

  assert.equal((await cache.getJWK("k9")).kid, "k9");
  assert.equal(await cache.getJWK("k1"), undefined);
  cache.close();
});

test("a failed refresh keeps the previously published keys", async () => {
  const server = jwksServer();
  const cache = cacheFor(server.fetch);
  await cache.getJWK("k1");

  // Upstream goes away mid-rotation.
  server.state.status = 503;
  await assert.rejects(cache.refresh(), (error) => {
    assert.ok(error instanceof JWKSCacheError);
    assert.equal(error.code, "jwks_fetch_failed");
    return true;
  });

  // The outage must not empty the cache: in-flight requests keep verifying.
  assert.equal((await cache.getJWK("k1")).kid, "k1");
  cache.close();
});

test("a miss during an outage stays a miss, not an exception", async () => {
  const server = jwksServer();
  let clock = T0;
  const cache = cacheFor(server.fetch, { now: () => clock, cooldownMs: 0 });
  await cache.getJWK("k1");
  server.state.status = 500;

  clock += 10_000;
  assert.equal(await cache.getJWK("absent"), undefined);
  cache.close();
});

test("a document without a keys array is rejected as malformed", async () => {
  const cache = cacheFor(async () =>
    new Response(JSON.stringify({ nope: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
  );

  await assert.rejects(cache.refresh(), (error) => {
    assert.ok(error instanceof JWKSCacheError);
    assert.equal(error.code, "jwks_document_malformed");
    return true;
  });
  cache.close();
});

test("a non-JSON body is rejected as malformed", async () => {
  const cache = cacheFor(async () => new Response("not json", { status: 200 }));

  await assert.rejects(cache.refresh(), (error) => {
    assert.ok(error instanceof JWKSCacheError);
    assert.equal(error.code, "jwks_document_malformed");
    return true;
  });
  cache.close();
});

test("a transport error is reported as a fetch failure", async () => {
  const cache = cacheFor(async () => {
    throw new Error("connection refused");
  });

  await assert.rejects(cache.refresh(), (error) => {
    assert.ok(error instanceof JWKSCacheError);
    assert.equal(error.code, "jwks_fetch_failed");
    return true;
  });
  cache.close();
});

test("an empty kid is a miss without a fetch", async () => {
  const server = jwksServer();
  const cache = cacheFor(server.fetch);

  assert.equal(await cache.getJWK(""), undefined);
  assert.equal(server.state.calls, 0);
  cache.close();
});

test("the background refresher revalidates and can be closed", async () => {
  const server = jwksServer();
  const scheduled = [];
  const cache = createJWKSCache(URL_JWKS, {
    refreshIntervalMs: 1_000,
    now: () => T0,
    fetch: server.fetch,
    scheduleTimeout: (handler, ms) => {
      scheduled.push(ms);
      return scheduled.length;
    },
    cancelTimeout: () => {},
  });

  // One interval was scheduled; the exact delay carries a jitter term.
  assert.equal(scheduled.length, 1);
  assert.ok(scheduled[0] >= 1_000);

  cache.close();
  // close() is idempotent, so a shutdown path may call it twice.
  cache.close();
});

test("close() stops further refreshes", async () => {
  const server = jwksServer();
  const cache = cacheFor(server.fetch);
  await cache.getJWK("k1");
  cache.close();

  assert.equal(await cache.refresh(), false);
  assert.equal(server.state.calls, 1);
});

test("base64url decoding is padding-free and URL-safe", () => {
  // { "alg": "ES256" } in base64url, no padding.
  const encoded = "eyJhbGciOiJFUzI1NiJ9";
  const decoded = new TextDecoder().decode(base64UrlToBytes(encoded));
  assert.equal(decoded, '{"alg":"ES256"}');

  // A segment whose length needs padding must still decode.
  assert.equal(base64UrlToBytes("YQ").length, 1);
  assert.equal(base64UrlToBytes("YWI").length, 2);
});

test("the native alg set covers every asymmetric alg WebCrypto can import", () => {
  // EdDSA is deliberately absent: it needs an injected verifier.
  assert.deepEqual([...NATIVE_ALGS].sort(), ["ES256", "ES384", "ES512", "PS256", "RS256"]);
  assert.ok(!NATIVE_ALGS.includes("EdDSA"));
  assert.ok(!NATIVE_ALGS.includes("none"));
  for (const alg of NATIVE_ALGS) {
    assert.ok(!alg.startsWith("HS"), `${alg} must not be symmetric`);
  }
});

test("the issuer JWKS URL drops trailing slashes", () => {
  assert.equal(issuerJwksUrl("https://sso.example.test"), URL_JWKS);
  assert.equal(issuerJwksUrl("https://sso.example.test/"), URL_JWKS);
  assert.equal(issuerJwksUrl("https://sso.example.test///"), URL_JWKS);
});
