// Resource-server (RS) side of the Snaplink TypeScript SDK: the JWKS cache a
// microservice uses to verify this server's access tokens locally, so the
// authorization server is not on the per-request path and may even be offline.
//
// This is the TypeScript counterpart of Go `interfaces/ssoclient/rs`'s
// JWKSCache re-export (`interfaces/ssoclient/remote`). The behavior that
// matters is preserved:
//
//   - ETag / If-None-Match revalidation, so a poll costs a 304 and no body.
//   - A background refresher on a jittered interval, so key rotation is picked
//     up without a request first failing.
//   - Unknown-kid triggers an immediate (rate-limited) fetch, because rotation
//     is the normal reason a kid is missing.
//   - Concurrent miss-triggered fetches collapse into one round-trip.
//   - A failed refresh keeps the previously published keys rather than
//     emptying the cache: a transient AS outage must not turn every in-flight
//     request into a signature failure.
//
// `resource-server.ts` owns the verification itself; this module only turns a
// JWKS document into `CryptoKey`s.

/** A single JSON Web Key, projected to the members verification needs. */
export interface JWK {
  kty: string;
  kid?: string;
  use?: string;
  alg?: string;
  key_ops?: string[];
  /** RSA modulus. */
  n?: string;
  /** RSA exponent. */
  e?: string;
  /** EC/OKP curve name. */
  crv?: string;
  /** EC x coordinate. */
  x?: string;
  /** Ed25519 / Ed448 public key. */
  k?: string;
}

/** A JWKS document as served at `/.well-known/jwks.json`. */
export interface JWKS {
  keys: JWK[];
}

/** Why a key could not be produced. Callers must not distinguish these to a
 * token holder — see `rs_signature_invalid` in `resource-server.ts`. */
export type JWKSCacheErrorCode =
  | "jwks_fetch_failed"
  | "jwks_document_malformed"
  | "jwks_unknown_kid"
  | "jwks_algorithm_unsupported"
  | "jwks_key_malformed";

/** A JWKS retrieval or key-import failure. */
export class JWKSCacheError extends Error {
  constructor(
    readonly code: JWKSCacheErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "JWKSCacheError";
  }
}

/** Injected transport, so a test or a Deno/Bun/Node host can supply its own. */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/**
 * An EdDSA verifier for runtimes whose WebCrypto has no Ed25519.
 *
 * Ed25519 is the historical only-accepted alg of this authorization server, so
 * a deployment signing with it needs this hook; `RS256`/`PS256`/`ES256`/
 * `ES384`/`ES512` need no injection. Same shape and rationale as
 * `LicenseVerifier` in `license-file.ts`.
 */
export type EdDSASigner = (params: {
  publicKey: JWK;
  message: Uint8Array;
  signature: Uint8Array;
}) => Promise<boolean>;

export interface JWKSCacheOptions {
  /** Transport for the JWKS document. Defaults to global `fetch`. */
  fetch?: FetchLike;
  /** Minimum age before a cached document is revalidated. Default 300_000ms. */
  minRefreshIntervalMs?: number;
  /** Background refresh cadence; 0 disables it. Default 1_800_000ms. */
  refreshIntervalMs?: number;
  /** How long a kid miss suppresses another miss-triggered fetch. Default 30_000ms. */
  cooldownMs?: number;
  /** Millisecond timer source, injected by tests. Defaults to `setTimeout`. */
  scheduleTimeout?: (handler: () => void, ms: number) => unknown;
  /** Cancel handle for {@link JWKSCacheOptions.scheduleTimeout}. */
  cancelTimeout?: (handle: unknown) => void;
  /** Clock, injected by tests. Defaults to `Date.now`. */
  now?: () => number;
  /** Ed25519 support for runtimes without it in WebCrypto. */
  eddsaVerify?: EdDSASigner;
}

/** The shared handle an RS consumer holds for one authorization server. */
export interface JWKSCache {
  /**
   * The key named by `kid`, or `undefined` when it is not published.
   *
   * A miss refreshes once (subject to the cooldown) and re-checks, so a
   * rotated key is found without waiting for the background refresher. An
   * absent key resolves `undefined` rather than rejecting: "no such key" and
   * "bad signature" must be indistinguishable to a token holder.
   */
  getJWK(kid: string): Promise<JWK | undefined>;
  /** Re-fetch now, honoring ETag. Resolves false when the server answered 304. */
  refresh(): Promise<boolean>;
  /** Stop the background refresher. Safe to call more than once. */
  close(): void;
}

/** The JWS algs this module imports natively, mirroring
 * `security.AsymmetricJWSAlgs` in the Go tree. */
export const NATIVE_ALGS: readonly string[] = ["ES256", "ES384", "ES512", "PS256", "RS256"];

/** EdDSA, which needs {@link JWKSCacheOptions.eddsaVerify} to be usable. */
export const INJECTED_ALGS: readonly string[] = ["EdDSA"];

/**
 * The server's conventional JWKS URL for an issuer base URL, mirroring
 * `rs.IssuerJWKSURL`.
 */
export function issuerJwksUrl(issuer: string): string {
  return `${issuer.replace(/\/+$/, "")}/.well-known/jwks.json`;
}

const DEFAULT_MIN_REFRESH_MS = 300_000;
const DEFAULT_REFRESH_MS = 1_800_000;
const DEFAULT_COOLDOWN_MS = 30_000;

/** RFC 7515 §2 base64url decode — no padding, no `+`/`/`. */
export function base64UrlToBytes(encoded: string): Uint8Array {
  const padded = encoded.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded.padEnd(padded.length + ((4 - (padded.length % 4)) % 4), "="));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

/** The WebCrypto parameters for one JWS alg. Throws for anything asymmetric
 * that this module does not import. */
function webCryptoParams(alg: string): {
  name: string;
  hash: string;
  namedCurve?: string;
  saltLength?: number;
} {
  switch (alg) {
    case "RS256":
      return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
    case "PS256":
      // RFC 7518 §3.5: the salt length equals the hash output length.
      return { name: "RSA-PSS", hash: "SHA-256", saltLength: 32 };
    case "ES256":
      return { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
    case "ES384":
      return { name: "ECDSA", namedCurve: "P-384", hash: "SHA-384" };
    case "ES512":
      // JWS spells the P-521 curve "ES512"; WebCrypto names it P-521.
      return { name: "ECDSA", namedCurve: "P-521", hash: "SHA-512" };
    default:
      throw new JWKSCacheError("jwks_algorithm_unsupported", `alg ${alg} is not importable`);
  }
}

/** Import a JWK for `alg`, or return undefined for the injected EdDSA alg. */
async function importVerificationKey(
  jwk: JWK,
  alg: string,
  cache: JWKSCacheOptions,
): Promise<CryptoKey | "eddsa"> {
  if (alg === "EdDSA") {
    if (!cache.eddsaVerify) {
      throw new JWKSCacheError(
        "jwks_algorithm_unsupported",
        "EdDSA needs an eddsaVerify verifier in this runtime",
      );
    }
    return "eddsa";
  }
  const params = webCryptoParams(alg);
  const material: RsaHashedImportParams | EcKeyImportParams = {
    name: params.name,
    hash: params.hash,
  } as RsaHashedImportParams;
  if (params.namedCurve) (material as EcKeyImportParams).namedCurve = params.namedCurve;
  if (params.saltLength) (material as RsaHashedImportParams).saltLength = params.saltLength;
  const key = jwk.kty === "EC" ? jwk.x : jwk.n;
  if (!key) {
    throw new JWKSCacheError("jwks_key_malformed", `kty ${jwk.kty} has no key material`);
  }
  try {
    return await crypto.subtle.importKey("jwk", jwk as JsonWebKey, material, true, ["verify"]);
  } catch (cause) {
    throw new JWKSCacheError("jwks_key_malformed", `import failed: ${String(cause)}`);
  }
}

/**
 * Build a JWKS cache for one authorization server.
 *
 * Callers own the lifecycle: share one cache across every consumer of the same
 * issuer rather than constructing one per request.
 */
export function createJWKSCache(url: string, options: JWKSCacheOptions = {}): JWKSCache {
  const doFetch = options.fetch ?? ((input, init) => fetch(input, init));
  const minRefreshMs = options.minRefreshIntervalMs ?? DEFAULT_MIN_REFRESH_MS;
  const refreshMs = options.refreshIntervalMs ?? DEFAULT_REFRESH_MS;
  const cooldownMs = options.cooldownMs ?? DEFAULT_COOLDOWN_MS;
  const now = options.now ?? (() => Date.now());
  const schedule = options.scheduleTimeout ?? ((handler, ms) => setTimeout(handler, ms));
  const cancel = options.cancelTimeout ?? ((handle) => clearTimeout(handle as number));

  let published: Map<string, JWK> = new Map();
  let etag: string | undefined;
  let lastFetchAt = 0;
  let lastMissFetchAt = 0;
  let inFlight: Promise<boolean> | undefined;
  let closed = false;

  async function load(): Promise<boolean> {
    const init: RequestInit = { headers: { accept: "application/json" } };
    if (etag) (init.headers as Record<string, string>)["if-none-match"] = etag;
    let response: Response;
    try {
      response = await doFetch(url, init);
    } catch (cause) {
      throw new JWKSCacheError("jwks_fetch_failed", `${url}: ${String(cause)}`);
    }
    if (response.status === 304) {
      lastFetchAt = now();
      return false;
    }
    if (!response.ok) {
      throw new JWKSCacheError("jwks_fetch_failed", `${url}: status ${response.status}`);
    }
    let document: JWKS;
    try {
      document = (await response.json()) as JWKS;
    } catch (cause) {
      throw new JWKSCacheError("jwks_document_malformed", `${url}: ${String(cause)}`);
    }
    if (!document || !Array.isArray(document.keys)) {
      throw new JWKSCacheError("jwks_document_malformed", `${url}: no keys array`);
    }
    const next = new Map<string, JWK>();
    for (const key of document.keys) {
      if (key && typeof key.kid === "string" && key.kid !== "") next.set(key.kid, key);
    }
    // Publish only after a fully parsed document, so a malformed refresh
    // cannot leave a half-populated cache behind.
    published = next;
    etag = response.headers.get("etag") ?? undefined;
    lastFetchAt = now();
    return true;
  }

  function refresh(): Promise<boolean> {
    if (closed) return Promise.resolve(false);
    // Collapse concurrent callers: rotation storm or a miss burst must not
    // multiply round-trips against the AS.
    if (!inFlight) {
      inFlight = load().finally(() => {
        inFlight = undefined;
      });
    }
    return inFlight;
  }

  const cache: JWKSCache = {
    async getJWK(kid: string): Promise<JWK | undefined> {
      if (kid === "") return undefined;
      let found = published.get(kid);
      if (found) return found;
      const since = now() - lastMissFetchAt;
      const stale = lastFetchAt === 0 || now() - lastFetchAt >= minRefreshMs;
      if (since >= cooldownMs && (stale || lastMissFetchAt === 0)) {
        lastMissFetchAt = now();
        try {
          await refresh();
          found = published.get(kid);
        } catch {
          // A refresh failure keeps the previously published keys. The miss
          // stays a miss; the caller reports the signature class, not this.
          return undefined;
        }
      }
      return published.get(kid);
    },

    refresh,

    close(): void {
      if (closed) return;
      closed = true;
      if (refreshMs > 0) cancel(timer);
    },
  };

  let timer: unknown;

  function scheduleNextRefresh(): void {
    if (closed || refreshMs <= 0) return;
    // Jitter so a fleet of services does not poll in lockstep. Derived from the
    // clock rather than a random source, so an injected `now` stays
    // deterministic.
    const jitter = Math.abs(now()) % (refreshMs / 4);
    timer = schedule(() => {
      refresh().catch(() => {
        /* keep the published keys; the next tick retries */
      });
      scheduleNextRefresh();
    }, refreshMs + jitter);
  }

  scheduleNextRefresh();

  return cache;
}

export type { JWKSCacheOptions as JWKSOptions, JWKS as JWKSDocument };

/**
 * Import a JWK for signature verification under `alg`.
 *
 * Exported because `resource-server.ts` verifies against it and a consumer
 * building a custom gate needs the same primitive. Returns the literal
 * `"eddsa"` when `alg` is EdDSA, whose verification is delegated to the
 * injected `eddsaVerify` signer.
 */
export { importVerificationKey };

