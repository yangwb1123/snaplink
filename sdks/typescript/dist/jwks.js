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
/** A JWKS retrieval or key-import failure. */
export class JWKSCacheError extends Error {
    code;
    constructor(code, message) {
        super(`${code}: ${message}`);
        this.code = code;
        this.name = "JWKSCacheError";
    }
}
/** The JWS algs this module imports natively, mirroring
 * `security.AsymmetricJWSAlgs` in the Go tree. */
export const NATIVE_ALGS = ["ES256", "ES384", "ES512", "PS256", "RS256"];
/** EdDSA, which needs {@link JWKSCacheOptions.eddsaVerify} to be usable. */
export const INJECTED_ALGS = ["EdDSA"];
/**
 * The server's conventional JWKS URL for an issuer base URL, mirroring
 * `rs.IssuerJWKSURL`.
 */
export function issuerJwksUrl(issuer) {
    return `${issuer.replace(/\/+$/, "")}/.well-known/jwks.json`;
}
const DEFAULT_MIN_REFRESH_MS = 300_000;
const DEFAULT_REFRESH_MS = 1_800_000;
const DEFAULT_COOLDOWN_MS = 30_000;
/** RFC 7515 §2 base64url decode — no padding, no `+`/`/`. */
export function base64UrlToBytes(encoded) {
    const padded = encoded.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(padded.padEnd(padded.length + ((4 - (padded.length % 4)) % 4), "="));
    const bytes = new Uint8Array(new ArrayBuffer(binary.length));
    for (let index = 0; index < binary.length; index += 1)
        bytes[index] = binary.charCodeAt(index);
    return bytes;
}
/** The WebCrypto import parameters for one JWS alg. Throws for anything
 * asymmetric that this module does not import. */
function webCryptoParams(alg) {
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
/** Import a key for `alg`, or return the literal `"eddsa"` when the alg is
 * EdDSA, whose verification is delegated to the injected signer. */
async function importVerificationKey(jwk, alg, cache) {
    if (alg === "EdDSA") {
        if (!cache.eddsaVerify) {
            throw new JWKSCacheError("jwks_algorithm_unsupported", "EdDSA needs an eddsaVerify verifier in this runtime");
        }
        return "eddsa";
    }
    const material = webCryptoParams(alg);
    const encoded = jwk.kty === "EC" ? jwk.x : jwk.n;
    if (!encoded) {
        throw new JWKSCacheError("jwks_key_malformed", `kty ${jwk.kty} has no key material`);
    }
    try {
        return await crypto.subtle.importKey("jwk", jwk, material, true, ["verify"]);
    }
    catch (cause) {
        throw new JWKSCacheError("jwks_key_malformed", `import failed: ${String(cause)}`);
    }
}
/**
 * Build a JWKS cache for one authorization server.
 *
 * Callers own the lifecycle: share one cache across every consumer of the same
 * issuer rather than constructing one per request.
 */
export function createJWKSCache(url, options = {}) {
    const doFetch = options.fetch ?? ((input, init) => fetch(input, init));
    const minRefreshMs = options.minRefreshIntervalMs ?? DEFAULT_MIN_REFRESH_MS;
    const refreshMs = options.refreshIntervalMs ?? DEFAULT_REFRESH_MS;
    const cooldownMs = options.cooldownMs ?? DEFAULT_COOLDOWN_MS;
    const now = options.now ?? (() => Date.now());
    const schedule = options.scheduleTimeout ?? ((handler, ms) => setTimeout(handler, ms));
    const cancel = options.cancelTimeout ?? ((handle) => clearTimeout(handle));
    let published = new Map();
    let etag;
    let lastFetchAt = 0;
    let lastMissFetchAt = 0;
    let inFlight;
    let closed = false;
    async function load() {
        const init = { headers: { accept: "application/json" } };
        if (etag)
            init.headers["if-none-match"] = etag;
        let response;
        try {
            response = await doFetch(url, init);
        }
        catch (cause) {
            throw new JWKSCacheError("jwks_fetch_failed", `${url}: ${String(cause)}`);
        }
        if (response.status === 304) {
            lastFetchAt = now();
            return false;
        }
        if (!response.ok) {
            throw new JWKSCacheError("jwks_fetch_failed", `${url}: status ${response.status}`);
        }
        let document;
        try {
            document = (await response.json());
        }
        catch (cause) {
            throw new JWKSCacheError("jwks_document_malformed", `${url}: ${String(cause)}`);
        }
        if (!document || !Array.isArray(document.keys)) {
            throw new JWKSCacheError("jwks_document_malformed", `${url}: no keys array`);
        }
        const next = new Map();
        for (const key of document.keys) {
            if (key && typeof key.kid === "string" && key.kid !== "")
                next.set(key.kid, key);
        }
        // Publish only after a fully parsed document, so a malformed refresh
        // cannot leave a half-populated cache behind.
        published = next;
        etag = response.headers.get("etag") ?? undefined;
        lastFetchAt = now();
        return true;
    }
    function refresh() {
        if (closed)
            return Promise.resolve(false);
        // Collapse concurrent callers: rotation storm or a miss burst must not
        // multiply round-trips against the AS.
        if (!inFlight) {
            inFlight = load().finally(() => {
                inFlight = undefined;
            });
        }
        return inFlight;
    }
    const cache = {
        async getJWK(kid) {
            if (kid === "")
                return undefined;
            const found = published.get(kid);
            if (found) {
                // Revalidate a stale document at most once per minRefreshIntervalMs so a
                // long-lived process keeps its key set fresh even with no background
                // timer. The server answers 304, so this costs a conditional request
                // and no body.
                const age = now() - lastFetchAt;
                if (lastFetchAt === 0 || age >= minRefreshMs) {
                    try {
                        await refresh();
                    }
                    catch {
                        /* keep the published keys and serve the hit */
                    }
                    return published.get(kid);
                }
                return found;
            }
            // Another caller already started a refresh: await it rather than
            // reporting a miss, so a rotation burst resolves for everyone from the
            // single round-trip already in progress.
            if (inFlight) {
                try {
                    await inFlight;
                }
                catch {
                    return undefined;
                }
                return published.get(kid);
            }
            // The cooldown is the ONLY gate on a miss-triggered fetch: once it has
            // elapsed, a miss may revalidate whatever the document's age, because a
            // missing kid is the normal signature of rotation.
            if (lastMissFetchAt !== 0 && now() - lastMissFetchAt < cooldownMs) {
                return undefined;
            }
            lastMissFetchAt = now();
            try {
                await refresh();
            }
            catch {
                // A refresh failure keeps the previously published keys. The miss stays
                // a miss; the caller reports the signature class, not this.
                return undefined;
            }
            const hit = published.get(kid);
            // The cooldown damps repeated misses, it does not penalize a rotation
            // that just resolved: a fetch that produced the requested key releases the
            // window so the next genuine rotation is served at once.
            if (hit)
                lastMissFetchAt = 0;
            return hit;
        },
        refresh,
        close() {
            if (closed)
                return;
            closed = true;
            if (refreshMs > 0)
                cancel(timer);
        },
    };
    let timer;
    function scheduleNextRefresh() {
        if (closed || refreshMs <= 0)
            return;
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
/**
 * Import a JWK for signature verification under `alg`.
 *
 * Exported because `resource-server.ts` verifies against it and a consumer
 * building a custom gate needs the same primitive. Returns the literal
 * `"eddsa"` when `alg` is EdDSA, whose verification is delegated to the
 * injected `eddsaVerify` signer.
 */
export { importVerificationKey };
