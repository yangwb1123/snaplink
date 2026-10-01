import type { FetchLike } from "./client.js";
export type { FetchLike };
/**
 * A JSON Web Key carrying the material verification needs.
 *
 * Distinct from the generated `JWK` wire projection in `client.ts`: that one
 * describes what the JWKS document *advertises* (a `kid`, a `use`, an EC `x`),
 * while this one is the superset an RS actually imports, adding the RSA `n`/`e`
 * and OKP `k` members.
 */
export interface RSJWK {
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
export interface RSJWKS {
    keys: RSJWK[];
}
/** Why a key could not be produced. Callers must not distinguish these to a
 * token holder — see `rs_signature_invalid` in `resource-server.ts`. */
export type JWKSCacheErrorCode = "jwks_fetch_failed" | "jwks_document_malformed" | "jwks_unknown_kid" | "jwks_algorithm_unsupported" | "jwks_key_malformed";
/** A JWKS retrieval or key-import failure. */
export declare class JWKSCacheError extends Error {
    readonly code: JWKSCacheErrorCode;
    constructor(code: JWKSCacheErrorCode, message: string);
}
/** Injected transport, so a test or a Deno/Bun/Node host can supply its own. */
export type JWKSCacheFetch = FetchLike;
/**
 * An EdDSA verifier for runtimes whose WebCrypto has no Ed25519.
 *
 * Ed25519 is the historical only-accepted alg of this authorization server, so
 * a deployment signing with it needs this hook; `RS256`/`PS256`/`ES256`/
 * `ES384`/`ES512` need no injection. Same shape and rationale as
 * `LicenseVerifier` in `license-file.ts`.
 */
export type EdDSASigner = (params: {
    publicKey: RSJWK;
    message: Uint8Array;
    signature: Uint8Array;
}) => Promise<boolean>;
export interface JWKSCacheOptions {
    /** Transport for the JWKS document. Defaults to global `fetch`. */
    fetch?: JWKSCacheFetch;
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
    getJWK(kid: string): Promise<RSJWK | undefined>;
    /** Re-fetch now, honoring ETag. Resolves false when the server answered 304. */
    refresh(): Promise<boolean>;
    /** Stop the background refresher. Safe to call more than once. */
    close(): void;
}
/** The JWS algs this module imports natively, mirroring
 * `security.AsymmetricJWSAlgs` in the Go tree. */
export declare const NATIVE_ALGS: readonly string[];
/** EdDSA, which needs {@link JWKSCacheOptions.eddsaVerify} to be usable. */
export declare const INJECTED_ALGS: readonly string[];
/**
 * The server's conventional JWKS URL for an issuer base URL, mirroring
 * `rs.IssuerJWKSURL`.
 */
export declare function issuerJwksUrl(issuer: string): string;
/** RFC 7515 §2 base64url decode — no padding, no `+`/`/`. */
export declare function base64UrlToBytes(encoded: string): Uint8Array<ArrayBuffer>;
/** Import a key for `alg`, or return the literal `"eddsa"` when the alg is
 * EdDSA, whose verification is delegated to the injected signer. */
declare function importVerificationKey(jwk: RSJWK, alg: string, cache: JWKSCacheOptions): Promise<CryptoKey | "eddsa">;
/**
 * Build a JWKS cache for one authorization server.
 *
 * Callers own the lifecycle: share one cache across every consumer of the same
 * issuer rather than constructing one per request.
 */
export declare function createJWKSCache(url: string, options?: JWKSCacheOptions): JWKSCache;
export type { JWKSCacheOptions as JWKSOptions, RSJWKS as JWKSDocument };
/**
 * Import a JWK for signature verification under `alg`.
 *
 * Exported because `resource-server.ts` verifies against it and a consumer
 * building a custom gate needs the same primitive. Returns the literal
 * `"eddsa"` when `alg` is EdDSA, whose verification is delegated to the
 * injected `eddsaVerify` signer.
 */
export { importVerificationKey };
