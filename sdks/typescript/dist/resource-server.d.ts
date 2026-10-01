import { type EdDSASigner, type FetchLike, type JWKSCache } from "./jwks.js";
/**
 * The wall-clock drift ordinarily seen between independently NTP-synced hosts
 * when comparing `exp`/`nbf`/`iat`, mirroring `rs.DefaultMaxClockSkew`.
 */
export declare const DEFAULT_MAX_CLOCK_SKEW_SEC = 30;
/**
 * The stable code for a validation failure.
 *
 * These originate in the SDK, never on the wire: the wire vocabulary of
 * {@link rsMiddleware} stays the standard RFC 6750 `invalid_token` /
 * `insufficient_scope` challenge, deliberately collapsing the detailed cause so
 * a 401 never becomes a token-validation oracle.
 */
export type RSErrorCode = "rs_config" | "rs_token_malformed" | "rs_token_type_mismatch" | "rs_signature_invalid" | "rs_issuer_mismatch" | "rs_audience_mismatch" | "rs_serving_region_mismatch" | "rs_token_expired" | "rs_token_not_yet_valid" | "rs_token_inactive" | "rs_introspection_failed" | "rs_insufficient_scope" | "rs_subject_missing";
/** A token-validation or authorization failure. */
export declare class RSError extends Error {
    readonly code: RSErrorCode;
    constructor(code: RSErrorCode, message: string);
}
/**
 * The validated view of an access token the RS acts on: the RFC 9068 §2.2
 * claim set plus the two Snaplink extension claims and the RFC 9449
 * confirmation binding. `raw` holds the complete claim document for anything
 * beyond them.
 */
export declare class RSClaims {
    readonly issuer: string;
    readonly subject: string;
    readonly audience: readonly string[];
    readonly clientId: string;
    readonly scope: string;
    readonly jti: string;
    readonly expiresAt: number;
    readonly notBefore: number;
    readonly issuedAt: number;
    /** Snaplink extension: the region that minted this token. */
    readonly servingRegion: string;
    /** Snaplink extension: the mint-time tenant binding of the client. */
    readonly tenantId: string;
    /** RFC 9449 §6.1 confirmation thumbprint; non-empty means sender-constrained. */
    readonly cnfJkt: string;
    /** The full claim set, for claims this projection omits. */
    readonly raw: Record<string, unknown>;
    constructor(issuer: string, subject: string, audience: readonly string[], clientId: string, scope: string, jti: string, expiresAt: number, notBefore: number, issuedAt: number, 
    /** Snaplink extension: the region that minted this token. */
    servingRegion: string, 
    /** Snaplink extension: the mint-time tenant binding of the client. */
    tenantId: string, 
    /** RFC 9449 §6.1 confirmation thumbprint; non-empty means sender-constrained. */
    cnfJkt: string, 
    /** The full claim set, for claims this projection omits. */
    raw: Record<string, unknown>);
    /** The space-delimited `scope` claim, split (RFC 8693 §4.2). */
    scopes(): string[];
    /** Whether `aud` contains the given value. */
    hasAudience(audience: string): boolean;
    /** Whether the token carries a `serving_region` claim. */
    hasServingRegion(): boolean;
    /** Whether the token carries a `tenant_id` claim. */
    hasTenantId(): boolean;
    /** Whether the token is sender-constrained and therefore unusable without
     * sender-constrained proof support (see the module header). */
    isSenderConstrained(): boolean;
}
/** The RS's own client credentials for the introspection endpoint. RFC 7662
 * requires the caller to authenticate — an open introspection endpoint would be
 * a token-validity oracle. */
export interface ClientCreds {
    id: string;
    secret: string;
}
export interface RSConfig {
    /** REQUIRED: the expected `iss` claim, matched exactly. */
    issuer: string;
    /** Verification keys for local validation. Required unless `introspectUrl` is set. */
    jwks?: JWKSCache;
    /** JWS alg allowlist, checked before any signature work. Defaults to the
     * server's asymmetric set (`EdDSA`, `ES256/384/512`, `RS256`, `PS256`).
     * `none` and every symmetric `HS*` alg are refused even if listed. */
    allowedAlgs?: readonly string[];
    /** When set, the token's `aud` must contain it. */
    expectedAud?: string;
    /**
     * Opt-in, fail-closed: when non-empty, a `serving_region` claim must be
     * present and in this set. Enable only AFTER the server fleet mints the
     * claim — an older server that omits it then denies every token.
     */
    allowedServingRegions?: readonly string[];
    /** `exp`/`nbf`/`iat` comparison tolerance. <= 0 selects
     * {@link DEFAULT_MAX_CLOCK_SKEW_SEC}. */
    maxClockSkewSec?: number;
    /** Enables remote (RFC 7662) validation instead of local verification. */
    introspectUrl?: string;
    /** Authenticates the RS to the introspection endpoint via HTTP Basic. */
    introspectCreds?: ClientCreds;
    /** Transport for the JWKS cache and introspection calls. */
    fetch?: FetchLike;
    /** Ed25519 support for runtimes without it in WebCrypto. */
    eddsaVerify?: EdDSASigner;
    /** Clock, injected by tests. Defaults to `Date.now`. */
    now?: () => number;
}
/** The default asymmetric JWS alg set, mirroring
 * `security.AsymmetricJWSAlgs` in the Go tree. */
export declare const DEFAULT_ALLOWED_ALGS: readonly string[];
/**
 * Verify an access token LOCALLY: JWS signature against the cached JWKS plus
 * the full claim gates. The authorization server is not on the request path.
 *
 * @throws {RSError} with an {@link RSErrorCode} the caller may branch on.
 */
export declare function validateToken(token: string, config: RSConfig): Promise<RSClaims>;
/**
 * Verify an access token by asking the RFC 7662 introspection endpoint, so
 * revocation is visible immediately. The round-trip failure is reported as
 * `rs_introspection_failed`, distinct from `rs_token_inactive`, so a caller can
 * choose its own fail mode for an authorization-server outage.
 */
export declare function validateTokenWithIntrospect(token: string, config: RSConfig): Promise<RSClaims>;
/**
 * Route to remote introspection when configured, else local signature
 * validation — the shared entry point {@link rsMiddleware} uses.
 */
export declare function validateTokenByMode(token: string, config: RSConfig): Promise<RSClaims>;
/** Whether the token's `scope` claim contains `scope` exactly. */
export declare function hasScope(claims: RSClaims, scope: string): boolean;
/** Resolves only when EVERY required scope is present, naming the first missing
 * one. */
export declare function checkScope(claims: RSClaims, ...required: readonly string[]): void;
/** Resolves when AT LEAST ONE listed scope is present — the "reader or admin may
 * pass" shape. An empty list matches nothing (fail-closed). */
export declare function checkAnyScope(claims: RSClaims, ...any: readonly string[]): void;
/** The token subject, or `rs_subject_missing` — the guard that keeps a
 * client_credentials (machine) token out of user-only endpoints. */
export declare function requireSubject(claims: RSClaims): string;
/**
 * The RFC 6750 challenge for a failure, mirroring Go `rs.writeChallenge`.
 *
 * A missing token gets a bare `Bearer` challenge with no `error=`; an invalid
 * one gets `error="invalid_token"` — the exact opaque-failure shape
 * `/userinfo` returns, so this never leaks which gate rejected the token.
 * `insufficient_scope` carries the required scopes and the `scope` attribute.
 */
export declare function wwwAuthenticate(failure: RSError, required?: readonly string[]): string;
/** A handler guarded by the RS middleware. */
export type RSHandler = (request: Request, claims: RSClaims) => Response | Promise<Response>;
/** Read the bearer token, mirroring Go `rs.extractToken`. A `DPoP` scheme is
 * recognized and refused rather than ignored: accepting a sender-constrained
 * token without verifying its proof would be a silent downgrade. */
export declare function extractToken(request: Request): string;
/**
 * A Web-standard `Request -> Response` middleware, the Fetch-API counterpart of
 * Go `rs.HTTPMiddleware` and usable from Deno, Bun, Node 18+, and edge
 * runtimes.
 *
 * The validated claims are passed to the handler as its second argument; the
 * immutable `Request` is not mutated. Failures become an RFC 6750 challenge
 * response and never reach the handler.
 */
export declare function rsMiddleware(config: RSConfig, handler: RSHandler): (request: Request) => Promise<Response>;
