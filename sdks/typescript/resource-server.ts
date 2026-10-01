// Resource-server (RS) side of the Snaplink TypeScript SDK: everything a
// service consuming this authorization server's access tokens needs in order to
// validate them and make authorization decisions, without re-implementing the
// security gates the server already enforces.
//
// This is the TypeScript counterpart of Go `interfaces/ssoclient/rs`, and the
// gate ORDER is load-bearing and identical to it:
//
//   1. `typ` (RFC 9068 §4) — only `at+jwt` may pass, checked BEFORE any
//      signature work, so `alg: none` and symmetric algs can never reach the
//      verifier and a misrouted ID / logout / SET token is rejected early.
//   2. Key resolution by `kid`, then signature verification against ONLY that
//      key, so a token cannot validate against a different published key than
//      its header names.
//   3. Claim gates, read only from a payload whose signature already verified:
//      `iss` → `exp` presence → `exp` → `nbf` → `iat` → `aud` → region.
//
// Two validation modes, matching the Go package:
//
//   - Local (stateless): `validateToken` verifies the JWT signature against the
//     cached JWKS. The server is not on the per-request path and may be
//     offline. Revocation before natural expiry is NOT visible.
//   - Remote (introspection): `validateTokenWithIntrospect` asks the RFC 7662
//     endpoint, so revocation is visible immediately at the cost of a
//     round-trip per call.
//
// Authorization helpers read the token's OWN `scope` claim only — no server
// round-trip — so they are the RS-side complement of the server's Authorizer,
// not a replacement for a policy engine. A missing or absent claims object
// authorizes nothing (fail-closed).
//
// Not implemented here, unlike Go `rs`: RFC 9449 DPoP proof verification and
// RFC 8705 mTLS sender-constraint validation. WebCrypto has no access to the
// peer certificate, so a certificate-bound token (`cnf.x5t#S256`) cannot be
// validated in this runtime family. `cnfJkt` is projected on the claims so a
// caller can detect a sender-constrained token and refuse it explicitly.

import {
  base64UrlToBytes,
  importVerificationKey,
  JWKSCacheError,
  type EdDSASigner,
  type FetchLike,
  type JWKSCache,
  type RSJWK,
} from "./jwks.js";

/** RFC 9068 §2.1 access-token JOSE `typ` values, short and full spelling. */
const ACCESS_TOKEN_TYP = "at+jwt";
const ACCESS_TOKEN_TYP_FULL = "application/at+jwt";

/**
 * The wall-clock drift ordinarily seen between independently NTP-synced hosts
 * when comparing `exp`/`nbf`/`iat`, mirroring `rs.DefaultMaxClockSkew`.
 */
export const DEFAULT_MAX_CLOCK_SKEW_SEC = 30;

/**
 * The stable code for a validation failure.
 *
 * These originate in the SDK, never on the wire: the wire vocabulary of
 * {@link rsMiddleware} stays the standard RFC 6750 `invalid_token` /
 * `insufficient_scope` challenge, deliberately collapsing the detailed cause so
 * a 401 never becomes a token-validation oracle.
 */
export type RSErrorCode =
  | "rs_config"
  | "rs_token_malformed"
  | "rs_token_type_mismatch"
  | "rs_signature_invalid"
  | "rs_issuer_mismatch"
  | "rs_audience_mismatch"
  | "rs_serving_region_mismatch"
  | "rs_token_expired"
  | "rs_token_not_yet_valid"
  | "rs_token_inactive"
  | "rs_introspection_failed"
  | "rs_insufficient_scope"
  | "rs_subject_missing";

/** A token-validation or authorization failure. */
export class RSError extends Error {
  constructor(
    readonly code: RSErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "RSError";
  }
}

/**
 * The validated view of an access token the RS acts on: the RFC 9068 §2.2
 * claim set plus the two Snaplink extension claims and the RFC 9449
 * confirmation binding. `raw` holds the complete claim document for anything
 * beyond them.
 */
export class RSClaims {
  constructor(
    readonly issuer: string,
    readonly subject: string,
    readonly audience: readonly string[],
    readonly clientId: string,
    readonly scope: string,
    readonly jti: string,
    readonly expiresAt: number,
    readonly notBefore: number,
    readonly issuedAt: number,
    /** Snaplink extension: the region that minted this token. */
    readonly servingRegion: string,
    /** Snaplink extension: the mint-time tenant binding of the client. */
    readonly tenantId: string,
    /** RFC 9449 §6.1 confirmation thumbprint; non-empty means sender-constrained. */
    readonly cnfJkt: string,
    /** The full claim set, for claims this projection omits. */
    readonly raw: Record<string, unknown>,
  ) {}

  /** The space-delimited `scope` claim, split (RFC 8693 §4.2). */
  scopes(): string[] {
    return this.scope === "" ? [] : this.scope.split(/\s+/).filter(Boolean);
  }

  /** Whether `aud` contains the given value. */
  hasAudience(audience: string): boolean {
    return this.audience.includes(audience);
  }

  /** Whether the token carries a `serving_region` claim. */
  hasServingRegion(): boolean {
    return this.servingRegion !== "";
  }

  /** Whether the token carries a `tenant_id` claim. */
  hasTenantId(): boolean {
    return this.tenantId !== "";
  }

  /** Whether the token is sender-constrained and therefore unusable without
   * sender-constrained proof support (see the module header). */
  isSenderConstrained(): boolean {
    return this.cnfJkt !== "";
  }
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
export const DEFAULT_ALLOWED_ALGS: readonly string[] = [
  "EdDSA",
  "ES256",
  "ES384",
  "ES512",
  "PS256",
  "RS256",
];

/** Refused unconditionally, so a misconfigured allowlist fails closed instead of
 * opening the public-key-as-HMAC confusion attack. */
function refusedAlgs(): ReadonlySet<string> {
  return new Set(["none", "HS256", "HS384", "HS512"]);
}

function effectiveAlgs(config: RSConfig): ReadonlySet<string> {
  const allowed = new Set(
    (config.allowedAlgs ?? DEFAULT_ALLOWED_ALGS).filter((alg) => !refusedAlgs().has(alg)),
  );
  return allowed;
}

function skewSeconds(config: RSConfig): number {
  const configured = config.maxClockSkewSec ?? 0;
  return configured > 0 ? configured : DEFAULT_MAX_CLOCK_SKEW_SEC;
}

function decodeSegment(segment: string, what: string): Uint8Array<ArrayBuffer> {
  try {
    return base64UrlToBytes(segment);
  } catch (cause) {
    throw new RSError("rs_token_malformed", `${what}: ${String(cause)}`);
  }
}

function decodeJson<T>(bytes: Uint8Array, what: string): T {
  try {
    return JSON.parse(new TextDecoder().decode(bytes)) as T;
  } catch (cause) {
    throw new RSError("rs_token_malformed", `${what}: ${String(cause)}`);
  }
}

/** RFC 9068 §4: only the access-token `typ` may pass, case-insensitively per
 * RFC 7515 §4.1.9. The server always stamps `at+jwt` on access tokens, so this
 * strict gate costs nothing and rejects a misrouted ID / logout / SET token
 * before signature work. */
function checkAccessTokenTyp(typ: string | undefined): void {
  if (typ === undefined) {
    throw new RSError("rs_token_malformed", "header has no typ");
  }
  const lowered = typ.toLowerCase();
  if (lowered !== ACCESS_TOKEN_TYP && lowered !== ACCESS_TOKEN_TYP_FULL) {
    throw new RSError("rs_token_type_mismatch", `typ ${typ}`);
  }
}

function audienceOf(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((entry): entry is string => typeof entry === "string");
  return [];
}

function numberOrZero(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function stringOrEmpty(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function cnfThumbprint(payload: Record<string, unknown>): string {
  const cnf = payload.cnf;
  if (typeof cnf !== "object" || cnf === null) return "";
  const jkt = (cnf as Record<string, unknown>).jkt;
  return typeof jkt === "string" ? jkt : "";
}

function claimsFrom(payload: Record<string, unknown>): RSClaims {
  return new RSClaims(
    stringOrEmpty(payload.iss),
    stringOrEmpty(payload.sub),
    audienceOf(payload.aud),
    stringOrEmpty(payload.client_id),
    stringOrEmpty(payload.scope),
    stringOrEmpty(payload.jti),
    numberOrZero(payload.exp),
    numberOrZero(payload.nbf),
    numberOrZero(payload.iat),
    stringOrEmpty(payload.serving_region),
    stringOrEmpty(payload.tenant_id),
    cnfThumbprint(payload),
    payload,
  );
}

function validateClaims(claims: RSClaims, config: RSConfig): RSClaims {
  const nowSec = Math.floor((config.now ?? Date.now)() / 1000);
  const skew = skewSeconds(config);

  if (claims.issuer !== config.issuer) {
    throw new RSError("rs_issuer_mismatch", `iss ${claims.issuer}`);
  }
  if (claims.expiresAt === 0) {
    throw new RSError("rs_token_malformed", "missing exp");
  }
  if (nowSec >= claims.expiresAt + skew) {
    throw new RSError("rs_token_expired", "exp in the past");
  }
  if (claims.notBefore !== 0 && nowSec + skew < claims.notBefore) {
    throw new RSError("rs_token_not_yet_valid", "nbf in the future");
  }
  if (claims.issuedAt !== 0 && claims.issuedAt > nowSec + skew) {
    throw new RSError("rs_token_not_yet_valid", "iat in the future");
  }
  if (config.expectedAud !== undefined && config.expectedAud !== "" && !claims.hasAudience(config.expectedAud)) {
    throw new RSError("rs_audience_mismatch", `aud ${claims.audience.join(",")}`);
  }
  // Region governance runs LAST, after the identity/time gates, so a garbage or
  // expired token still reports its higher-priority code and the gate never
  // becomes a probe oracle.
  const regions = config.allowedServingRegions ?? [];
  if (regions.length > 0 && !regions.includes(claims.servingRegion)) {
    throw new RSError("rs_serving_region_mismatch", `serving_region ${claims.servingRegion}`);
  }
  return claims;
}

async function verifySignature(
  token: string,
  header: { alg: string; kid: string; typ: string },
  config: RSConfig,
  jwk: RSJWK,
): Promise<Uint8Array<ArrayBuffer>> {
  const parts = token.split(".");
  const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const signature = decodeSegment(parts[2], "signature");
  if (header.alg === "EdDSA") {
    if (!config.eddsaVerify) {
      throw new RSError("rs_signature_invalid", "EdDSA needs an eddsaVerify verifier here");
    }
    const ok = await config.eddsaVerify({ publicKey: jwk, message: signingInput, signature });
    if (!ok) throw new RSError("rs_signature_invalid", "EdDSA signature did not verify");
    return decodeSegment(parts[1], "payload");
  }
  let key: CryptoKey | "eddsa";
  try {
    key = await importVerificationKey(jwk, header.alg, {
      eddsaVerify: config.eddsaVerify,
    });
  } catch (cause) {
    // An unimportable or unsupported key is the signature class, not a
    // separate oracle.
    throw new RSError("rs_signature_invalid", cause instanceof JWKSCacheError ? cause.code : String(cause));
  }
  if (key === "eddsa") {
    throw new RSError("rs_signature_invalid", "unexpected eddsa key for a non-EdDSA alg");
  }
  // One branch per alg family, so the WebCrypto parameters are a literal rather
  // than a widened union: PS256 needs its salt length, ES* its curve hash, and
  // the RS* family takes the bare algorithm name.
  let verified: boolean;
  if (header.alg === "PS256") {
    verified = await crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, key, signature, signingInput);
  } else if (header.alg.startsWith("ES")) {
    verified = await crypto.subtle.verify({ name: "ECDSA", hash: ecdsaHash(header.alg) }, key, signature, signingInput);
  } else {
    verified = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, signingInput);
  }
  if (!verified) throw new RSError("rs_signature_invalid", "signature did not verify");
  return decodeSegment(parts[1], "payload");
}

function ecdsaHash(alg: string): string {
  return alg === "ES384" ? "SHA-384" : alg === "ES512" ? "SHA-512" : "SHA-256";
}

/**
 * Verify an access token LOCALLY: JWS signature against the cached JWKS plus
 * the full claim gates. The authorization server is not on the request path.
 *
 * @throws {RSError} with an {@link RSErrorCode} the caller may branch on.
 */
export async function validateToken(token: string, config: RSConfig): Promise<RSClaims> {
  if (config.issuer === "") {
    throw new RSError("rs_config", "issuer required");
  }
  if (!config.jwks) {
    throw new RSError("rs_config", "a jwks cache is required for local validation");
  }
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] === "" || parts[1] === "" || parts[2] === "") {
    throw new RSError("rs_token_malformed", "not a compact JWS");
  }
  const header = decodeJson<{ alg?: string; kid?: string; typ?: string }>(
    decodeSegment(parts[0], "header"),
    "header parse",
  );
  checkAccessTokenTyp(header.typ);
  if (typeof header.alg !== "string" || header.alg === "") {
    throw new RSError("rs_token_malformed", "header has no alg");
  }
  // The allowlist gate runs before any signature work, and `none`/HS* are
  // refused by effectiveAlgs regardless of what the caller listed.
  if (!effectiveAlgs(config).has(header.alg)) {
    throw new RSError("rs_signature_invalid", `alg ${header.alg} is not allowed`);
  }
  const kid = typeof header.kid === "string" ? header.kid : "";
  // An unknown kid collapses into the signature class: whether the key is
  // absent or the signature is wrong must look identical to a token holder.
  const jwk = await config.jwks.getJWK(kid);
  if (!jwk) {
    throw new RSError("rs_signature_invalid", "no verification key for kid");
  }
  const payloadBytes = await verifySignature(token, { alg: header.alg, kid, typ: header.typ ?? "" }, config, jwk);
  const claims = claimsFrom(decodeJson<Record<string, unknown>>(payloadBytes, "payload parse"));
  return validateClaims(claims, config);
}

/**
 * Verify an access token by asking the RFC 7662 introspection endpoint, so
 * revocation is visible immediately. The round-trip failure is reported as
 * `rs_introspection_failed`, distinct from `rs_token_inactive`, so a caller can
 * choose its own fail mode for an authorization-server outage.
 */
export async function validateTokenWithIntrospect(token: string, config: RSConfig): Promise<RSClaims> {
  if (config.issuer === "") {
    throw new RSError("rs_config", "issuer required");
  }
  if (!config.introspectUrl) {
    throw new RSError("rs_config", "introspectUrl required for remote validation");
  }
  if (!config.introspectCreds) {
    throw new RSError("rs_config", "introspectCreds required: an open endpoint is an oracle");
  }
  const doFetch = config.fetch ?? ((input, init) => fetch(input, init));
  const basic = btoa(`${config.introspectCreds.id}:${config.introspectCreds.secret}`);
  let response: Response;
  try {
    response = await doFetch(config.introspectUrl, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
        authorization: `Basic ${basic}`,
      },
      body: new URLSearchParams({ token }).toString(),
    });
  } catch (cause) {
    throw new RSError("rs_introspection_failed", String(cause));
  }
  if (!response.ok) {
    throw new RSError("rs_introspection_failed", `status ${response.status}`);
  }
  let body: Record<string, unknown>;
  try {
    body = (await response.json()) as Record<string, unknown>;
  } catch (cause) {
    throw new RSError("rs_introspection_failed", String(cause));
  }
  if (body.active !== true) {
    // RFC 7662 deliberately does not say whether this is revoked, expired, or
    // never issued.
    throw new RSError("rs_token_inactive", "introspection reported inactive");
  }
  const claims = claimsFrom(body);
  // Introspection-only field: the server's token-policy governance asks for a
  // renewal before it starts reporting the token inactive.
  if (typeof body.renew_after === "number" && body.renew_after > 0) {
    Object.defineProperty(claims, "renewAfter", { value: body.renew_after, enumerable: false });
  }
  return validateClaims(claims, config);
}

/**
 * Route to remote introspection when configured, else local signature
 * validation — the shared entry point {@link rsMiddleware} uses.
 */
export function validateTokenByMode(token: string, config: RSConfig): Promise<RSClaims> {
  return config.introspectUrl
    ? validateTokenWithIntrospect(token, config)
    : validateToken(token, config);
}

/** Whether the token's `scope` claim contains `scope` exactly. */
export function hasScope(claims: RSClaims, scope: string): boolean {
  return claims.scopes().includes(scope);
}

/** Resolves only when EVERY required scope is present, naming the first missing
 * one. */
export function checkScope(claims: RSClaims, ...required: readonly string[]): void {
  for (const want of required) {
    if (!hasScope(claims, want)) {
      throw new RSError("rs_insufficient_scope", want);
    }
  }
}

/** Resolves when AT LEAST ONE listed scope is present — the "reader or admin may
 * pass" shape. An empty list matches nothing (fail-closed). */
export function checkAnyScope(claims: RSClaims, ...any: readonly string[]): void {
  for (const want of any) {
    if (hasScope(claims, want)) return;
  }
  throw new RSError("rs_insufficient_scope", `none of ${any.join(",")}`);
}

/** The token subject, or `rs_subject_missing` — the guard that keeps a
 * client_credentials (machine) token out of user-only endpoints. */
export function requireSubject(claims: RSClaims): string {
  if (claims.subject === "") {
    throw new RSError("rs_subject_missing", "no sub claim");
  }
  return claims.subject;
}

/**
 * The RFC 6750 challenge for a failure, mirroring Go `rs.writeChallenge`.
 *
 * A missing token gets a bare `Bearer` challenge with no `error=`; an invalid
 * one gets `error="invalid_token"` — the exact opaque-failure shape
 * `/userinfo` returns, so this never leaks which gate rejected the token.
 * `insufficient_scope` carries the required scopes and the `scope` attribute.
 */
export function wwwAuthenticate(
  failure: RSError,
  required: readonly string[] = [],
): string {
  if (failure.code === "rs_insufficient_scope") {
    const scope = required.join(" ");
    return scope === ""
      ? 'Bearer error="insufficient_scope"'
      : `Bearer error="insufficient_scope", scope="${scope}"`;
  }
  return 'Bearer error="invalid_token"';
}

/** A handler guarded by the RS middleware. */
export type RSHandler = (request: Request, claims: RSClaims) => Response | Promise<Response>;

function basicAuthResponse(status: number, challenge: string): Response {
  return new Response(null, {
    status,
    headers: {
      "www-authenticate": challenge,
      "cache-control": "no-store",
      pragma: "no-cache",
      "content-type": "application/json;charset=utf-8",
    },
  });
}

/** Read the bearer token, mirroring Go `rs.extractToken`. A `DPoP` scheme is
 * recognized and refused rather than ignored: accepting a sender-constrained
 * token without verifying its proof would be a silent downgrade. */
export function extractToken(request: Request): string {
  const header = request.headers.get("authorization");
  if (!header) return "";
  const [scheme, ...rest] = header.trim().split(/\s+/);
  const token = rest.join(" ");
  if (scheme === undefined) return "";
  if (scheme.toLowerCase() === "dpop") {
    throw new RSError("rs_signature_invalid", "DPoP-bound tokens are not supported in this runtime");
  }
  if (scheme.toLowerCase() !== "bearer") return "";
  return token;
}

/**
 * A Web-standard `Request -> Response` middleware, the Fetch-API counterpart of
 * Go `rs.HTTPMiddleware` and usable from Deno, Bun, Node 18+, and edge
 * runtimes.
 *
 * The validated claims are passed to the handler as its second argument; the
 * immutable `Request` is not mutated. Failures become an RFC 6750 challenge
 * response and never reach the handler.
 */
export function rsMiddleware(config: RSConfig, handler: RSHandler): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    let claims: RSClaims;
    try {
      const token = extractToken(request);
      if (token === "") {
        return basicAuthResponse(401, "Bearer");
      }
      claims = await validateTokenByMode(token, config);
    } catch (failure) {
      if (failure instanceof RSError) {
        return basicAuthResponse(401, wwwAuthenticate(failure));
      }
      throw failure;
    }
    return handler(request, claims);
  };
}
