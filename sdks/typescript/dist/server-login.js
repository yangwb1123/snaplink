/**
 * Server-side hosted login for a public OAuth client (BFF shape).
 *
 * `browser-login.ts` drives the same protocol from a page: it creates the
 * state/PKCE transaction, navigates the browser, and resumes on the next
 * load. A server-side host cannot navigate, and a navigation that never
 * completes leaves the pending transaction unresolved, so this module keeps
 * the same protocol shape in two explicit phases instead:
 *
 *   1. `login({ ... })` with no callback URL returns `{ kind: "redirect" }`.
 *      The host returns `redirectUrl` as an HTTP 302.
 *   2. `login({ ... callbackUrl })` with the request URL the authorization
 *      server redirected to validates the transaction and exchanges the code.
 *
 * This mirrors `sdks/go/login.go`: same validation order, same single-use
 * transaction semantics, same `state` and RFC 9207 `iss` checks. Differences
 * are deliberate and documented in docs/sdks/typescript/README.md.
 */
import { buildHostedLoginURL } from "./hosted-login.js";
import { SSOClient, SSOError } from "./client.js";
const DEFAULT_TRANSACTION_TTL_MS = 10 * 60_000;
const DEFAULT_SCOPE = ["openid", "profile", "email"];
/** Single-process store. Development and examples only. */
export class MemoryStateStore {
    values = new Map();
    take(key) {
        const value = this.values.get(key);
        this.values.delete(key);
        return value;
    }
    save(key, transaction) {
        this.values.set(key, transaction);
    }
}
export class SnaplinkServerClient {
    store;
    fetchImpl;
    requestTimeoutMs;
    constructor(options = {}) {
        this.store = options.store ?? new MemoryStateStore();
        this.fetchImpl = options.fetch ?? fetch;
        this.requestTimeoutMs = options.requestTimeoutMs;
    }
    /**
     * Starts hosted login, or completes a callback supplied in `callbackUrl`.
     * The host returns `redirectUrl` as a 302 when the result asks to redirect.
     */
    async login(options) {
        const config = normalizeOptions(options);
        const callback = callbackValues(options.callbackUrl, config);
        if (callback)
            return this.finish(config, callback);
        return this.start(config, options);
    }
    async start(config, options) {
        const codeVerifier = randomBase64URL(32);
        const transaction = {
            baseUrl: config.baseUrl,
            clientId: config.clientId,
            codeVerifier,
            redirectUri: config.redirectUri,
            returnTo: config.returnTo,
            state: randomBase64URL(32),
            createdAt: Date.now(),
            transactionTtlMs: config.transactionTtlMs,
        };
        const redirectUrl = buildHostedLoginURL({
            loginPageUrl: config.loginPageUrl,
            clientId: config.clientId,
            redirectUri: config.redirectUri,
            responseType: "code",
            responseMode: "query",
            scope: config.scope,
            state: transaction.state,
            codeChallenge: await sha256Base64URL(codeVerifier),
            codeChallengeMethod: "S256",
            resource: options.resource,
            prompt: options.prompt,
            maxAge: options.maxAge,
            loginHint: options.loginHint,
            acrValues: options.acrValues,
            uiLocales: options.uiLocales,
            allowInsecureHttpForDevelopment: options.allowInsecureHttpForDevelopment,
        });
        // Persist only after the URL is known good: an unusable login page must
        // not leave an orphan transaction the caller can never complete.
        this.store.save(storeKey(config.clientId), transaction);
        return { kind: "redirect", redirectUrl, returnTo: config.returnTo };
    }
    async finish(config, callback) {
        const transaction = this.store.take(storeKey(config.clientId));
        // The TTL travels with the transaction: a host that builds its options per
        // request and forgets to repeat `transactionTtlMs` on the callback must not
        // silently fall back to the default expiry.
        const ttlMs = transaction?.transactionTtlMs ?? config.transactionTtlMs;
        if (!transaction || !Number.isFinite(transaction.createdAt) || Date.now() - transaction.createdAt > ttlMs) {
            throw invalidRequest("hosted-login transaction is missing or expired");
        }
        if (!callback.state || !constantTimeEqual(callback.state, transaction.state)) {
            throw invalidRequest("hosted-login state did not match");
        }
        // RFC 9207 issuer identification: an authorization response that names a
        // different issuer is not ours, even when the code is otherwise valid.
        if (canonicalUrl(callback.issuer) !== canonicalUrl(transaction.baseUrl)) {
            throw invalidRequest("authorization issuer did not match Snaplink");
        }
        if (callback.error) {
            throw new SSOError(0, callback.error, callback.errorDescription);
        }
        if (!callback.code) {
            throw invalidRequest("authorization response did not contain a code");
        }
        const tokens = await this.exchange(transaction, callback.code);
        return { kind: "tokens", tokens, returnTo: transaction.returnTo };
    }
    async exchange(transaction, code) {
        const client = new SSOClient({
            baseUrl: transaction.baseUrl,
            clientId: transaction.clientId,
            fetch: this.fetchImpl,
            requestTimeoutMs: this.requestTimeoutMs,
        });
        return client.postToken({
            grant_type: "authorization_code",
            client_id: transaction.clientId,
            code,
            code_verifier: transaction.codeVerifier,
            redirect_uri: transaction.redirectUri,
        });
    }
}
function normalizeOptions(options) {
    const baseUrl = requiredText(options.baseUrl, "baseUrl").replace(/\/+$/, "");
    const clientId = requiredText(options.clientId, "clientId");
    const redirectUri = requiredText(options.redirectUri, "redirectUri");
    const returnTo = options.returnTo ? requiredText(options.returnTo, "returnTo") : redirectUri;
    // A cross-origin landing URL turns an open redirect into a token-bearing
    // navigation, so the return target is pinned to the redirect URI origin.
    if (originOf(returnTo) !== originOf(redirectUri)) {
        throw invalidRequest("returnTo must use the redirectUri origin");
    }
    const scope = (options.scope ?? DEFAULT_SCOPE).map((value) => requiredText(value, "scope"));
    return {
        baseUrl,
        clientId,
        loginPageUrl: options.loginPageUrl ?? `${baseUrl}/login/`,
        redirectUri,
        returnTo,
        scope,
        transactionTtlMs: options.transactionTtlMs ?? DEFAULT_TRANSACTION_TTL_MS,
    };
}
/**
 * Returns the parsed callback, or undefined when `callbackUrl` is absent.
 * A URL that does not address the redirect URI is a configuration error, not
 * a login attempt, so it fails instead of silently starting a new login.
 */
function callbackValues(raw, config) {
    if (!raw)
        return undefined;
    if (canonicalUrl(raw) !== canonicalUrl(config.redirectUri)) {
        throw invalidRequest("callbackUrl does not match redirectUri");
    }
    const query = new URL(raw).searchParams;
    return {
        code: query.get("code") ?? "",
        state: query.get("state") ?? "",
        issuer: query.get("iss") ?? "",
        error: query.get("error") ?? "",
        errorDescription: query.get("error_description") ?? "",
    };
}
function storeKey(clientId) {
    return `snaplink:server-login:${encodeURIComponent(clientId)}`;
}
function requiredText(value, name) {
    if (typeof value !== "string" || value.trim() === "") {
        throw invalidRequest(`${name} is required`);
    }
    return value.trim();
}
function invalidRequest(description) {
    return new SSOError(0, "invalid_request", description);
}
function safeParse(value, name) {
    try {
        return new URL(value);
    }
    catch {
        throw invalidRequest(`${name} is not a valid URL`);
    }
}
function originOf(value) {
    try {
        return new URL(value).origin;
    }
    catch {
        return "";
    }
}
/**
 * Compares by URL semantics: scheme/host case, default port, trailing slash.
 * Query and fragment are dropped because the callback carries the
 * authorization response in them and the redirect URI never does.
 */
function canonicalUrl(value) {
    try {
        const url = new URL(value);
        return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
    }
    catch {
        return value;
    }
}
function constantTimeEqual(a, b) {
    if (a.length !== b.length)
        return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++)
        diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
}
function randomBase64URL(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    let binary = "";
    for (const byte of bytes)
        binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function sha256Base64URL(value) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
    let binary = "";
    for (const byte of new Uint8Array(digest))
        binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
