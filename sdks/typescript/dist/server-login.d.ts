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
import type { TokenIssuance } from "./client.js";
export interface SnaplinkServerTransaction {
    baseUrl: string;
    clientId: string;
    codeVerifier: string;
    redirectUri: string;
    returnTo: string;
    state: string;
    createdAt: number;
    /** TTL in force when the transaction was created; bounds the callback phase. */
    transactionTtlMs?: number;
}
/**
 * Single-use transaction storage. `take` must consume atomically: a replayed
 * callback has to find nothing even when two requests race.
 */
export interface SnaplinkStateStore {
    take(key: string): SnaplinkServerTransaction | undefined;
    save(key: string, transaction: SnaplinkServerTransaction): void;
}
/** Single-process store. Development and examples only. */
export declare class MemoryStateStore implements SnaplinkStateStore {
    private readonly values;
    take(key: string): SnaplinkServerTransaction | undefined;
    save(key: string, transaction: SnaplinkServerTransaction): void;
}
export interface SnaplinkServerClientOptions {
    /** Defaults to an in-process store; a multi-replica host needs a shared one. */
    store?: SnaplinkStateStore;
    fetch?: typeof fetch;
    requestTimeoutMs?: number;
}
export interface SnaplinkServerLoginOptions {
    baseUrl: string;
    clientId: string;
    redirectUri: string;
    /** Defaults to `<baseUrl>/login/`. */
    loginPageUrl?: string;
    /** Post-login landing URL; must share the redirect URI origin. */
    returnTo?: string;
    scope?: readonly string[];
    resource?: readonly string[];
    prompt?: string;
    loginHint?: string;
    acrValues?: string;
    uiLocales?: string;
    maxAge?: number;
    /** The callback request URL. Its presence selects the completion phase. */
    callbackUrl?: string;
    allowInsecureHttpForDevelopment?: boolean;
    transactionTtlMs?: number;
}
export type SnaplinkServerLoginResult = {
    kind: "redirect";
    redirectUrl: string;
    returnTo: string;
} | {
    kind: "tokens";
    tokens: TokenIssuance;
    returnTo: string;
};
export declare class SnaplinkServerClient {
    private readonly store;
    private readonly fetchImpl;
    private readonly requestTimeoutMs;
    constructor(options?: SnaplinkServerClientOptions);
    /**
     * Starts hosted login, or completes a callback supplied in `callbackUrl`.
     * The host returns `redirectUrl` as a 302 when the result asks to redirect.
     */
    login(options: SnaplinkServerLoginOptions): Promise<SnaplinkServerLoginResult>;
    private start;
    private finish;
    private exchange;
}
