import { ActivationContextResponse, ActivationPrepareResponse, FetchLike, SSOClient, TokenIssuance } from "./client.js";
/** Minimal storage contract used for the cross-navigation login transaction. */
export interface SnaplinkStorage {
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
    removeItem(key: string): void;
}
/** Browser location seam, exposed so SSR/tests can provide a safe adapter. */
export interface SnaplinkLocation {
    href: string;
    assign(url: string): void;
}
/** History seam used to remove one-use OAuth parameters after callback. */
export interface SnaplinkHistory {
    replaceState(data: unknown, unused: string, url?: string | URL | null): void;
}
/** Product activation options. The credential is sent only in the HTTPS body. */
export interface SnaplinkSetupOptions {
    baseUrl: string;
    clientId: string;
    productId: string;
    licenseKey?: string;
    invitationCode?: string;
    tenantHint?: string;
    locale?: string;
    appVersion?: string;
    /** Development-only opt-in for trusted non-loopback HTTP URLs. */
    allowInsecureHttpForDevelopment?: boolean;
    storage?: SnaplinkStorage;
    fetch?: FetchLike;
}
/** Inline setup options for login(); baseUrl and clientId come from login(). */
export interface SnaplinkLoginSetup {
    productId: string;
    licenseKey?: string;
    invitationCode?: string;
    tenantHint?: string;
    locale?: string;
    appVersion?: string;
}
export type ActivationPreparation = ActivationPrepareResponse;
export type AccountContext = ActivationContextResponse["context"];
/** Options for a browser-only, public-client hosted login. */
export interface SnaplinkLoginOptions {
    /** Snaplink issuer/API base URL, for example https://sso.example.com. */
    baseUrl: string;
    /** Public OAuth client registered for this browser application. */
    clientId: string;
    /** Existing Console hosted login page; defaults to <baseUrl>/login/. */
    loginPageUrl?: string | URL;
    /** Registered code callback; defaults to the current path without query/hash. */
    redirectUri?: string | URL;
    /** Where to return after a callback handled on a dedicated callback route. */
    returnTo?: string | URL;
    /** Requested OAuth/OIDC scopes. */
    scope?: readonly string[];
    /** RFC 8707 resource indicators. */
    resource?: readonly string[];
    prompt?: string | readonly string[];
    maxAge?: number;
    loginHint?: string;
    acrValues?: string | readonly string[];
    uiLocales?: string | readonly string[];
    /** Development-only LAN HTTP opt-in; never enable this in production. */
    allowInsecureHttpForDevelopment?: boolean;
    /** Lifetime of the state/verifier transaction kept in sessionStorage. */
    transactionTtlMs?: number;
    /** Optional paid license/invitation activation performed before hosted login. */
    setup?: SnaplinkLoginSetup;
    /** SSR/test seams; normal browser callers do not need these. */
    storage?: SnaplinkStorage;
    location?: SnaplinkLocation;
    history?: SnaplinkHistory;
    navigate?: (url: string) => void;
    fetch?: FetchLike;
}
/**
 * Browser facade for the public-client authorization-code flow.
 *
 * It deliberately has no client-secret option. The first login call stores a
 * state/verifier transaction and navigates to the separately deployed Console
 * login page. The same call made by the application after the redirect detects
 * the callback, validates it, exchanges the code, and exposes the bearer-backed
 * generated API client through `api`.
 */
export declare class SnaplinkBrowserClient {
    private apiClient;
    private apiConfig;
    private issuedAt;
    private tokens;
    private activationContext;
    /** True while an unexpired access token is held in this page's memory. */
    get isLoggedIn(): boolean;
    /** Access token held by this page, or undefined before login/after logout. */
    get accessToken(): string | undefined;
    /** The server-derived product/account context from the latest activation. */
    get accountContext(): AccountContext | undefined;
    /** Generated API client with the current access-token provider. */
    get api(): SSOClient;
    login(options: SnaplinkLoginOptions): Promise<TokenIssuance>;
    /** Prepare a one-time activation ticket before calling login(). */
    setup(options: SnaplinkSetupOptions): Promise<ActivationPreparation>;
    /** Fetch server-derived plan, feature, and quota information for a product. */
    getAccountContext(productId?: string): Promise<AccountContext>;
    /** Best-effort server logout followed by local token removal. */
    logout(): Promise<void>;
    private configureAPI;
    private configureAPIValues;
    private finishLogin;
    private hasUsableTokens;
    private tryRefresh;
    private prepareSetup;
    private claimPendingSetup;
    private claimActivation;
    private setTokens;
    private clearTokens;
    private accessTokenExpired;
}
/** Default singleton for the requested `snaplink.login({...})` API. */
export declare const snaplink: SnaplinkBrowserClient;
export default snaplink;
