import {
  FetchLike,
  SSOClient,
  SSOError,
  TokenIssuance,
} from "./client.js";
import { buildHostedLoginURL } from "./hosted-login.js";

const transactionPrefix = "snaplink.login.transaction.v1.";
const handoffPrefix = "snaplink.login.handoff.v1.";
const defaultTransactionTTL = 10 * 60 * 1000;
const callbackParameterNames = [
  "code",
  "state",
  "iss",
  "error",
  "error_description",
  "error_uri",
];

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

  /** SSR/test seams; normal browser callers do not need these. */
  storage?: SnaplinkStorage;
  location?: SnaplinkLocation;
  history?: SnaplinkHistory;
  navigate?: (url: string) => void;
  fetch?: FetchLike;
}

interface LoginTransaction {
  baseUrl: string;
  clientId: string;
  codeChallenge: string;
  codeVerifier: string;
  createdAt: number;
  redirectUri: string;
  returnTo: string;
  state: string;
}

interface LoginHandoff {
  baseUrl: string;
  clientId: string;
  createdAt: number;
  issuedAt: number;
  tokens: TokenIssuance;
}

interface AuthorizationResponse {
  code?: string;
  error?: string;
  errorDescription?: string;
  errorURI?: string;
  iss?: string;
  state?: string;
}

interface ResolvedLoginOptions {
  baseUrl: string;
  clientId: string;
  fetch?: FetchLike;
  history?: SnaplinkHistory;
  location: SnaplinkLocation;
  loginPageUrl: string | URL;
  navigate: (url: string) => void;
  redirectUri: string;
  returnTo: string;
  storage: SnaplinkStorage;
  transactionTtlMs: number;
  options: SnaplinkLoginOptions;
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
export class SnaplinkBrowserClient {
  private apiClient: SSOClient | undefined;
  private apiConfig: { baseUrl: string; clientId: string } | undefined;
  private issuedAt = 0;
  private tokens: TokenIssuance | undefined;

  /** True while an unexpired access token is held in this page's memory. */
  get isLoggedIn(): boolean {
    return this.tokens !== undefined && !this.accessTokenExpired();
  }

  /** Access token held by this page, or undefined before login/after logout. */
  get accessToken(): string | undefined {
    return this.tokens?.access_token;
  }

  /** Generated API client with the current access-token provider. */
  get api(): SSOClient {
    if (!this.apiClient) {
      throw new SSOError(0, "login_required", "call snaplink.login() before using the API client");
    }
    return this.apiClient;
  }

  async login(options: SnaplinkLoginOptions): Promise<TokenIssuance> {
    const resolved = resolveLoginOptions(options);
    this.configureAPI(resolved);

    const handoff = consumeHandoff(resolved);
    if (handoff) {
      this.setTokens(handoff.tokens, handoff.issuedAt);
      return handoff.tokens;
    }

    if (this.hasUsableTokens(resolved)) return this.tokens as TokenIssuance;
    const refreshed = await this.tryRefresh(resolved);
    if (refreshed) return refreshed;

    const callback = readAuthorizationResponse(resolved.location.href);
    if (callback) return this.finishLogin(resolved, callback);

    const transaction = await createTransaction(resolved);
    writeTransaction(resolved.storage, transaction);
    const loginURL = buildHostedLoginURL({
      loginPageUrl: resolved.loginPageUrl,
      clientId: resolved.clientId,
      redirectUri: resolved.redirectUri,
      responseType: "code",
      responseMode: "query",
      scope: resolved.options.scope ?? ["openid", "profile", "email"],
      state: transaction.state,
      codeChallenge: transaction.codeChallenge,
      codeChallengeMethod: "S256",
      resource: resolved.options.resource,
      prompt: resolved.options.prompt,
      maxAge: resolved.options.maxAge,
      loginHint: resolved.options.loginHint,
      acrValues: resolved.options.acrValues,
      uiLocales: resolved.options.uiLocales,
      allowInsecureHttpForDevelopment: resolved.options.allowInsecureHttpForDevelopment,
    });
    resolved.navigate(loginURL);
    return waitForNavigation();
  }

  /** Best-effort server logout followed by local token removal. */
  async logout(): Promise<void> {
    try {
      if (this.tokens && this.apiClient) await this.apiClient.postLogout({});
    } finally {
      this.clearTokens();
    }
  }

  private configureAPI(options: ResolvedLoginOptions): void {
    if (
      this.apiClient &&
      this.apiConfig?.baseUrl === options.baseUrl &&
      this.apiConfig.clientId === options.clientId
    ) {
      return;
    }
    this.apiClient = new SSOClient({
      baseUrl: options.baseUrl,
      clientId: options.clientId,
      fetch: options.fetch,
      getAccessToken: () => this.tokens?.access_token,
    });
    this.apiConfig = { baseUrl: options.baseUrl, clientId: options.clientId };
    this.clearTokens();
  }

  private async finishLogin(
    options: ResolvedLoginOptions,
    response: AuthorizationResponse,
  ): Promise<TokenIssuance> {
    const key = transactionKey(options.clientId);
    const transaction = readTransaction(options.storage, key);
    if (!transaction || transactionExpired(transaction, options.transactionTtlMs)) {
      options.storage.removeItem(key);
      cleanAuthorizationResponse(options);
      throw new SSOError(0, "invalid_request", "the hosted-login transaction is missing or expired");
    }

    try {
      validateAuthorizationResponse(options, transaction, response);
      if (response.error) {
        throw new SSOError(0, response.error, response.errorDescription);
      }
      if (!response.code) {
        throw new SSOError(0, "invalid_request", "the authorization response did not contain a code");
      }
      const tokens = await this.api.postToken({
        grant_type: "authorization_code",
        client_id: transaction.clientId,
        code: response.code,
        code_verifier: transaction.codeVerifier,
        redirect_uri: transaction.redirectUri,
      });
      this.setTokens(tokens, Date.now());
      options.storage.removeItem(key);
      cleanAuthorizationResponse(options);

      if (transaction.returnTo !== cleanURL(options.location.href)) {
        writeHandoff(options.storage, {
          baseUrl: transaction.baseUrl,
          clientId: transaction.clientId,
          createdAt: Date.now(),
          issuedAt: this.issuedAt,
          tokens,
        });
        options.navigate(transaction.returnTo);
        return waitForNavigation();
      }
      return tokens;
    } catch (error) {
      options.storage.removeItem(key);
      cleanAuthorizationResponse(options);
      throw error;
    }
  }

  private hasUsableTokens(options: ResolvedLoginOptions): boolean {
    return this.apiConfig?.baseUrl === options.baseUrl &&
      this.apiConfig.clientId === options.clientId &&
      this.tokens !== undefined &&
      !this.accessTokenExpired();
  }

  private async tryRefresh(options: ResolvedLoginOptions): Promise<TokenIssuance | undefined> {
    if (!this.tokens?.refresh_token || !this.accessTokenExpired()) return undefined;
    try {
      const refreshed = await this.api.postToken({
        grant_type: "refresh_token",
        client_id: options.clientId,
        refresh_token: this.tokens.refresh_token,
      });
      this.setTokens(refreshed, Date.now());
      return refreshed;
    } catch (error) {
      if (!(error instanceof SSOError) || (error.status !== 400 && error.status !== 401)) throw error;
      this.clearTokens();
      return undefined;
    }
  }

  private setTokens(tokens: TokenIssuance, issuedAt: number): void {
    this.tokens = tokens;
    this.issuedAt = issuedAt;
  }

  private clearTokens(): void {
    this.tokens = undefined;
    this.issuedAt = 0;
  }

  private accessTokenExpired(): boolean {
    if (!this.tokens) return true;
    if (!Number.isFinite(this.tokens.expires_in) || this.tokens.expires_in <= 0) return false;
    return Date.now() >= this.issuedAt + this.tokens.expires_in * 1000;
  }
}

/** Default singleton for the requested `snaplink.login({...})` API. */
export const snaplink = new SnaplinkBrowserClient();

export default snaplink;

function resolveLoginOptions(options: SnaplinkLoginOptions): ResolvedLoginOptions {
  rejectConfidentialOptions(options);
  const location = options.location ?? browserLocation();
  const current = new URL(location.href);
  const baseUrl = normalizeBaseURL(options.baseUrl);
  const clientId = requiredText(options.clientId, "clientId");
  const redirectUri = options.redirectUri
    ? absoluteURL(options.redirectUri, "redirectUri")
    : `${current.origin}${current.pathname || "/"}`;
  const returnTo = absoluteSameOriginURL(options.returnTo ?? current.toString(), current, "returnTo");
  const transactionTtlMs = options.transactionTtlMs ?? defaultTransactionTTL;
  if (!Number.isSafeInteger(transactionTtlMs) || transactionTtlMs <= 0) {
    throw new SSOError(0, "invalid_request", "transactionTtlMs must be a positive safe integer");
  }
  const storage = options.storage ?? browserSessionStorage();
  const history = options.history ?? browserHistory();
  return {
    baseUrl,
    clientId,
    fetch: options.fetch,
    history,
    location,
    loginPageUrl: options.loginPageUrl ?? new URL("/login/", `${baseUrl}/`).toString(),
    navigate: options.navigate ?? ((url) => location.assign(url)),
    redirectUri,
    returnTo,
    storage,
    transactionTtlMs,
    options,
  };
}

function rejectConfidentialOptions(options: SnaplinkLoginOptions): void {
  const unsafe = options as unknown as Record<string, unknown>;
  if ("clientSecret" in unsafe || "client_secret" in unsafe) {
    throw new TypeError("browser hosted login does not accept client secrets");
  }
}

function normalizeBaseURL(value: string): string {
  const url = new URL(requiredText(value, "baseUrl"));
  if (url.username || url.password || url.search || url.hash) {
    throw new TypeError("baseUrl must not contain credentials, a query, or a fragment");
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopbackHost(url.hostname))) {
    throw new TypeError("baseUrl must use HTTPS or loopback HTTP");
  }
  return url.toString().replace(/\/+$/, "");
}

function absoluteURL(value: string | URL, name: string): string {
  try {
    return new URL(value.toString()).toString();
  } catch {
    throw new TypeError(`${name} must be an absolute URL`);
  }
}

function absoluteSameOriginURL(value: string | URL, current: URL, name: string): string {
  let url: URL;
  try {
    url = new URL(value.toString(), current);
  } catch {
    throw new TypeError(`${name} must be a valid URL`);
  }
  if (url.origin !== current.origin || url.username || url.password) {
    throw new TypeError(`${name} must stay on the current origin`);
  }
  return url.toString();
}

function requiredText(value: string, name: string): string {
  if (typeof value !== "string" || value.trim() === "") throw new TypeError(`${name} is required`);
  return value;
}

async function createTransaction(options: ResolvedLoginOptions): Promise<LoginTransaction> {
  const codeVerifier = randomBase64URL(64);
  return {
    baseUrl: options.baseUrl,
    clientId: options.clientId,
    codeChallenge: await sha256Base64URL(codeVerifier),
    codeVerifier,
    createdAt: Date.now(),
    redirectUri: options.redirectUri,
    returnTo: options.returnTo,
    state: randomBase64URL(32),
  };
}

function writeTransaction(storage: SnaplinkStorage, transaction: LoginTransaction): void {
  storage.setItem(transactionKey(transaction.clientId), JSON.stringify(transaction));
}

function readTransaction(storage: SnaplinkStorage, key: string): LoginTransaction | undefined {
  return readJSON<LoginTransaction>(storage, key);
}

function writeHandoff(storage: SnaplinkStorage, handoff: LoginHandoff): void {
  storage.setItem(handoffKey(handoff.clientId), JSON.stringify(handoff));
}

function consumeHandoff(options: ResolvedLoginOptions): LoginHandoff | undefined {
  const key = handoffKey(options.clientId);
  const handoff = readJSON<LoginHandoff>(options.storage, key);
  if (!handoff) return undefined;
  options.storage.removeItem(key);
  if (
    handoff.baseUrl !== options.baseUrl ||
    handoff.clientId !== options.clientId ||
    Date.now() - handoff.createdAt > options.transactionTtlMs
  ) {
    throw new SSOError(0, "invalid_request", "the hosted-login handoff is missing, stale, or belongs to another client");
  }
  return handoff;
}

function readJSON<T>(storage: SnaplinkStorage, key: string): T | undefined {
  const raw = storage.getItem(key);
  if (!raw) return undefined;
  try {
    return JSON.parse(raw) as T;
  } catch {
    storage.removeItem(key);
    return undefined;
  }
}

function transactionKey(clientId: string): string {
  return transactionPrefix + encodeURIComponent(clientId);
}

function handoffKey(clientId: string): string {
  return handoffPrefix + encodeURIComponent(clientId);
}

function transactionExpired(transaction: LoginTransaction, ttl: number): boolean {
  return Date.now() - transaction.createdAt > ttl;
}

function readAuthorizationResponse(href: string): AuthorizationResponse | undefined {
  const url = new URL(href);
  const hasCode = url.searchParams.has("code");
  const hasError = url.searchParams.has("error");
  if (!hasCode && !hasError) return undefined;
  return {
    code: url.searchParams.get("code") ?? undefined,
    error: url.searchParams.get("error") ?? undefined,
    errorDescription: url.searchParams.get("error_description") ?? undefined,
    errorURI: url.searchParams.get("error_uri") ?? undefined,
    iss: url.searchParams.get("iss") ?? undefined,
    state: url.searchParams.get("state") ?? undefined,
  };
}

function validateAuthorizationResponse(
  options: ResolvedLoginOptions,
  transaction: LoginTransaction,
  response: AuthorizationResponse,
): void {
  if (!response.state || response.state !== transaction.state) {
    throw new SSOError(0, "invalid_request", "the hosted-login state did not match");
  }
  if (!response.iss || canonicalURL(response.iss) !== canonicalURL(transaction.baseUrl)) {
    throw new SSOError(0, "invalid_request", "the authorization issuer did not match the configured Snaplink issuer");
  }
  if (response.code && response.error) {
    throw new SSOError(0, "invalid_request", "the authorization response contained both code and error");
  }
  if (options.clientId !== transaction.clientId || options.baseUrl !== transaction.baseUrl) {
    throw new SSOError(0, "invalid_request", "the hosted-login transaction belongs to another client");
  }
}

function cleanAuthorizationResponse(options: ResolvedLoginOptions): void {
  const url = new URL(options.location.href);
  for (const name of callbackParameterNames) url.searchParams.delete(name);
  options.history?.replaceState(null, "", url.toString());
}

function cleanURL(href: string): string {
  const url = new URL(href);
  for (const name of callbackParameterNames) url.searchParams.delete(name);
  return url.toString();
}

function waitForNavigation(): Promise<never> {
  return new Promise<never>(() => undefined);
}

function randomBase64URL(length: number): string {
  const cryptoAPI = globalThis.crypto;
  if (!cryptoAPI?.getRandomValues) throw new SSOError(0, "invalid_request", "Web Crypto is required for hosted login");
  const bytes = new Uint8Array(length);
  cryptoAPI.getRandomValues(bytes);
  return encodeBase64URL(bytes);
}

async function sha256Base64URL(value: string): Promise<string> {
  const cryptoAPI = globalThis.crypto;
  if (!cryptoAPI?.subtle) throw new SSOError(0, "invalid_request", "Web Crypto is required for hosted login");
  const digest = await cryptoAPI.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return encodeBase64URL(new Uint8Array(digest));
}

function encodeBase64URL(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function browserLocation(): SnaplinkLocation {
  const value = globalThis.location;
  if (!value || typeof value.href !== "string" || typeof value.assign !== "function") {
    throw new SSOError(0, "invalid_request", "hosted login requires a browser location or an injected location adapter");
  }
  return value;
}

function browserHistory(): SnaplinkHistory | undefined {
  const value = globalThis.history;
  return value && typeof value.replaceState === "function" ? value : undefined;
}

function browserSessionStorage(): SnaplinkStorage {
  try {
    if (typeof sessionStorage !== "undefined") return sessionStorage;
  } catch {
    // Fall through to the explicit error below; private browsing may deny it.
  }
  throw new SSOError(0, "invalid_request", "sessionStorage is required to protect the hosted-login redirect");
}

function canonicalURL(value: string): string {
  return new URL(value).toString().replace(/\/+$/, "");
}

function isLoopbackHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
}
