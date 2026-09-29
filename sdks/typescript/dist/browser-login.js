import { SSOClient, SSOError, } from "./client.js";
import { buildHostedLoginURL } from "./hosted-login.js";
const transactionPrefix = "snaplink.login.transaction.v1.";
const handoffPrefix = "snaplink.login.handoff.v1.";
const activationPrefix = "snaplink.activation.pending.v1.";
const defaultTransactionTTL = 10 * 60 * 1000;
const callbackParameterNames = [
    "code",
    "state",
    "iss",
    "error",
    "error_description",
    "error_uri",
];
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
    apiClient;
    apiConfig;
    issuedAt = 0;
    tokens;
    activationContext;
    /** True while an unexpired access token is held in this page's memory. */
    get isLoggedIn() {
        return this.tokens !== undefined && !this.accessTokenExpired();
    }
    /** Access token held by this page, or undefined before login/after logout. */
    get accessToken() {
        return this.tokens?.access_token;
    }
    /** The server-derived product/account context from the latest activation. */
    get accountContext() {
        return this.activationContext;
    }
    /** Generated API client with the current access-token provider. */
    get api() {
        if (!this.apiClient) {
            throw new SSOError(0, "login_required", "call snaplink.login() before using the API client");
        }
        return this.apiClient;
    }
    async login(options) {
        const resolved = resolveLoginOptions(options);
        this.configureAPI(resolved);
        const handoff = consumeHandoff(resolved);
        if (handoff) {
            this.setTokens(handoff.tokens, handoff.issuedAt);
            this.activationContext = handoff.context;
            return handoff.tokens;
        }
        const callback = readAuthorizationResponse(resolved.location.href);
        if (!callback && resolved.options.setup)
            await this.prepareSetup(resolved, resolved.options.setup);
        if (this.hasUsableTokens(resolved)) {
            await this.claimPendingSetup(resolved);
            return this.tokens;
        }
        const refreshed = await this.tryRefresh(resolved);
        if (refreshed) {
            await this.claimPendingSetup(resolved);
            return refreshed;
        }
        if (callback)
            return this.finishLogin(resolved, callback);
        const transaction = await createTransaction(resolved, readPendingSetup(resolved.storage, resolved.baseUrl, resolved.clientId));
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
    /** Prepare a one-time activation ticket before calling login(). */
    async setup(options) {
        rejectConfidentialOptions(options);
        const baseUrl = normalizeBaseURL(options.baseUrl, options.allowInsecureHttpForDevelopment === true);
        const clientId = requiredText(options.clientId, "clientId");
        const storage = options.storage ?? browserSessionStorage();
        this.configureAPIValues(baseUrl, clientId, options.fetch);
        const preparation = await this.api.postActivationPrepare(activationRequest(clientId, {
            productId: options.productId,
            licenseKey: options.licenseKey,
            invitationCode: options.invitationCode,
            tenantHint: options.tenantHint,
            locale: options.locale,
            appVersion: options.appVersion,
        }));
        writePendingSetup(storage, {
            activationTicket: preparation.activation_ticket,
            baseUrl,
            clientId,
            createdAt: Date.now(),
            productId: preparation.product_id,
        });
        return preparation;
    }
    /** Fetch server-derived plan, feature, and quota information for a product. */
    async getAccountContext(productId) {
        const resolvedProduct = requiredText(productId ?? this.activationContext?.product_id ?? "", "productId");
        const response = await this.api.getMyAccountContext({ productId: resolvedProduct });
        this.activationContext = response.context;
        return response.context;
    }
    /** Best-effort server logout followed by local token removal. */
    async logout() {
        try {
            if (this.tokens && this.apiClient)
                await this.apiClient.postLogout({});
        }
        finally {
            this.clearTokens();
            this.activationContext = undefined;
        }
    }
    configureAPI(options) {
        this.configureAPIValues(options.baseUrl, options.clientId, options.fetch);
    }
    configureAPIValues(baseUrl, clientId, fetchImpl) {
        if (this.apiClient &&
            this.apiConfig?.baseUrl === baseUrl &&
            this.apiConfig.clientId === clientId) {
            return;
        }
        this.apiClient = new SSOClient({
            baseUrl,
            clientId,
            fetch: fetchImpl,
            getAccessToken: () => this.tokens?.access_token,
        });
        this.apiConfig = { baseUrl, clientId };
        this.clearTokens();
        this.activationContext = undefined;
    }
    async finishLogin(options, response) {
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
            if (transaction.activationTicket && transaction.productId) {
                await this.claimActivation(options, transaction.activationTicket, transaction.productId);
            }
            options.storage.removeItem(key);
            cleanAuthorizationResponse(options);
            if (transaction.returnTo !== cleanURL(options.location.href)) {
                writeHandoff(options.storage, {
                    baseUrl: transaction.baseUrl,
                    clientId: transaction.clientId,
                    createdAt: Date.now(),
                    issuedAt: this.issuedAt,
                    tokens,
                    context: this.activationContext,
                });
                options.navigate(transaction.returnTo);
                return waitForNavigation();
            }
            return tokens;
        }
        catch (error) {
            if (transaction.activationTicket)
                this.clearTokens();
            options.storage.removeItem(key);
            cleanAuthorizationResponse(options);
            throw error;
        }
    }
    hasUsableTokens(options) {
        return this.apiConfig?.baseUrl === options.baseUrl &&
            this.apiConfig.clientId === options.clientId &&
            this.tokens !== undefined &&
            !this.accessTokenExpired();
    }
    async tryRefresh(options) {
        if (!this.tokens?.refresh_token || !this.accessTokenExpired())
            return undefined;
        try {
            const refreshed = await this.api.postToken({
                grant_type: "refresh_token",
                client_id: options.clientId,
                refresh_token: this.tokens.refresh_token,
            });
            this.setTokens(refreshed, Date.now());
            return refreshed;
        }
        catch (error) {
            if (!(error instanceof SSOError) || (error.status !== 400 && error.status !== 401))
                throw error;
            this.clearTokens();
            return undefined;
        }
    }
    async prepareSetup(options, setup) {
        rejectConfidentialOptions(setup);
        const preparation = await this.api.postActivationPrepare(activationRequest(options.clientId, setup));
        writePendingSetup(options.storage, {
            activationTicket: preparation.activation_ticket,
            baseUrl: options.baseUrl,
            clientId: options.clientId,
            createdAt: Date.now(),
            productId: preparation.product_id,
        });
    }
    async claimPendingSetup(options) {
        const pending = readPendingSetup(options.storage, options.baseUrl, options.clientId);
        if (pending)
            await this.claimActivation(options, pending.activationTicket, pending.productId);
    }
    async claimActivation(options, activationTicket, productId) {
        const result = await this.api.postMyActivationClaim({
            activation_ticket: activationTicket,
            product_id: productId,
        });
        this.activationContext = result.context;
        clearPendingSetup(options.storage, options.clientId, activationTicket);
        return result.context;
    }
    setTokens(tokens, issuedAt) {
        this.tokens = tokens;
        this.issuedAt = issuedAt;
    }
    clearTokens() {
        this.tokens = undefined;
        this.issuedAt = 0;
    }
    accessTokenExpired() {
        if (!this.tokens)
            return true;
        if (!Number.isFinite(this.tokens.expires_in) || this.tokens.expires_in <= 0)
            return false;
        return Date.now() >= this.issuedAt + this.tokens.expires_in * 1000;
    }
}
/** Default singleton for the requested `snaplink.login({...})` API. */
export const snaplink = new SnaplinkBrowserClient();
export default snaplink;
function resolveLoginOptions(options) {
    rejectConfidentialOptions(options);
    const location = options.location ?? browserLocation();
    const current = new URL(location.href);
    const allowInsecure = options.allowInsecureHttpForDevelopment === true;
    const baseUrl = normalizeBaseURL(options.baseUrl, allowInsecure);
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
function rejectConfidentialOptions(options) {
    const unsafe = options;
    if ("clientSecret" in unsafe || "client_secret" in unsafe) {
        throw new TypeError("browser hosted login does not accept client secrets");
    }
}
function normalizeBaseURL(value, allowInsecure = false) {
    const url = new URL(requiredText(value, "baseUrl"));
    if (url.username || url.password || url.search || url.hash) {
        throw new TypeError("baseUrl must not contain credentials, a query, or a fragment");
    }
    if (url.protocol !== "https:" &&
        !(url.protocol === "http:" && (isLoopbackHost(url.hostname) || allowInsecure))) {
        throw new TypeError("baseUrl must use HTTPS or loopback HTTP");
    }
    return url.toString().replace(/\/+$/, "");
}
function absoluteURL(value, name) {
    try {
        return new URL(value.toString()).toString();
    }
    catch {
        throw new TypeError(`${name} must be an absolute URL`);
    }
}
function absoluteSameOriginURL(value, current, name) {
    let url;
    try {
        url = new URL(value.toString(), current);
    }
    catch {
        throw new TypeError(`${name} must be a valid URL`);
    }
    if (url.origin !== current.origin || url.username || url.password) {
        throw new TypeError(`${name} must stay on the current origin`);
    }
    return url.toString();
}
function requiredText(value, name) {
    if (typeof value !== "string" || value.trim() === "")
        throw new TypeError(`${name} is required`);
    return value;
}
function optionalText(value) {
    return typeof value === "string" ? value : "";
}
function requiredString(value) {
    return typeof value === "string" && value.trim() !== "";
}
async function createTransaction(options, pending) {
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
        activationTicket: pending?.activationTicket,
        productId: pending?.productId,
    };
}
function writeTransaction(storage, transaction) {
    storage.setItem(transactionKey(transaction.clientId), JSON.stringify(transaction));
}
function readTransaction(storage, key) {
    return readJSON(storage, key);
}
function writeHandoff(storage, handoff) {
    storage.setItem(handoffKey(handoff.clientId), JSON.stringify(handoff));
}
function consumeHandoff(options) {
    const key = handoffKey(options.clientId);
    const handoff = readJSON(options.storage, key);
    if (!handoff)
        return undefined;
    options.storage.removeItem(key);
    if (handoff.baseUrl !== options.baseUrl ||
        handoff.clientId !== options.clientId ||
        Date.now() - handoff.createdAt > options.transactionTtlMs) {
        throw new SSOError(0, "invalid_request", "the hosted-login handoff is missing, stale, or belongs to another client");
    }
    return handoff;
}
function readJSON(storage, key) {
    const raw = storage.getItem(key);
    if (!raw)
        return undefined;
    try {
        return JSON.parse(raw);
    }
    catch {
        storage.removeItem(key);
        return undefined;
    }
}
function transactionKey(clientId) {
    return transactionPrefix + encodeURIComponent(clientId);
}
function activationKey(clientId) {
    return activationPrefix + encodeURIComponent(clientId);
}
function activationRequest(clientId, setup) {
    const productId = requiredText(setup.productId, "productId");
    const licenseKey = optionalText(setup.licenseKey);
    const invitationCode = optionalText(setup.invitationCode);
    if ((licenseKey === "") === (invitationCode === "")) {
        throw new SSOError(0, "invalid_request", "exactly one of licenseKey or invitationCode is required");
    }
    return {
        client_id: clientId,
        product_id: productId,
        ...(licenseKey ? { license_key: licenseKey } : {}),
        ...(invitationCode ? { invitation_code: invitationCode } : {}),
        ...(setup.tenantHint ? { tenant_hint: setup.tenantHint } : {}),
        ...(setup.locale ? { locale: setup.locale } : {}),
        ...(setup.appVersion ? { app_version: setup.appVersion } : {}),
    };
}
function writePendingSetup(storage, pending) {
    storage.setItem(activationKey(pending.clientId), JSON.stringify(pending));
}
function readPendingSetup(storage, baseUrl, clientId) {
    const key = activationKey(clientId);
    const pending = readJSON(storage, key);
    if (!pending)
        return undefined;
    if (pending.baseUrl !== baseUrl ||
        pending.clientId !== clientId ||
        !requiredString(pending.activationTicket) ||
        !requiredString(pending.productId) ||
        Date.now() - pending.createdAt > defaultTransactionTTL) {
        storage.removeItem(key);
        return undefined;
    }
    return pending;
}
function clearPendingSetup(storage, clientId, ticket) {
    const key = activationKey(clientId);
    const pending = readJSON(storage, key);
    if (pending?.activationTicket === ticket)
        storage.removeItem(key);
}
function handoffKey(clientId) {
    return handoffPrefix + encodeURIComponent(clientId);
}
function transactionExpired(transaction, ttl) {
    return Date.now() - transaction.createdAt > ttl;
}
function readAuthorizationResponse(href) {
    const url = new URL(href);
    const hasCode = url.searchParams.has("code");
    const hasError = url.searchParams.has("error");
    if (!hasCode && !hasError)
        return undefined;
    return {
        code: url.searchParams.get("code") ?? undefined,
        error: url.searchParams.get("error") ?? undefined,
        errorDescription: url.searchParams.get("error_description") ?? undefined,
        errorURI: url.searchParams.get("error_uri") ?? undefined,
        iss: url.searchParams.get("iss") ?? undefined,
        state: url.searchParams.get("state") ?? undefined,
    };
}
function validateAuthorizationResponse(options, transaction, response) {
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
function cleanAuthorizationResponse(options) {
    const url = new URL(options.location.href);
    for (const name of callbackParameterNames)
        url.searchParams.delete(name);
    options.history?.replaceState(null, "", url.toString());
}
function cleanURL(href) {
    const url = new URL(href);
    for (const name of callbackParameterNames)
        url.searchParams.delete(name);
    return url.toString();
}
function waitForNavigation() {
    return new Promise(() => undefined);
}
function randomBase64URL(length) {
    const cryptoAPI = globalThis.crypto;
    if (!cryptoAPI?.getRandomValues)
        throw new SSOError(0, "invalid_request", "Web Crypto is required for hosted login");
    const bytes = new Uint8Array(length);
    cryptoAPI.getRandomValues(bytes);
    return encodeBase64URL(bytes);
}
async function sha256Base64URL(value) {
    const cryptoAPI = globalThis.crypto;
    if (!cryptoAPI?.subtle)
        throw new SSOError(0, "invalid_request", "Web Crypto is required for hosted login");
    const digest = await cryptoAPI.subtle.digest("SHA-256", new TextEncoder().encode(value));
    return encodeBase64URL(new Uint8Array(digest));
}
function encodeBase64URL(bytes) {
    let binary = "";
    for (const byte of bytes)
        binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function browserLocation() {
    const value = globalThis.location;
    if (!value || typeof value.href !== "string" || typeof value.assign !== "function") {
        throw new SSOError(0, "invalid_request", "hosted login requires a browser location or an injected location adapter");
    }
    return value;
}
function browserHistory() {
    const value = globalThis.history;
    return value && typeof value.replaceState === "function" ? value : undefined;
}
function browserSessionStorage() {
    try {
        if (typeof sessionStorage !== "undefined")
            return sessionStorage;
    }
    catch {
        // Fall through to the explicit error below; private browsing may deny it.
    }
    throw new SSOError(0, "invalid_request", "sessionStorage is required to protect the hosted-login redirect");
}
function canonicalURL(value) {
    return new URL(value).toString().replace(/\/+$/, "");
}
function isLoopbackHost(hostname) {
    const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
    return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
}
