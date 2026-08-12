package main

// tsRuntime is the fetch-based transport every generated method calls
// through. Hand-written once rather than generated per-operation.
const tsRuntime = `export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export interface SSOClientOptions {
  /** Base URL of the snaplink/sso deployment, e.g. "https://sso.example.com". */
  baseUrl: string;
  /** This application's registered client_id. */
  clientId?: string;
  /** Confidential client secret. Server-side use only; sent with HTTP Basic. */
  clientSecret?: string;
  /** Per-request timeout in milliseconds. Omit to use the runtime fetch default. */
  requestTimeoutMs?: number;
  /** Injectable fetch (tests, non-global runtimes). Defaults to globalThis.fetch. */
  fetch?: FetchLike;
  /** Returns the bearer token for auth-required calls (getMe, revokeMySessions, ...).
   *  Omit it: after login() the SDK holds the access token and auto-attaches it. */
  getAccessToken?: () => string | undefined | Promise<string | undefined>;
}

/** Thrown on any non-2xx response; carries the parsed ErrorResponse when the body was JSON. */
export class SSOError extends Error {
  constructor(
    public status: number,
    public error?: string,
    public errorDescription?: string,
  ) {
    super(errorDescription || error || ` + "`sso request failed with status ${status}`" + `);
    this.name = "SSOError";
  }
}

interface requestOptions {
  query?: Record<string, string | number | boolean | readonly (string | number | boolean)[] | undefined>;
  body?: unknown;
  auth?: boolean;
  clientAuth?: boolean;
  /** Send the body as application/x-www-form-urlencoded instead of JSON. */
  form?: boolean;
  /** Body keys with no form encoding; never emitted (defense in depth behind the generated guard). */
  formBlockedFields?: string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function encodeBasicCredentials(clientId: string, clientSecret: string): string {
  const bytes = new TextEncoder().encode(clientId + ":" + clientSecret);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/**
 * Serialize a request body as application/x-www-form-urlencoded, mirroring
 * the Go binder in protocols/oauth/oauthwire (bind.go):
 * - undefined/null keys are dropped (JSON.stringify does the same today);
 * - blockedFields keys are never emitted (no RFC defines a map form encoding);
 * - booleans/numbers/strings use String(v) -- String(true) == "true", the
 *   binder's only accepted truthy spelling;
 * - string arrays become REPEATED keys (the documented resource/audience/
 *   tokens contract; formStringSlice returns multi-value lists verbatim);
 * - any other array (authorization_details) or plain object (claims) becomes
 *   a single key with JSON.stringify(value) -- RFC 9396 §3 / OIDC Core §5.5.
 */
function formSerialize(body: Record<string, unknown>, blockedFields: string[]): string {
  const params = new URLSearchParams();
  const blocked = new Set(blockedFields);
  for (const [k, v] of Object.entries(body)) {
    if (blocked.has(k) || v === undefined || v === null) continue;
    if (typeof v === "string" || typeof v === "boolean" || typeof v === "number") {
      params.set(k, String(v));
    } else if (Array.isArray(v) && v.every((item) => typeof item === "string")) {
      for (const item of v) params.append(k, item);
    } else {
      params.set(k, JSON.stringify(v));
    }
  }
  return params.toString();
}

`

// tsClientHeader opens the SSOClient class; tsEmitMethods fills the body,
// GenerateTS closes it with the final "}\n".
const tsClientHeader = `export class SSOClient {
  private readonly baseUrl: string;
  private readonly clientId: string | undefined;
  private readonly clientSecret: string | undefined;
  private readonly requestTimeoutMs: number | undefined;
  private readonly fetchImpl: FetchLike;
  private readonly getAccessToken: (() => string | undefined | Promise<string | undefined>) | undefined;
  /** Access token captured by login(); auto-attached to auth-required calls. */
  private token: string | undefined;

  constructor(opts: SSOClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.clientId = opts.clientId;
    this.clientSecret = opts.clientSecret;
    if (opts.requestTimeoutMs !== undefined && (!Number.isFinite(opts.requestTimeoutMs) || opts.requestTimeoutMs <= 0)) {
      throw new SSOError(0, "invalid_request", "requestTimeoutMs must be a positive finite number");
    }
    this.requestTimeoutMs = opts.requestTimeoutMs;
    this.fetchImpl = opts.fetch ?? fetch;
    // Default token source is the token login() captured, so getUserInfo() etc.
    // work right after login without wiring anything.
    this.getAccessToken = opts.getAccessToken ?? (() => this.token);
  }

  /** True once login() succeeded and a token is held. */
  get isLoggedIn(): boolean {
    return !!this.token;
  }

  /** The access token captured by login() (undefined before login/after logout). */
  get accessToken(): string | undefined {
    return this.token;
  }

  /**
   * Password login: fills in the configured client_id and returns the auth
   * info (access_token / id_token / refresh_token / ...) directly — no redirect.
   * The token is captured internally so subsequent getUserInfo()/getMe() calls
   * auto-attach it. This is the simplest integration:
   *
   *   const sso = new SSOClient({ baseUrl, clientId: "my-app" });
   *   const auth = await sso.login(username, password);
   *   const me = await sso.getUserInfo();
   *
   * CHECK isLoggedIn (or "access_token" in auth) before assuming success: when
   * the account/client has MFA enabled, this resolves to a MFARequiredResponse
   * instead — no token is issued until POST /auth/mfa completes the second leg.
   */
  async login(
    username: string,
    password: string,
    opts?: { clientId?: string; scope?: string[]; extraCredential?: Record<string, string> },
  ): Promise<LoginResponse | MFARequiredResponse> {
    const clientId = opts?.clientId ?? this.clientId;
    if (!clientId) {
      throw new SSOError(0, "invalid_request", "clientId is required (set it in the constructor or pass it to login)");
    }
    // provider is always set below, so postLogin's LoginDiscoveryResponse (the
    // no-provider home-realm-discovery arm) can never apply to this call.
    const resp = (await this.postLogin({
      provider: "password",
      client_id: clientId,
      scope: opts?.scope ?? ["openid", "profile", "email"],
      credential: { username, password, ...(opts?.extraCredential ?? {}) },
    })) as LoginResponse | MFARequiredResponse;
    if ("access_token" in resp) this.token = resp.access_token;
    return resp;
  }

  /** Clear the held token and best-effort revoke the server session. */
  async logout(): Promise<void> {
    try {
      if (this.token) await this.postLogout({});
    } finally {
      this.token = undefined;
    }
  }

  private async request<T>(method: string, path: string, opts: requestOptions = {}): Promise<T> {
    let url = this.baseUrl + path;
    if (opts.query) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(opts.query)) {
		if (Array.isArray(v)) {
		  for (const item of v) qs.append(k, String(item));
		} else if (v !== undefined) {
		  qs.set(k, String(v));
		}
      }
      const s = qs.toString();
      if (s) url += "?" + s;
    }
    const headers: Record<string, string> = { Accept: "application/json" };
    const authenticatedBody = opts.clientAuth ? this.withClientAuthentication(opts.body, headers) : opts.body;
    const init: RequestInit = { method, headers };
    if (this.requestTimeoutMs !== undefined) init.signal = AbortSignal.timeout(this.requestTimeoutMs);
    if (authenticatedBody !== undefined) {
      if (opts.form) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
        init.body = formSerialize(authenticatedBody as Record<string, unknown>, opts.formBlockedFields ?? []);
      } else {
        headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(authenticatedBody);
      }
    }
    if (opts.auth && this.getAccessToken) {
      const token = await this.getAccessToken();
      if (token) headers["Authorization"] = ` + "`Bearer ${token}`" + `;
    }
    const res = await this.fetchImpl(url, init);
    if (!res.ok) {
      let error: string | undefined;
      let errorDescription: string | undefined;
      try {
        const parsed = await res.json();
        error = parsed?.error;
        errorDescription = parsed?.error_description;
      } catch {
        // non-JSON error body; SSOError falls back to a generic message.
      }
      throw new SSOError(res.status, error, errorDescription);
    }
    if (res.status === 204) return undefined as T;
    const text = await res.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }

  private withClientAuthentication(body: unknown, headers: Record<string, string>): unknown {
    if (!isRecord(body)) return body;
    const clientId = this.clientId ?? stringValue(body.client_id);
    const clientSecret = this.clientSecret ?? stringValue(body.client_secret);
    if (!clientSecret) return body;
    if (!clientId) {
      throw new SSOError(0, "invalid_request", "clientId is required when a confidential client secret is configured");
    }
    headers["Authorization"] = "Basic " + encodeBasicCredentials(clientId, clientSecret);
    const withoutCredentials = { ...body };
    delete withoutCredentials.client_id;
    delete withoutCredentials.client_secret;
    return withoutCredentials;
  }
`
