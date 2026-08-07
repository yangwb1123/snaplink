/** Parameters for a Snaplink hosted-login authorization-code redirect. */
export interface HostedLoginURLParams {
  /** Absolute URL of the separately deployed Snaplink login page. */
  loginPageUrl: string | URL;
  /** Registered Snaplink OAuth client identifier. */
  clientId: string;
  /** Registered callback URL that receives code, state, and iss. */
  redirectUri: string | URL;
  /** Hosted login only supports the authorization-code flow. */
  responseType: "code";
  /** Requested OAuth/OIDC scopes. */
  scope: readonly string[];
  /** Opaque CSRF value persisted and verified by the relying party. */
  state: string;
  /** RFC 7636 SHA-256 challenge. Never pass the verifier to this helper. */
  codeChallenge: string;
  /** Hosted login deliberately refuses the weaker plain PKCE method. */
  codeChallengeMethod: "S256";

  nonce?: string;
  prompt?: string | readonly string[];
  maxAge?: number;
  loginHint?: string;
  acrValues?: string | readonly string[];
  uiLocales?: string | readonly string[];
  responseMode?: string;
  resource?: readonly string[];
  requestUri?: string;
  request?: string;
  authorizationDetails?: string | readonly unknown[];
  claims?: string | Readonly<Record<string, unknown>>;
  idTokenHint?: string;

  /**
   * Development-only escape hatch for LAN URLs such as http://192.168.x.x.
   * HTTPS and loopback HTTP work without this flag. Never enable it in production.
   */
  allowInsecureHttpForDevelopment?: boolean;
}

const sensitiveParameterNames = new Set(["clientsecret", "codeverifier"]);

/**
 * Build the browser navigation target for a separately deployed Snaplink login UI.
 *
 * The function is intentionally a URL builder, not a fetch call: browser-based
 * authorization and federated IdP redirects must happen as top-level navigation.
 * It accepts neither a client secret nor a PKCE verifier, so those values cannot
 * be disclosed through the authorization URL.
 */
export function buildHostedLoginURL(params: HostedLoginURLParams): string {
  rejectSensitiveProperties(params);
  assertLiteral(params.responseType, "code", "responseType");
  assertLiteral(params.codeChallengeMethod, "S256", "codeChallengeMethod");
  assertNonEmpty(params.clientId, "clientId");
  assertNonEmpty(params.state, "state");
  assertS256Challenge(params.codeChallenge);

  const allowInsecure = params.allowInsecureHttpForDevelopment === true;
  const loginPage = parseAndValidateURL(params.loginPageUrl, "loginPageUrl", allowInsecure);
  const redirect = parseAndValidateURL(params.redirectUri, "redirectUri", allowInsecure);
  rejectSensitiveQuery(loginPage, "loginPageUrl");
  rejectSensitiveQuery(redirect, "redirectUri");

  const scopes = validateSpaceDelimited(params.scope, "scope");
  setCoreParameters(loginPage, params, redirect, scopes);
  setOptionalParameters(loginPage, params);
  return loginPage.toString();
}

function setCoreParameters(
  url: URL,
  params: HostedLoginURLParams,
  redirect: URL,
  scopes: string,
): void {
  url.searchParams.set("client_id", params.clientId);
  url.searchParams.set("redirect_uri", redirect.toString());
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", scopes);
  url.searchParams.set("state", params.state);
  url.searchParams.set("code_challenge", params.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
}

function setOptionalParameters(url: URL, params: HostedLoginURLParams): void {
  clearManagedOptionalParameters(url);
  setOptional(url, "nonce", params.nonce);
  setOptional(url, "prompt", optionalSpaceDelimited(params.prompt, "prompt"));
  setOptional(url, "login_hint", params.loginHint);
  setOptional(url, "acr_values", optionalSpaceDelimited(params.acrValues, "acrValues"));
  setOptional(url, "ui_locales", optionalSpaceDelimited(params.uiLocales, "uiLocales"));
  setOptional(url, "response_mode", params.responseMode);
  setOptional(url, "request_uri", params.requestUri);
  setOptional(url, "request", params.request);
  setOptional(url, "authorization_details", encodeJSONParameter(params.authorizationDetails));
  setOptional(url, "claims", encodeJSONParameter(params.claims));
  setOptional(url, "id_token_hint", params.idTokenHint);
  setMaxAge(url, params.maxAge);
  setResources(url, params.resource);
}

function clearManagedOptionalParameters(url: URL): void {
  for (const name of [
    "nonce",
    "prompt",
    "max_age",
    "login_hint",
    "acr_values",
    "ui_locales",
    "response_mode",
    "resource",
    "request_uri",
    "request",
    "authorization_details",
    "claims",
    "id_token_hint",
  ]) {
    url.searchParams.delete(name);
  }
}

function parseAndValidateURL(value: string | URL, name: string, allowInsecure: boolean): URL {
  let url: URL;
  try {
    url = new URL(value.toString());
  } catch {
    throw new TypeError(`${name} must be an absolute HTTP(S) URL`);
  }
  if (!url.hostname || url.username || url.password || url.hash) {
    throw new TypeError(`${name} must not contain credentials or a fragment`);
  }
  if (url.protocol === "https:") return url;
  if (url.protocol !== "http:") {
    throw new TypeError(`${name} must use HTTPS or loopback HTTP`);
  }
  if (!isLoopbackHost(url.hostname) && !allowInsecure) {
    throw new TypeError(
      `${name} uses non-loopback HTTP; set allowInsecureHttpForDevelopment only for trusted development networks`,
    );
  }
  return url;
}

function isLoopbackHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
}

function rejectSensitiveProperties(params: HostedLoginURLParams): void {
  for (const key of Object.keys(params as unknown as Record<string, unknown>)) {
    if (isSensitiveName(key)) {
      throw new TypeError(`${key} must never be included in a hosted-login URL`);
    }
  }
}

function rejectSensitiveQuery(url: URL, name: string): void {
  for (const key of url.searchParams.keys()) {
    if (isSensitiveName(key)) {
      throw new TypeError(`${name} must not contain ${key}`);
    }
  }
}

function isSensitiveName(name: string): boolean {
  return sensitiveParameterNames.has(name.replace(/[-_]/g, "").toLowerCase());
}

function assertLiteral<T extends string>(actual: string, expected: T, name: string): asserts actual is T {
  if (actual !== expected) throw new TypeError(`${name} must be ${expected}`);
}

function assertNonEmpty(value: string, name: string): void {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${name} is required`);
  }
}

function assertS256Challenge(value: string): void {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new TypeError("codeChallenge must be a 43-character base64url SHA-256 challenge");
  }
}

function validateSpaceDelimited(values: readonly string[], name: string): string {
  if (!Array.isArray(values) || values.length === 0) {
    throw new TypeError(`${name} must contain at least one value`);
  }
  for (const value of values) {
    if (typeof value !== "string" || value === "" || /\s/.test(value)) {
      throw new TypeError(`${name} values must be non-empty and must not contain whitespace`);
    }
  }
  return values.join(" ");
}

function optionalSpaceDelimited(
  value: string | readonly string[] | undefined,
  name: string,
): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value === "string") {
    assertNonEmpty(value, name);
    return value;
  }
  return validateSpaceDelimited(value, name);
}

function setOptional(url: URL, name: string, value: string | undefined): void {
  if (value !== undefined && value !== "") url.searchParams.set(name, value);
}

function setMaxAge(url: URL, maxAge: number | undefined): void {
  if (maxAge === undefined) return;
  if (!Number.isSafeInteger(maxAge) || maxAge < 0) {
    throw new TypeError("maxAge must be a non-negative safe integer");
  }
  url.searchParams.set("max_age", String(maxAge));
}

function setResources(url: URL, resources: readonly string[] | undefined): void {
  if (resources === undefined) return;
  url.searchParams.delete("resource");
  for (const resource of resources) {
    assertNonEmpty(resource, "resource");
    url.searchParams.append("resource", resource);
  }
}

function encodeJSONParameter(
  value: string | readonly unknown[] | Readonly<Record<string, unknown>> | undefined,
): string | undefined {
  if (value === undefined || typeof value === "string") return value;
  return JSON.stringify(value);
}
