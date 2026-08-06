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
/**
 * Build the browser navigation target for a separately deployed Snaplink login UI.
 *
 * The function is intentionally a URL builder, not a fetch call: browser-based
 * authorization and federated IdP redirects must happen as top-level navigation.
 * It accepts neither a client secret nor a PKCE verifier, so those values cannot
 * be disclosed through the authorization URL.
 */
export declare function buildHostedLoginURL(params: HostedLoginURLParams): string;
