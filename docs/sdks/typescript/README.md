# snaplink/sso — TypeScript SDK

> **Scope:** generated client for the full documented API surface of
> `docs/openapi.yaml`, plus browser hosted-login orchestration. It is
> publishable to npm as `@snaplink/sso-client` and does not ship a login page,
> self-service portal, setup UI, developer portal, or admin console.
> `sso-server` is a pure API backend; those browser experiences are separate
> frontend projects.

`client.ts` is **generated output**, committed the same way generated Go under
`gen/proto/` is: checked in for consumers to use directly, regenerated from
`docs/openapi.yaml` by a Go program rather than hand-maintained.
`hosted-login.ts` is the small hand-written browser-navigation companion and
`browser-login.ts` is the public-client PKCE facade; both are exported through
`index.ts` and are not overwritten by API generation.

The directory is a valid npm package (`@snaplink/sso-client`) and can be
consumed from a checked-out Snaplink repository with a `file:` dependency.

```
go run ./cmd/gensdk --lang=ts
```

Regenerate after any change to `docs/openapi.yaml` or
`ops/build/sdk-surface.json` (run `python cli.py sdk-surface generate`, which
re-emits every language). The generator is a plain Go program (`cmd/gensdk`)
that parses the YAML spec (via the `goccy/go-yaml` dependency already in
`go.mod`) and writes a plain `.ts` file. The package's npm build and browser
tests run in `.github/workflows/sdk-ci.yml`; the protected npm publish path is
`.github/workflows/sdk-typescript.yml`. The root `make ci` remains Go/API
focused and does not install the Node toolchain.

The generator reads `docs/openapi.yaml`; it does not discover Go route
registration. A runtime endpoint missing from OpenAPI cannot appear in this
client, so route inventory and OpenAPI validation must be reconciled before
claiming complete API coverage.

## What's covered

The **complete** registered operation set of `docs/openapi.yaml` has a
generated method, grouped by tag: discovery,
OAuth 2.0/OIDC auth + token lifecycle, self-service (`/me*`), the full
admin control plane, SCIM, CAEP/SSF, OpenID Federation, FGA/ReBAC,
WebAuthn, mesh and operational endpoints. The operationId set is declared
once in `ops/build/sdk-surface.json` (grouped, capability-linked,
validated against `docs/openapi.yaml` + `ops/build/capabilities.json` by
`python cli.py sdk-surface check`) — the generator carries no allowlist of
its own, so the two language clients cannot drift apart in scope.

Every generated method name is the operation's `operationId` **verbatim**
(e.g. `client.postToken(...)`, `client.getUserInfo()`) — no derived/shortened
aliasing — so a call site is grep-able straight back to its
`docs/openapi.yaml` operation. The generated client's method exceptions are
`login()`/`logout()` (plus the `isLoggedIn`/`accessToken` getters): hand-written
convenience wrappers around `postLogin`/`postLogout`, not generated from an
operationId. The default browser facade is also exported as `snaplink` — see
Usage below.

## Known simplifications in the generator

(`cmd/gensdk/schema.go` + `gen_ts.go` — see their doc comments for detail.)

- **Field order is alphabetical**, not the YAML's authored order — the
  YAML decoder used here (`goccy/go-yaml` decoding into `any`) loses
  Go-map ordering, so alphabetical is the deterministic substitute:
  regenerating twice yields byte-identical output.
- **`allOf` only resolves a single-entry list** (the one shape
  `docs/openapi.yaml` actually uses); a multi-entry `allOf` falls back to
  `unknown` rather than attempting a schema merge.
- **`oneOf`/`anyOf`** become a TypeScript union of the resolved variants
  (e.g. `IntrospectResponse.aud: string | string[]`, or a whole
  operation's response type like
  `Promise<LoginResponse | AuthorizationCodeResponse |
  LoginDiscoveryResponse | MFARequiredResponse>`).
- An operation's **form-urlencoded content type is modeled as the
  preferred wire for the OAuth credential family**: the seven
  credential-endpoint operations (`postToken`, `postIntrospect`,
  `postRevoke`, `postPAR`, `postDeviceCode`, `postDeviceVerify`,
  `postMFAComplete`) send `application/x-www-form-urlencoded` bodies;
  every other operation keeps sending JSON. Form values follow the
  server binder's contract: booleans are lowercase `true`/`false`,
  string arrays (`resource`/`audience`/`tokens`) become repeated keys,
  objects and arrays of objects (`claims`, `authorization_details`)
  become a single key holding the JSON text (RFC 9396 §3 / OIDC Core
  §5.5), and `MFACompleteRequest.params` has no form encoding — the
  client rejects it with an `invalid_request` error rather than
  sending it (use the flat `code`/`assertion` fields instead).

## Usage

### One-call browser login without a BFF

For a browser SPA, import the default `snaplink` facade and call the same
login code on every application boot. The first call generates state and
PKCE, then navigates to the existing Console hosted page at `/login/`. After
the Console redirects back, the same call validates the callback, exchanges
the code, and keeps the access token in memory:

```ts
import snaplink from "@snaplink/sso-client";

const session = await snaplink.login({
  baseUrl: "https://sso.example.com",
  clientId: "my-public-spa",
  loginPageUrl: "https://sso.example.com/login/",
  redirectUri: `${location.origin}/auth/callback`,
  returnTo: location.href,
  scope: ["openid", "profile", "email"],
});

const me = await snaplink.api.getUserInfo();
```

For a paid product, prepare activation before the redirect. The SDK sends the
license key only in the HTTPS request body, stores only the short-lived ticket
in `sessionStorage`, and claims it automatically after the code exchange:

```ts
await snaplink.setup({
  baseUrl: "https://sso.example.com",
  clientId: "my-public-spa",
  productId: "pro",
  licenseKey: "license-from-your-checkout",
});

await snaplink.login({
  baseUrl: "https://sso.example.com",
  clientId: "my-public-spa",
  redirectUri: `${location.origin}/auth/callback`,
});

const account = await snaplink.getAccountContext();
```

The equivalent one-call form is `login({ ..., setup: { productId,
licenseKey } })`. Use `invitationCode` instead of `licenseKey` for an
invitation. Do not put either credential in a URL, OAuth `state`, or browser
local storage; the server resolves the tenant and returns the authoritative
entitlement and limits.

The application must register `redirectUri` on a public OAuth client and must
allow the SPA origin through the server's CORS policy. Do not configure a
client secret: this flow is Authorization Code + PKCE for a public client.
`returnTo` is constrained to the current origin. When it points to a separate
route, the SDK uses a one-time `sessionStorage` handoff to return there; the
access token is then held in memory and is not written to `localStorage`.
The authorization transaction expires after ten minutes by default.

### Hosted login: redirect without collecting credentials in the RP

For an application that must use a separately deployed Snaplink login page,
generate state plus an RFC 7636 verifier/challenge in the trusted RP/BFF,
persist the state and verifier, then redirect the browser to the URL returned
by `buildHostedLoginURL`. The verifier and confidential client secret stay in
the BFF and are never accepted by the URL helper.

```ts
import { buildHostedLoginURL } from "@snaplink/sso-client";

const location = buildHostedLoginURL({
  loginPageUrl: "https://sso.example.com/login/",
  clientId: "my-app",
  redirectUri: "https://app.example.com/api/auth/callback",
  responseType: "code",
  scope: ["openid", "profile", "email"],
  state: persistedState,
  codeChallenge: sha256Base64URL(persistedVerifier),
  codeChallengeMethod: "S256",
  nonce: persistedNonce,
});

return Response.redirect(location, 302);
```

The login page calls `postLogin` / `postMFAComplete` from this SDK and returns
the resulting authorization code to `redirectUri`. The BFF validates `state`
and `iss`, then exchanges the code with `postToken` using the original verifier.

Both login-page and callback URLs must use HTTPS. Loopback HTTP is accepted for
local development. A trusted LAN can opt in explicitly with
`allowInsecureHttpForDevelopment: true`; this must never be enabled in a
production configuration. Existing query parameters such as a theme selector
are preserved, while OAuth parameters are set from the validated arguments.
The helper rejects URL fragments, embedded credentials, `client_secret`,
`code_verifier`, PKCE downgrade to `plain`, and non-code response types.

### Simplest integration: direct password login, no redirect

For a frontend that owns its own login form and just wants tokens back —
set `clientId` once, call `login(username, password)`:

```ts
import { SSOClient } from "@snaplink/sso-client";

const client = new SSOClient({ baseUrl: "https://sso.example.com", clientId: "my-app" });

const auth = await client.login(username, password);
if (!client.isLoggedIn) {
  // auth is a MFARequiredResponse (auth.error === "mfa_required") — no token
  // yet; complete the second leg via postMFAComplete(...) before proceeding.
} else {
  const me = await client.getUserInfo(); // access token auto-attached
}

await client.logout();
```

### Authorization-code exchange + manual token storage

```ts
import { SSOClient, SSOError } from "@snaplink/sso-client";

let accessToken: string | undefined;
const clientSecret = process.env.SNAPLINK_CLIENT_SECRET;
if (!clientSecret) throw new Error("SNAPLINK_CLIENT_SECRET is required");

const client = new SSOClient({
  baseUrl: "https://sso.example.com",
  clientId: "my-confidential-app",
  clientSecret,
  requestTimeoutMs: 15_000,
  getAccessToken: () => accessToken,
});

const tokens = await client.postToken({
  grant_type: "authorization_code",
  code: "ac_...",
  code_verifier: "the-original-pkce-verifier",
  redirect_uri: "https://app.example.com/cb",
});
accessToken = tokens.access_token;

try {
  const me = await client.getUserInfo();
  console.log(me.email);
} catch (err) {
  if (err instanceof SSOError) {
    console.error(err.status, err.error, err.errorDescription);
  }
}
```

`clientSecret` is for trusted server/BFF runtimes only. The SDK sends it with
HTTP Basic for token, revocation, introspection, and PAR calls; never bundle a
confidential client secret into browser code.

`SSOClientOptions.fetch` lets you inject a non-global `fetch`
implementation (tests, older Node). Any method whose operation requires a
bearer (`security: [bearerAuth]` in the spec) calls `getAccessToken()`
first and sends `Authorization: Bearer <token>` when it returns one — the
`login()` path above supplies this automatically without any wiring.
