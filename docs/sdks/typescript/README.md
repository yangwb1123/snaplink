# snaplink/sso — TypeScript client (generated)

> **Scope:** convenience client for a curated OpenAPI subset. It is not a
> complete SDK for every runtime route, is not published to the public npm
> registry, and does not ship a
> login page, self-service portal, setup UI, developer portal, or admin console.
> `sso-server` is a pure API backend; those browser experiences are separate
> frontend projects.

`client.ts` is **generated output**, committed the same way generated Go under
`gen/proto/` is: checked in for consumers to use directly, regenerated from
`docs/openapi.yaml` by a Go program rather than hand-maintained.

The directory is a valid npm package (`@snaplink/sso-client`) and can be
consumed from a checked-out Snaplink repository with a `file:` dependency.

```
go run ./cmd/gensdk --lang=ts
```

Regenerate after any change to `docs/openapi.yaml` that touches an operation
listed below. There is no Node.js/npm build step in this repo — the
generator is a plain Go program (`cmd/gensdk`) that parses the YAML spec
(via the `goccy/go-yaml` dependency already in `go.mod`) and writes a
plain `.ts` file; nothing here runs `npm install` or `tsc` as part of
`make ci` or any other repo build target.

The generator reads `docs/openapi.yaml`; it does not discover Go route
registration. A runtime endpoint missing from OpenAPI cannot appear in this
client, so route inventory and OpenAPI validation must be reconciled before
claiming complete API coverage.

## What's covered

A curated, hand-scoped **subset** of `docs/openapi.yaml` — not a full
mirror of the more than 250 operations the spec currently documents. The full
allowlist lives
as `coreSurface` in `cmd/gensdk/operations.go`:

- **Discovery**: JWKS, OpenID Connect discovery document, OAuth
  Authorization Server Metadata.
- **Core OAuth 2.0 / OIDC**: `/auth/login`, `/auth/mfa`, `/auth/send-code`,
  the full `/token` family (token, introspect, revoke, revoke-all), PAR,
  device flow (code + verify), Dynamic Client Registration (register +
  the RFC 7592 get/put/delete self-management trio), `/logout`,
  `/userinfo`.
- **Self-service** (`/me*`): account overview + profile update, password
  change, MFA factor listing, session listing/bulk-revoke, consent
  listing, permissions/roles/menu-tree.
- **A small representative admin sample**: client lookup by id, the
  runtime endpoint inventory, local-user listing, per-client role listing,
  and the audit-event query API — enough to
  demonstrate the pattern, NOT the full admin
  grpc-gateway-generated admin CRUD surface (clients/users/tenants/
  domains/releases/snapshots/tokens/policies/...), nor SCIM, CAEP/SSF,
  OpenID Federation, webhooks, or compliance export/erase. Widening
  `coreSurface` to cover more of that surface is mechanical — the
  parser/resolver already walks the whole spec — but was left out of this
  pass to keep the generator (and this README's promise about what it
  covers) honest and reviewable in one sitting.

Every generated method name is the operation's `operationId` **verbatim**
(e.g. `client.postToken(...)`, `client.getUserInfo()`) — no derived/shortened
aliasing — so a call site is grep-able straight back to its
`docs/openapi.yaml` operation. The one exception is `login()`/`logout()`
(plus the `isLoggedIn`/`accessToken` getters): hand-written convenience
wrappers around `postLogin`/`postLogout`, not generated from an operationId —
see Usage below.

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
- An operation's **form-urlencoded content type is not separately
  modeled** — every curated operation that accepts
  `application/x-www-form-urlencoded` also accepts `application/json`
  with an identical schema, and the client always sends JSON.

## Usage

### Simplest integration: direct password login, no redirect

For a frontend that owns its own login form and just wants tokens back —
set `clientId` once, call `login(username, password)`:

```ts
import { SSOClient } from "./client";

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
import { SSOClient, SSOError } from "./client";

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
