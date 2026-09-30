# Snaplink Swift SDK (experimental, 0.3.0)

The package name follows the naming scheme in [`../README.md`](../README.md).
SwiftPM has no namespace slot, so the brand and the product share one PascalCase
module name: `SnaplinkSSO` is the Apple-idiomatic rendering of `snaplink` + `sso`,
and it does not stutter against the `SnaplinkAuthClient` type inside it.

This Swift Package implements native public-client hosted login using
Authorization Code + PKCE S256, one-use state and issuer validation, Keychain
token storage, serialized refresh, and token revocation. It uses
`ASWebAuthenticationSession` and Keychain; no WebView or client secret is
involved. This package is under development, not published, and not approved
for production use.

The package is an identity SDK, not a generated Snaplink REST client. Use the
service's OpenAPI-generated client for business APIs. Server-side authorization,
permissions, and tenant boundaries remain authoritative.

## Requirements

- iOS 17+ / iPadOS 17+ or macOS 14+
- Swift 5.9+
- A public Snaplink OAuth client with a pre-registered callback URI

Registered custom-URI callbacks work at the package deployment minimums.
`ASWebAuthenticationSession`'s host/path-bound HTTPS callback API requires
iOS 17.4 or macOS 14.4; on older supported systems the SDK rejects HTTPS
callbacks and applications must use a registered custom URI scheme. The
minimum versions are initial SDK decisions and should be reviewed against the
SVERP device-support matrix before distribution.

## Add the package

The SwiftPM manifest is at the repository root and points to this SDK's source
and tests under `sdks/swift/`. In Xcode, add the repository root as a local
Swift Package and select the `SnaplinkSSO` product. Once a release is approved,
Git-based SwiftPM dependencies use a plain SemVer tag (for example, `0.3.0`);
custom monorepo tags such as `sdk-swift-v0.3.0` are not the version selector.
This package remains experimental and unpublished.

```swift
import SnaplinkSSO

let configuration = try SnaplinkConfiguration(
    issuerBaseURL: URL(string: "https://sso.example.com")!,
    clientID: "sverp-ios",
    redirectURI: URL(string: "https://app.example.com/oauth/callback")!,
    loginPageURL: URL(string: "https://login.example.com/login/"),
    scopes: ["openid", "profile", "email"],
    resources: ["https://api.example.com"],
    prompt: "login",
    loginHint: "operator@example.com",
    acrValues: "urn:example:mfa",
    uiLocales: "en-US zh-CN",
    maxAge: 0 // seconds
)
let snaplink = SnaplinkAuthClient(configuration: configuration)
let browser = SnaplinkSystemBrowser()
```

The UI owner supplies a presentation context. With an HTTPS callback, configure
the matching Associated Domain entitlement and serve the Apple App Site
Association file. Register the exact same callback at Snaplink:

```swift
let authorizationURL = try await snaplink.beginAuthorization()
let callbackURL = try await browser.authorize(
    url: authorizationURL,
    redirectURI: configuration.redirectURI,
    presentationContextProvider: self
)
let session = try await snaplink.handleAuthorizationCallback(callbackURL)
let accessToken = session.accessToken
```

`SnaplinkSystemBrowser` allows one active authorization at a time. If the host
UI abandons login, call `cancelAuthorization()` on the main actor; the pending
`authorize` call then fails with `authorization_cancelled`. Cancelling the Swift
`Task` awaiting `authorize` also cancels the browser session and throws
`CancellationError`.

A custom-scheme callback uses the same flow; register the scheme in the app's
URL Types and at Snaplink. Never treat callback parameters as credentials by
themselves: the SDK validates the saved state, exact redirect target, and
Snaplink `iss` before exchanging the code.

The authorization options `prompt`, `loginHint`, `acrValues`, `uiLocales`, and
non-negative `maxAge` map to the corresponding Go SDK `LoginOptions` fields.
They are omitted by default, and stale copies in `loginPageURL` are removed.
`accessToken()` returns a non-expired bearer and refreshes when needed;
`currentSession()` restores the persisted session and returns its updated
expiration after any required refresh. Tokens are proactively refreshed up to
60 seconds early, capped at 10% of the token lifetime for short-lived tokens.
Refresh requests are single-flight inside one SDK actor instance; they are not
coordinated across app processes or devices. `clear()` removes local Keychain
tokens and pending login state without a network call. `logout()` is distinct:
it clears local credentials before attempting server revocation, so a network
failure cannot leave the local session active.

## Paid products and entitlements

A paid or invited product is prepared before the redirect, and the pending
ticket is claimed automatically by the next successful callback:

```swift
try await snaplink.setup(SnaplinkSetupOptions(
    productID: "pro",
    licenseKey: "license-from-your-checkout" // or invitationCode:
))

let authorizationURL = try await snaplink.beginAuthorization()
// ... browser round trip ...
_ = try await snaplink.handleAuthorizationCallback(callbackURL)

let account = try await snaplink.accountContext(productID: "pro")
```

The credential is sent only in the HTTPS JSON body of the activation request.
The SDK stores just the opaque, short-lived ticket, and the callback claims it
with the bearer, so a license key never reaches a URL, OAuth `state`, or
Keychain. `setup` requires exactly one of `licenseKey` or `invitationCode`.

Test the three-state classification rather than the presence of the
`entitlement` field: a subscription whose window has closed is still returned by
the server and grants nothing.

```swift
if let entitlement = account.entitlement {
    switch entitlement.state(at: Date()) {
    case .active: entitlement.has(.scim, at: Date())
    case .inactive: /* reason is for display only */
    case .notActivated: /* prompt for a license key */
    }
}
// entitlement.unknownFeatures reports keys this build cannot yet gate
```

`accountContext.licenseState(at:)` is the single switch: it reports
`.notActivated` when the context carries no entitlement, so an absent binding
and a lapsed one are both reachable without inspecting `nil` first.

`SnaplinkFeature` and `SnaplinkLimit` are typed constants mirroring the server's
commerce vocabulary, so no call site compares a raw string. The server remains
the authority on every authorization decision; entitlement data exists for user
experience only.

## Transport seam

Every request is built as a normalized `SnaplinkHTTPRequest` by
`SnaplinkRequestBuilder`, which is a pure function of its inputs and performs no
I/O. Header names are canonicalized and case-insensitive, form bodies use
deterministic key ordering, JSON bodies are UTF-8 with no trailing newline, and
credential endpoints always carry `Cache-Control: no-store`. Endpoint
construction is testable without a transport:

```swift
let request = try SnaplinkRequestBuilder.credentialForm(
    baseURL: configuration.issuerBaseURL,
    path: "token",
    fields: ["grant_type": "client_credentials", "client_id": "my-client"]
)
request.canonical          // byte-comparable across SDKs
request.redactedDescription // safe to log: Authorization and credential fields redacted
```

`redactedDescription` never echoes an `Authorization`, `DPoP`, or cookie header
nor a credential form field (`code`, `code_verifier`, `refresh_token`,
`client_secret`, `license_key`, `invitation_code`, `activation_ticket`), so a
request can be logged without leaking a secret. Timeouts, redirect refusal, and
the response size cap live in the transport, not the session layer, so both are
substitutable in one place.

## Error taxonomy

Every SDK failure classifies the same way, so auth, commerce, and license errors
share one `catch`:

```swift
do {
    _ = try await snaplink.accountContext(productID: "pro")
} catch let error as any SnaplinkClassifiedError {
    switch error.classification.errorClass {
    case .activation, .commerce:
        // surface the activation prompt
    case .oauth, .authentication, .authorization:
        // authentication or permission problem
    case .license:
        // local entitlement-file verification failed
    case .sdk:
        // device, storage, or transport problem
    }
    // error.classification.code is the server's code verbatim
    // error.classification.recovery is terminal / retryWithBackoff /
    //   reauthenticate / recreateCeremony / fixRequest
}
```

A code the server sends that this build does not recognise is still surfaced
verbatim; it simply carries no known class. A description is never parsed for
behaviour, and a local license failure is never remapped onto a network error.

## Presentation preferences

The self-service preferences API is a default-deny projection: only `locale`,
`zoneinfo`, and the application-neutral `theme_mode` (plus its legacy
`sverp:theme_mode` alias) are readable or writable.

```swift
let stored = try await snaplink.presentationPreferences()

try await snaplink.updatePresentationPreferences(
    SnaplinkPresentationPreferencesPatch(locale: "zh-CN", themeMode: .dark)
)
```

An empty `locale` in a patch deletes that stored value. The wire keys stay
inside the SDK: the response's legacy alias is resolved for you, and a response
whose two theme aliases disagree is refused rather than resolved by precedence,
so a stale alias in the profile is visible instead of silently overridden.

A handoff carries presentation hints into hosted login. The server persists
them as the authenticated user's preference only after a successful
authentication, so they are not an authorization or tenant parameter:

```swift
let handoff = try SnaplinkPresentationPreferencesCodec.buildLoginHandoff(
    SnaplinkPresentationPreferencesPatch(locale: "zh-CN", themeMode: .dark)
)
// handoff: ["presentation_locale": "zh-CN", "presentation_theme_mode": "dark"]
```

Only explicitly set, non-empty values are included, so a handoff never clears a
preference the application did not mean to touch.

## Offline licensing

A private or air-gapped deployment gates paid features from a signed file
instead of the account-context route, so authentication never calls a vendor
licensing service on a login path. Verification is entirely local and performs
no network I/O on any path.

```swift
let trust = try SnaplinkLicenseTrust.fromKey(
    id: "vendor-2026",
    base64Encoded: pinnedPublicKey
)
let file = try SnaplinkLicenseFileVerifier.verify(
    try Data(contentsOf: licenseURL),
    trust: trust
)

if file.entitlement.has(.scim, at: Date()) {
    // enable the paid feature
}
```

Supply the public key through `SnaplinkLicenseTrust`; that is what makes OEM and
private-CA deployments possible. A file names the `key_id` it was signed with, so
a deployment can trust a current and a next key during rotation. Only Ed25519
envelope version 1 is accepted, and the declared algorithm is checked before any
signature work, so `none` is refused rather than tolerated. A verification
failure throws `SnaplinkLicenseError` and is never downgraded to an active or
free-tier entitlement; `file.state(at:)` reuses the same three-state
classification as the online path.

This package ships no vendor trust root. A release populates one from the real
key rather than carrying a placeholder that would read as vendor authority while
verifying nothing. The signing private key never enters this package, the
repository, or CI; only the payload and its signature are transmitted.

## Security boundary

- Tokens and PKCE transactions are stored in Keychain with
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; storage failures fail closed.
- The token `URLSession` is ephemeral, has no cookie storage, disables cookies,
  and rejects HTTP redirects. Browser cookies are never read or sent to the API;
  the authorization code is redeemed with its PKCE verifier.
- HTTPS is mandatory except explicit loopback HTTP for development. Never enable
  that option in a release build.
- The SDK does not expose or persist an ID token, accept a client secret, collect
  passwords, use the implicit flow, or connect to databases/ERP systems.
- Activation requests and the bearer read of the account context are no-store
  and cookie-free, and a redirect is refused rather than followed, so a
  credential or token cannot be replayed onto a host the SDK did not choose.
- A license key or invitation code is never persisted; only the short-lived
  activation ticket is, and it is deleted once it is claimed or found expired.
- Offline license verification is local and network-free, accepts only Ed25519
  envelope version 1, and never downgrades a failed verification to a free or
  active entitlement.
- DPoP, account/tenant selection, and the full generated REST surface are not
  included in this initial package. Add them only against approved server
  contracts and security review.

## Verify

Run these commands from the Snaplink repository root:

```bash
swift test
swift build -c release
```

The tests cover PKCE generation, callback state/issuer binding, token exchange,
concurrent refresh, local clear/logout cleanup, configuration validation,
browser-session cancellation, activation/entitlement handling, the account
context routes, presentation preferences, and all four shared cross-language
contracts in `ops/build/sdk-conformance/`: transport seam, entitlement semantics,
the error taxonomy, and offline license-file verification. Browser UI and device
Keychain integration still require Apple platform acceptance.
