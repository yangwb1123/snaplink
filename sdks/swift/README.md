# Snaplink Swift SDK (experimental, 0.3.0)

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

The current minimum OS version enables `ASWebAuthenticationSession` HTTPS
Universal Link callbacks. An application may instead register a unique custom
URI scheme. The minimum version is an initial SDK decision and should be
reviewed against the SVERP device-support matrix before distribution.

## Add the package

In Xcode, add this repository as a local Swift Package and select the
`SnaplinkSSO` product. For a published release, use the package URL and an
approved version tag.

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

A custom-scheme callback uses the same flow; register the scheme in the app's
URL Types and at Snaplink. Never treat callback parameters as credentials by
themselves: the SDK validates the saved state, exact redirect target, and
Snaplink `iss` before exchanging the code.

The authorization options `prompt`, `loginHint`, `acrValues`, `uiLocales`, and
non-negative `maxAge` map to the corresponding Go SDK `LoginOptions` fields.
They are omitted by default, and stale copies in `loginPageURL` are removed.
`accessToken()` returns a non-expired bearer and refreshes when needed. Refresh
requests are single-flight inside one SDK actor instance; they are not
coordinated across app processes or devices. `logout()` clears local Keychain
credentials before attempting server revocation, so a network failure cannot
leave the local session active.

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
- DPoP, account/tenant selection, and the full generated REST surface are not
  included in this initial package. Add them only against approved server
  contracts and security review.

## Verify

```bash
swift test
swift build -c release
```

The tests cover PKCE generation, callback state/issuer binding, token exchange,
concurrent refresh, logout cleanup, and configuration validation. Browser UI
and device Keychain integration still require Apple platform acceptance.
