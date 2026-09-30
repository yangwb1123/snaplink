# Native SDK packages

The first native packages are experimental identity clients in the repository:

- [Android/Kotlin](../../sdks/kotlin/README.md) — AndroidX Custom Tabs,
  Android Keystore AES-GCM storage, hosted login, PKCE, refresh and revoke.
- [iOS/Swift](../../sdks/swift/README.md) — `ASWebAuthenticationSession`,
  Keychain storage, hosted login, PKCE, refresh and revoke.

They are **native hosted-login SDKs**, not full generated REST clients. Native
applications must use the corresponding backend's OpenAPI-generated client for
business API calls. API permissions and tenant/company boundaries remain
server-side.

Their shared authorization configuration follows the Go SDK's `LoginOptions`
for scopes, resources, `prompt`, `max_age`, `login_hint`, `acr_values`, and
`ui_locales`. Server-flow orchestration options such as `ReturnTo` and `Setup`
are intentionally not native login options; the host application owns its
post-login navigation. Both SDKs parse callback query values using form-style
`+`/percent decoding, reject duplicate OAuth response fields, and bound
callback error codes/descriptions to 64/512 characters before exposing them.
Both SDKs expose distinct `clear()` and `logout()` operations: `clear()` drops
local credentials only; `logout()` also requests server revocation. Both token
transports use form-encoded requests, reject redirects, send no cookies, apply a
15-second request/resource timeout, and cap response bodies at
64 KiB. Malformed or blank OAuth error fields are ignored independently; a
missing/invalid code falls back to `http_error`, and a missing/invalid
description falls back to an HTTP-status message. Omitted refresh scope/token
fields retain the previous values.

These packages currently target Android API 23+ / iOS 17+; the Swift package
also builds for macOS 14+. They are not published or production-approved. The
iOS minimum exists to support verified HTTPS callbacks with
`ASWebAuthenticationSession`; confirm it against the approved device-support
matrix before release. Callback URIs and OAuth client IDs must
be registered before application integration. Production use additionally
requires platform-device acceptance, independent identity/security review, and
the SVERP production release gate. This package work does not authorize a SVERP
release, native-client rollout, or PostgreSQL cutover.

Scope intentionally excludes DPoP, app-specific account selection, and generated
business API clients until their contracts and platform behavior are approved.
The SDK uses Authorization Code + PKCE; it never turns a browser cookie or
session ID into a native credential.
