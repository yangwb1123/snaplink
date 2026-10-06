# Snaplink Android SDK (experimental, 0.3.0)

The published coordinate follows the naming scheme in
[`../README.md`](../README.md): the Gradle project is `:snaplink`, so the Maven
coordinate is `cn.ywbsd.sso:snaplink`. Maven Central verifies a `groupId`
against a domain the publisher controls, so the group is the reverse-DNS form of
the product host `sso.ywbsd.cn` and the brand sits in the artifactId; a
`com.snaplink` group would assert a domain this project does not own. Before the
first release that host must serve Central's verification token (or publish the
matching `token` TXT record) and keep resolving. The Android namespace
(`com.snaplink.sso`) is the code package, not the published artifact name, and
is not domain-verified. Maven publishing stays unconfigured.

This Android library provides the public-client hosted-login vertical slice:
Authorization Code + PKCE S256, state and issuer validation, encrypted token
storage, serialized refresh, and RFC 7009 revocation. It uses the system browser
through AndroidX Custom Tabs, never a WebView or an app client secret. This is
an SDK package under development; it is not yet published or approved for
production use.

The package is intentionally an identity SDK, not a generated Snaplink REST
client. Applications should use their service's OpenAPI-generated client for
business APIs. Native login does not change server-side authorization,
tenant isolation, or client permissions.

## Requirements

- Android API 23 or newer
- JDK 21 (the version used by the Android SDK CI)
- Gradle 8.13
- **Core library desugaring enabled in the consuming app.** The package targets
  API 23 but uses `java.time` and `java.util.Base64`, which the platform only
  provides from API 26. The AAR records this requirement, so the app that
  depends on it must enable desugaring too:

  ```kotlin
  compileOptions {
      isCoreLibraryDesugaringEnabled = true
  }
  dependencies {
      coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")
  }
  ```

  That is the deliberate trade for keeping `minSdk` at 23; the alternative is
  raising `minSdk` to 26 and dropping every device below it. An app that already
  requires API 26 or newer can set `minSdk = 26` instead and ignore this.

## Add the SDK

```kotlin
dependencies {
    implementation(project(":snaplink")) // local checkout / included build
}
```

Configure a public OAuth client with a pre-registered callback. Do not ship a
client secret in an Android application:

```kotlin
import java.net.URI

val configuration = SnaplinkConfiguration(
    issuerBaseUrl = "https://sso.example.com",
    loginPageUrl = "https://login.example.com/login/", // may be omitted
    clientId = "sverp-android",
    redirectUri = "com.example.sverp:/oauth/callback",
    scopes = listOf("openid", "profile", "email"),
    resources = listOf("https://api.example.com"),
    // Optional OAuth authorization parameters; maxAge is in seconds.
    prompt = "login",
    loginHint = "operator@example.com",
    acrValues = "urn:example:mfa",
    uiLocales = "en-US zh-CN",
    maxAge = 0,
)
val snaplink = SnaplinkAuthClient(applicationContext, configuration)
```

Register the exact callback with Snaplink and Android. Prefer a verified HTTPS
App Link when the application has an associated domain; a private-use scheme is
shown here only as a compact example:

```xml
<activity
    android:name=".AuthCallbackActivity"
    android:exported="true"
    android:launchMode="singleTop">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="com.example.sverp" android:path="/oauth/callback" />
    </intent-filter>
</activity>
```

Start the system-browser flow from the login button's Activity. The callback is
delivered later to the registered callback Activity; handle both initial intent
delivery and `onNewIntent` when using `singleTop`:

```kotlin
import androidx.lifecycle.lifecycleScope

// Login button handler:
lifecycleScope.launch { snaplink.authorize(this@LoginActivity) }

// Callback Activity / deep-link router, after receiving the redirect intent:
val callback = intent.data ?: return
lifecycleScope.launch {
    val session = snaplink.handleAuthorizationCallback(URI(callback.toString()))
    // Keep accessToken in memory only as long as needed.
    val accessToken = session.accessToken
}
```

The authorization options `prompt`, `loginHint`, `acrValues`, `uiLocales`, and
non-negative `maxAge` map to the matching Go SDK `LoginOptions` fields. They are
omitted by default, and stale copies in `loginPageUrl` are removed. The token
endpoint runs on `Dispatchers.IO`. `accessToken()` returns a non-expired bearer
token and refreshes it when needed. Refresh calls are
serialized within one SDK instance; this is not a cross-process or cross-device
lock. `clear()` removes local tokens and pending login state without a network
call. `logout()` is distinct: it attempts server revocation and clears local
credentials even if the network call fails. `isLoggedIn()` answers whether a
usable session is held right now; it is a point-in-time local read that never
issues a request, never writes, and never refreshes, so a token at or inside the
refresh skew reads as signed out and a storage failure raises
`secure_storage_error` rather than answering false. Use `currentSession()` when
you want the client to renew a nearly expired token instead.

## Commercial entitlements

A paid or invited product is prepared before the redirect, and the pending
ticket is claimed automatically by the next successful callback:

```kotlin
client.setup(SnaplinkSetupOptions(productId = "pro", licenseKey = "license-from-your-checkout"))

val authorization = client.beginAuthorization()
// ... Custom Tab round trip ...
client.handleAuthorizationCallback(callbackUri)

val account = client.accountContext("pro")
```

The credential is sent only in the HTTPS JSON body of the activation request.
The SDK stores just the opaque, short-lived ticket, and the callback claims it
with the bearer, so a license key never reaches a URL, OAuth `state`, or
encrypted storage. `setup` requires exactly one of `licenseKey` or
`invitationCode`.

`SnaplinkEntitlement`, `SnaplinkFeature`, and `SnaplinkLimit` mirror the
server's commerce vocabulary, and the three-state classification is the same one
the online path uses:

```kotlin
val state = account.licenseStateAt(Instant.now())
when (state.kind) {
    SnaplinkLicenseStateKind.ACTIVE -> state.entitlement?.has(SnaplinkFeature.SCIM, Instant.now())
    SnaplinkLicenseStateKind.INACTIVE -> showExpired(state.reason) // presentation only
    SnaplinkLicenseStateKind.NOT_ACTIVATED -> promptForLicenseKey()
}
```

`licenseStateAt` reports `NOT_ACTIVATED` when the context carries no
entitlement, so an absent binding and a lapsed one are both reachable without
inspecting `null` first. An inactive entitlement grants nothing whatever its
stored feature map says, and `unknownFeatures` reports keys this build cannot
yet gate. The server remains the authority on every authorization decision.

## Presentation preferences

The self-service preferences API is a default-deny projection: only `locale`,
`zoneinfo`, and the application-neutral `theme_mode` (plus its legacy
`sverp:theme_mode` alias) are readable or writable.

```kotlin
val stored = client.presentationPreferences()
client.updatePresentationPreferences(
    SnaplinkPresentationPreferencesPatch(locale = "zh-CN", themeMode = SnaplinkThemeMode.DARK),
)
```

An empty `locale` in a patch deletes that stored value. The wire keys stay
inside the SDK: the legacy alias is resolved for you, and a response whose two
theme aliases disagree is refused rather than resolved by precedence.

A handoff carries presentation hints into hosted login; the server persists
them as the authenticated user's preference only after a successful
authentication, so they are not an authorization or tenant parameter:

```kotlin
val handoff = SnaplinkPresentationPreferencesCodec.buildLoginHandoff(
    SnaplinkPresentationPreferencesPatch(locale = "zh-CN", themeMode = SnaplinkThemeMode.DARK),
)
// presentation_locale=zh-CN, presentation_theme_mode=dark
```

## Offline licensing

A private or air-gapped deployment gates paid features from a signed file
instead of the account-context route, so authentication never calls a vendor
licensing service on a login path. Verification is local and network-free:

```kotlin
val trust = SnaplinkLicenseTrust.ofKey("vendor-2026", pinnedPublicKey)
val file = SnaplinkLicenseFileVerifier.verify(licenseJson, trust)
if (file.entitlement.has(SnaplinkFeature.SCIM, Instant.now())) {
    // enable the paid feature
}
```

Only Ed25519 envelope version 1 is accepted, and the declared algorithm is
checked before any signature work, so `none` is refused rather than tolerated. A
verification failure throws `SnaplinkLicenseException` and is never downgraded to
an active or free-tier entitlement.

**Platform requirement:** the Android platform only exposes Ed25519 through the
JCA from API 33. On an older device `SnaplinkLicenseFileVerifier.isSupported()`
returns false and verification fails closed with
`license_verifier_unavailable`; an unverifiable file is never treated as
verified. This package ships no vendor trust root, and the signing private key
never enters this package, the repository, or CI.

## Transport seam

Every request is built as a normalized `SnaplinkHttpRequest` by
`SnaplinkRequestFactory`, which is a pure function of its inputs and performs no
I/O. Header names are canonicalized and matched case-insensitively, form fields
use deterministic key ordering, JSON bodies are UTF-8 with no trailing newline,
and credential endpoints always carry `Cache-Control: no-store`. Endpoint
construction is testable without a transport:

```kotlin
val request = SnaplinkRequestFactory.credentialForm(
    baseURL = configuration.issuerBaseUrl,
    path = "token",
    fields = mapOf("grant_type" to "client_credentials", "client_id" to "my-client"),
)
request.canonical()           // byte-comparable across SDKs
request.redactedDescription() // safe to log: Authorization and credentials redacted
```

`redactedDescription` never echoes an `Authorization`, `DPoP`, or cookie header
nor a credential form field (`code`, `code_verifier`, `refresh_token`,
`client_secret`, `license_key`, `invitation_code`, `activation_ticket`), so a
request can be logged without leaking a secret. Timeouts, redirect refusal, and
the response size cap live in the transport, not the client, so both are
substitutable in one place.

## Error taxonomy

Every SDK failure classifies the same way, so auth, commerce, and license errors
share one `catch`:

```kotlin
try {
    // ...
} catch (error: SnaplinkClassifiedError) {
    when (error.classification.errorClass) {
        SnaplinkErrorClass.ACTIVATION, SnaplinkErrorClass.COMMERCE -> promptForActivation()
        SnaplinkErrorClass.OAUTH,
        SnaplinkErrorClass.AUTHENTICATION,
        SnaplinkErrorClass.AUTHORIZATION -> signInAgain()
        SnaplinkErrorClass.LICENSE -> showLicenseProblem()
        SnaplinkErrorClass.SDK -> reportDeviceProblem()
    }
    // error.wireCode is the server's code verbatim
    // error.classification.recovery is TERMINAL / RETRY_WITH_BACKOFF /
    //   REAUTHENTICATE / RECREATE_CEREMONY / FIX_REQUEST
}
```

A code the server sends that this build does not recognise is still surfaced
verbatim; it simply carries no known class. A local license failure is never
remapped onto a network error.

## Storage

The token set, the one-use PKCE transaction, and a pending activation ticket live
in an app-private store. Every public constructor defaults to
`AndroidSecureStore`, which encrypts each record with AES-GCM under a
non-exportable Android Keystore key. An application that needs different storage
supplies its own `SnaplinkSecureStore`; nothing else about the client changes:

```kotlin
val client = SnaplinkAuthClient(SnaplinkMemorySecureStore(), configuration)
```

`SnaplinkMemorySecureStore` keeps records in heap with no confidentiality. It is
for unit tests, examples, and single-process development, not for a device build,
which is why the Keystore store stays the default. A custom store receives
opaque, versioned records and must store them verbatim without inspecting them.
It must raise `SnaplinkAuthException` with code `secure_storage_error` on a
storage failure rather than return an empty value, because the client cannot tell
a lost record from an absent one and would treat a fabricated answer as a live
session. Consuming the login transaction is a read followed by a delete inside the
SDK, so a store shared by several processes must make that effectively single-use.

## Security boundary

- Android Keystore AES-GCM encrypts both pending PKCE transactions and tokens;
  the key is non-exportable and records are authenticated with account-specific
  associated data. Keystore/storage errors fail closed.
- Authorization state, PKCE verifier, issuer (`iss`), and exact callback target
  are checked before code exchange. Transactions are short-lived and one-use.
- No WebView, password collection, browser-cookie extraction, client secret,
  direct database connection, or implicit-flow token is used.
- HTTP endpoints are rejected except explicit loopback HTTP in development.
  Do not enable that development path in a release build.
- `SnaplinkSession.accessToken` is a bearer credential: never log it, place it
  in an intent/query parameter, or persist it outside the SDK's secure store.
  A caller-injected `SnaplinkSecureStore` takes over that duty in full: an
  unencrypted store on a device leaks a refresh token.
- Activation and self-service requests carry `Cache-Control: no-store`, send no
  cookies, and refuse redirects, so a credential or a bearer cannot be replayed
  onto a host the SDK did not choose.
- A license key or invitation code is never persisted; only the short-lived
  activation ticket is, and it is deleted once claimed or found expired.
- Offline license verification is local and network-free, accepts only Ed25519
  envelope version 1, and never downgrades a failed verification to a free or
  active entitlement.
- DPoP, account/tenant selection, and the complete generated REST surface are
  not part of this initial package. Add them only against approved server
  contracts and security review.

## Verify

```bash
cd sdks
./gradlew :snaplink:testDebugUnitTest :snaplink:lintDebug :snaplink:assembleRelease
```

The Gradle workspace lives at `sdks/`. Kotlin package declarations remain
`com.snaplink.sso`; main, unit-test, and instrumentation sources are kept in
flat `kotlin/main`, `kotlin/test`, and `kotlin/androidTest` source roots to fit
the repository's directory-depth budget.

The Keystore instrumentation test needs a real emulator, so it is not part of
the per-push SDK job:

```bash
cd sdks
./gradlew :snaplink:connectedDebugAndroidTest   # requires a running emulator
```

It runs in `.github/workflows/android-instrumentation.yml`, which covers `main`
and can be dispatched on demand. The reason is infrastructure, not the SDK: an
emulator requires nested virtualization that shared runners do not reliably
provide, and the emulator action reports a failed boot as a bare adb connection
error from its teardown. That makes it a poor gate on every push while still
being a real signal when it runs.

The publication set is verified separately, without publishing anything:

```bash
cd sdks
./gradlew :snaplink:publishToMavenLocal
```

The unit suite covers PKCE construction, callback state/issuer binding, token
exchange, concurrent refresh, local clear/logout cleanup, the logged-in query's
no-network/no-write/fail-closed contract, the injectable store seam (record
isolation per configuration, a restart reading a persisted session, and storage
faults failing closed), configuration validation, activation and the account
context (both at the wire level through a real OkHttp stack and at the client
level), presentation preferences, and all four shared cross-language contracts in
`ops/build/sdk-conformance/`: transport seam, entitlement semantics, the error
taxonomy, and offline license-file verification. Keystore encryption is verified
separately on a device by the instrumentation suite in `kotlin/androidTest`.
