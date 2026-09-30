# Snaplink Android SDK (experimental, 0.3.0)

The published coordinate follows the naming scheme in
[`../README.md`](../README.md): the Gradle project is `:sso-client`, so the
Maven coordinate is `com.snaplink:sso-client` — the reverse-DNS group carries the
brand and the artifactId carries the capability. The Android namespace
(`com.snaplink.sso`) is the code package, not the published artifact name.
Maven Central additionally requires a domain-verified `groupId`; `com.snaplink`
presumes control of `snaplink.com`, and publication stays unconfigured until
that is settled.

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

## Add the SDK

```kotlin
dependencies {
    implementation(project(":sso-client")) // local checkout / included build
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
credentials even if the network call fails.

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
- DPoP, account/tenant selection, and the complete generated REST surface are
  not part of this initial package. Add them only against approved server
  contracts and security review.

## Verify

```bash
cd sdks
./gradlew :sso-client:testDebugUnitTest :sso-client:assembleRelease
```

The Gradle workspace lives at `sdks/`. Kotlin package declarations remain
`com.snaplink.sso`; main, unit-test, and instrumentation sources are kept in
flat `kotlin/main`, `kotlin/test`, and `kotlin/androidTest` source roots to fit
the repository's directory-depth budget.

The unit suite covers PKCE construction, callback state/issuer binding, token
exchange, concurrent refresh, local clear/logout cleanup, and configuration
validation.
