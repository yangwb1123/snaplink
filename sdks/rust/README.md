# snaplink-sso — Rust SDK

This crate provides framework-neutral hosted login for a public Snaplink
client. The first login call returns the existing Console /login/ URL; the
callback call validates state and issuer and exchanges the authorization code
with S256 PKCE. A web framework only needs to issue the redirect and pass the
callback URL back to the same client. No BFF or client secret is required.

~~~rust
use snaplink_sso::{LoginOptions, LoginResult, SnaplinkClient};

let mut snaplink = SnaplinkClient::new();
let options = LoginOptions::new(
    "https://sso.example.com",
    "my-public-app",
    "https://app.example.com/auth/callback",
)
.return_to("https://app.example.com/dashboard");

// Call from an async runtime (Tokio, async-std, etc.).
let started = snaplink.login(&options).await?;
if let LoginResult::Redirect { url, .. } = started {
    return redirect(url);
}

// On the registered callback route, use the same shared StateStore:
let completed = snaplink.login(
    &options.clone().callback_url(request.uri().to_string()),
).await?;
let access_token = completed.tokens().unwrap().access_token.clone();
~~~

The SDK generates and persists an OIDC nonce with the PKCE transaction; after
callback completion, read it with `LoginResult::nonce()`. The SDK does not verify
ID-token signatures. A relying party must validate the ID token against its
configured issuer, audience, and JWKS, then compare the validated token's nonce
with `LoginResult::nonce()` before accepting the identity.

Prepare a paid or invited product before starting login. `setup` sends the
credential only in the HTTPS request body and the callback claims the returned
short-lived ticket with the bearer:

~~~rust
let setup = snaplink_sso::SetupOptions::new(
    "https://sso.example.com", "my-public-app", "pro",
)
.license_key("license-from-your-checkout");
snaplink.setup(&setup).await?;
let started = snaplink.login(&options).await?;
// The callback login performs the activation claim.
let account = snaplink.get_account_context("pro").await?;
~~~

## Commercial entitlements

An entitlement is not the same as a licence. Test the three-state classification,
never the presence of the field: a subscription whose window has closed is still
present in the response and grants nothing.

~~~rust
use snaplink_sso::{Feature, LicenseState};

let account = snaplink.get_account_context("pro").await?;
match account.state() {
    LicenseState::Active(_) if account.has(Feature::Scim) => { /* scim is available */ }
    LicenseState::Active(_) => { /* plan does not include scim */ }
    LicenseState::Inactive { reason, .. } => { /* {reason} is for display only */ }
    LicenseState::NotActivated => { /* prompt for a license key */ }
}
~~~

`Feature` and `Limit` are typed constants mirroring the server's `commerce`
vocabulary, so no call site compares a raw string. An unrecognised key the server
adds later is preserved and reported by `unknown_features()` rather than
silently dropped or silently granted.

The server remains the authority on every authorization decision. SDK-side
entitlement data exists for user experience only.

## Offline licensing

`docs/commercial-model.md` requires that a private or air-gapped deployment gate
paid features from a signed file, and that authentication never calls a vendor
licensing service on a login path. `EntitlementFile` verifies such a file
entirely locally, with no network I/O on any path including login.

~~~rust
use snaplink_sso::{EntitlementFile, Feature, LicenseTrust};

let trust = LicenseTrust::from_key("vendor-2026", PUBLIC_KEY)?;
let file = EntitlementFile::verify(&std::fs::read("license.json")?, &trust)?;
if file.entitlement.has(Feature::Scim, snaplink_sso::unix_now()) {
    // enable the paid feature
}
~~~

Supply the public key through `LicenseTrust`, which is what makes OEM and
private-CA deployments possible. `LicenseTrust::vendor_pinned()` is the slot for
Snaplink's own root; it reports `LicenseError::TrustUnconfigured` in this build
rather than carrying a placeholder key that would read as vendor authority while
verifying nothing. A verification failure is never downgraded to an active or
free-tier entitlement.

The signing private key never enters this crate, this repository, or CI.

## Presentation preferences

Locale and theme survive a handoff into and out of hosted login. A handoff
carries only explicitly set values, so it never clears a preference the
application did not mean to touch.

~~~rust
use snaplink_sso::{PresentationPreferencesPatch, ThemeMode, build_login_preference_handoff};

let handoff = build_login_preference_handoff(&PresentationPreferencesPatch {
    locale: Some("en-US".into()),
    theme_mode: Some(ThemeMode::Dark),
})?;
// spread `handoff` into the login request
~~~

`SnaplinkClient` is async-first and accepts an injectable `Transport` through
`with_transport`, so applications can supply their configured HTTP client,
timeouts, and proxy policy. The default reqwest backend refuses redirects; custom
transports must keep authorization codes and bearer tokens on-origin too.
`MemoryStateStore` is suitable for development and
single-process examples; multi-worker deployments must provide a durable
implementation of the atomic `StateStore` trait. Tokens are never persisted by
the SDK: callers must save refreshed tokens and delete their saved copy on
logout. `refresh().await` explicitly rotates tokens, `logout().await` revokes the
server session and clears this client's in-memory state, and `clear()` only
forgets local state.
