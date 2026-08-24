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

let started = snaplink.login(&options)?;
if let LoginResult::Redirect { url, .. } = started {
    return redirect(url);
}

// On the registered callback route:
let completed = snaplink.login(
    &options.clone().callback_url(request.uri().to_string()),
)?;
let access_token = completed.tokens().unwrap().access_token.clone();
~~~

Prepare a paid or invited product before starting login. `setup` sends the
credential only in the HTTPS request body and the callback claims the returned
short-lived ticket with the bearer:

~~~rust
let setup = snaplink_sso::SetupOptions::new(
    "https://sso.example.com", "my-public-app", "pro",
)
.license_key("license-from-your-checkout");
snaplink.setup(&setup)?;
let started = snaplink.login(&options)?;
// The callback login performs the activation claim.
let account = snaplink.get_account_context("pro")?;
~~~

Use `LoginSetupOptions` with `LoginOptions::setup(...)` for the one-call form,
or `invitation_code(...)` for an invitation. The server remains authoritative
for tenant, plan, features, and limits.

MemoryStateStore is for development and single-process examples. Provide a
durable implementation of the atomic StateStore trait for multi-worker
deployments. The blocking HTTP client is intentionally easy to replace with
SnaplinkClient::with_http_client.
