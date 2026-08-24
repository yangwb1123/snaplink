# Snaplink Go SDK login

This package provides framework-neutral hosted login for a public OAuth
client. `Client.Login` returns a Console `/login/` redirect on the first call;
the callback call validates state and issuer and exchanges the authorization
code with S256 PKCE. The host application returns `RedirectURL` as HTTP 302
and passes the callback URL back to the same method. No client secret is
accepted.

```go
client := snaplink.NewClient(store, nil)
started, _ := client.Login(ctx, snaplink.LoginOptions{
    BaseURL: "https://sso.example.com",
    ClientID: "my-public-app",
    RedirectURI: "https://app.example.com/auth/callback",
    ReturnTo: "https://app.example.com/dashboard",
})
// return started.RedirectURL as a 302

completed, _ := client.Login(ctx, snaplink.LoginOptions{
    BaseURL: "https://sso.example.com",
    ClientID: "my-public-app",
    RedirectURI: "https://app.example.com/auth/callback",
    CallbackURL: callbackRequestURL,
})
token := completed.Tokens.AccessToken
```

Paid or invited products can use the activation ticket flow before login. The
credential is sent only in the HTTPS JSON body; the login transaction contains
only the short-lived ticket, which is claimed with the bearer after the code
exchange:

```go
_, err := client.Setup(ctx, snaplink.SetupOptions{
    BaseURL: "https://sso.example.com", ClientID: "my-public-app",
    ProductID: "pro", LicenseKey: "license-from-your-checkout",
})
if err != nil { /* show setup error */ }

started, _ := client.Login(ctx, snaplink.LoginOptions{
    BaseURL: "https://sso.example.com", ClientID: "my-public-app",
    RedirectURI: "https://app.example.com/auth/callback",
})
// return started.RedirectURL as a 302; the callback Login claims activation.
account, _ := client.GetAccountContext(ctx, "pro")
```

`LoginOptions.Setup` provides the same inline behavior. Use `InvitationCode`
instead of `LicenseKey` for an invitation. The server derives the tenant,
plan, features, and limits.

`MemoryStateStore` is for development. Production applications should provide
a tenant/session-backed `StateStore` whose `Take` operation atomically removes
the transaction; this is application session storage, not a separate BFF.
