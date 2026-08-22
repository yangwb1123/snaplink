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

`MemoryStateStore` is for development. Production applications should provide
a tenant/session-backed `StateStore` whose `Take` operation atomically removes
the transaction; this is application session storage, not a separate BFF.
