# Authentication Pipeline Hooks

Snaplink exposes five opt-in extension points without replacing the built-in
OAuth/OIDC authentication chain:

| Phase | Position | Allowed output |
|---|---|---|
| `pre_authenticate` | After request binding, before client/provider policy and credential verification | No mutation; may reject |
| `post_authenticate` | After primary authentication, before risk/MFA/session side effects | `Attributes`, `SkipMFA` |
| `pre_token_issuance` | Immediately before every access-token issuer call | `Claims` |
| `post_token_issuance` | After successful access-token issuance | Notification only |
| `on_login_failed` | After primary credential failure | Notification only |

No Hook is registered by default. The zero-Hook login path performs only a nil
registry check and retains the existing control flow. Hooks run by ascending
`Priority`, with registration order breaking ties. Each invocation receives a
deep-cloned `HookInput` and has an independent timeout (default five seconds),
so a timed-out Hook cannot mutate request-owned maps after the pipeline moves
on. A panic is converted to a Hook failure.

## Registering Hooks

Implement `core.AuthHook`, use `core.AuthHookFunc`, or use one of the phase
constructors (`NewPreAuthenticateHook`, `NewPostAuthenticateHook`,
`NewPreTokenIssuanceHook`, `NewPostTokenIssuanceHook`, `NewLoginFailedHook`).
Register one or more Hooks at startup:

```go
profile := core.NewPostAuthenticateHook(core.AuthHookConfig{
    Name: "company.profile",
    Priority: 20,
    FailClosed: true,
}, func(ctx context.Context, in *core.HookInput) (*core.HookOutput, error) {
    return &core.HookOutput{Attributes: map[string]string{"source": "company"}}, nil
})

claims := core.NewPreTokenIssuanceHook(core.AuthHookConfig{
    Name: "company.claims",
    Priority: 30,
    FailClosed: true,
}, func(ctx context.Context, in *core.HookInput) (*core.HookOutput, error) {
    return &core.HookOutput{Claims: map[string]string{"policy_version": "2026-08"}}, nil
})

server := sso.NewServer(sso.WithAuthHook(profile, claims))
```

`WithConfiguredAuthHook` supplies registration metadata externally for a Hook
that does not implement `AuthHookConfigurator`. Bare Hook implementations
default to fail-closed in decision/mutation phases. `AuthHookFunc` and other
configurable Hooks use their explicit `FailClosed` value. The two notification
phases always fail open, even if configured otherwise.

Return `core.NewAuthHookError(code, status, cause)` to expose a stable error
code and HTTP status. The cause is logged but never returned. Other errors are
collapsed to `hook_rejected`. A timeout is `hook_timeout`.

`HookInput.Headers` is request metadata supplied to trusted in-process Hooks;
it can include credential-bearing headers. Never log it wholesale or pass it
to an untrusted service. Hook names are startup-registered and bounded to 32
per phase because they become metric labels.

## Built-in Hooks

Package `platform/lifecycle/authpipeline` provides:

- `NewIPSkipMFAHook`: marks requests from configured CIDRs as eligible to skip
  MFA. Risk/conditional-access deny decisions still reject; only an MFA
  challenge is skipped.
- `NewProfileCompletionHook`: rejects an authenticated profile when a required
  attribute is empty, returning `profile_incomplete` before session/token side
  effects.
- `NewSIEMFailureHook`: sends login-failure notifications asynchronously with
  bounded concurrency and timeout. Saturation and delivery failures never
  change the login response.
- `NewWASMHook`: adapts the existing `wasmauthz.Engine`; the engine retains its
  wazero context timeout and memory limit. Guest errors and deny decisions are
  Hook failures.

The stock YAML composition supports the first two:

```yaml
auth_pipeline:
  ip_skip_mfa_cidrs: ["10.0.0.0/8", "2001:db8:1234::/48"]
  required_profile_attributes: ["email", "department"]
```

SIEM transports and WASM modules contain executable/runtime dependencies and
must be injected in Go.

## Observability

Each invocation records `sso_auth_hook_execution_duration_seconds` with
`phase`, registered `hook`, and `outcome` labels. Audit emits
`auth_hook_executed` or `auth_hook_failed` with phase/name/duration/continued
metadata. Neither telemetry surface contains Hook error detail, credentials,
claims, or token material.
