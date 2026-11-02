# Optional resource-server revocation checks

The Go resource-server SDK (`interfaces/ssoclient/rs`) can consult an
application-owned revocation backend after validating a token. Configure
`rs.Config.RevocationCheck` explicitly; its default is `nil`.

This is an SDK extension, not a stock `sso-server` configuration option. It
adds no store, cache, event receiver, CAEP wiring, background worker, or
automatic propagation between servers. Revocation visibility depends on the
backend's data and propagation latency, not merely on enabling the callback.

## Configure the callback

The optional field has this signature:

```go
RevocationCheck func(context.Context, rs.RevocationToken) (revoked bool, err error)
```

For example, adapt your application's backend (the `revocations` object below
is application code, not a Snaplink-provided store):

```go
cfg.RevocationCheck = func(ctx context.Context, token rs.RevocationToken) (bool, error) {
    return revocations.IsRevoked(ctx,
        token.Issuer, token.TenantID, token.ClientID, token.JTI)
}
protectedAPI := rs.HTTPMiddleware(cfg, apiHandler)
```

Returning `false, nil` permits validation to continue. Returning `true` or any
error denies the token. With a non-nil callback, a missing or empty `jti` is
also denied **without invoking the callback**. Ensure issuers and introspection
responses supply `jti` before enabling this check.

The callback runs synchronously on every validation that reaches it, with the
original caller/request context. It must be concurrency-safe, honor
cancellation and deadlines, and bound its own I/O. The SDK does not spawn a
goroutine, retry, cache verdicts, or interrupt an uncooperative backend. A
canceled context at the check, including cancellation before a backend
returns `false, nil`, cannot produce a successful validation.

## Use the complete namespace

`rs.RevocationToken` is a **value** containing only four strings:

| Field | Source |
| --- | --- |
| `Issuer` | Required `Config.Issuer`, already checked by the existing issuer gate when the token/response supplies `iss` |
| `TenantID` | Validated `tenant_id` projection; empty when absent |
| `ClientID` | Validated `client_id` projection; empty when absent |
| `JTI` | Validated, non-empty `jti` projection |

Key backend decisions by **all four fields**, with exact, unambiguous field
boundaries. Do not use a bare JTI, tenant-only key, or ambiguously concatenated
string: identical JTIs may belong to different issuers, tenants, or clients.
The SDK does not invent tenant/client identifiers when optional claims are
absent; the backend must define the meaning of empty namespace components or
return an error to deny them.

RFC 7662 responses may omit `iss`. The existing introspection policy still
allows that: the descriptor uses the configured expected issuer as its
namespace, while returned `Claims.Issuer` remains empty. A supplied issuer
must still match the configuration. Point introspection at the intended,
trusted AS over a suitably secured transport; the callback does not
independently authenticate an introspection response or verify an opaque
token's signature.

There is no raw token, `Claims` pointer, map, or slice in the descriptor.
Changing or retaining a callback's copy cannot change validated claims or
`Claims.Raw`. This callback supplies a revocation decision, not a general
claims mutation or authorization hook.

## Validation order and compatibility

Both `ValidateToken` (local JWT/JWKS) and `ValidateTokenWithIntrospect` call the
hook only **after all their existing validation gates**:

- Local mode: token structure/type, key lookup, algorithm/signature, claim
  decoding, issuer, required expiry and time checks, audience, and optional
  serving-region governance.
- Remote mode: successful introspection transport/decoding, `active: true`,
  then the existing issuer/audience/expiry/serving-region policy. Crypto,
  token type, and algorithm validation remain the AS's responsibility. The
  SDK does not add local JWT parsing or change which introspection claims
  are optional.

A token rejected by those gates never invokes the callback. Existing error
priority is preserved, including `403 region_not_allowed` for a serving-region
governance denial. Tenant claims are not rewritten or newly checked against
request headers.

`ValidateTokenWithDPoP` and `HTTPMiddleware` use the same token-validation
paths, then continue their existing DPoP checks. A valid access token can
therefore reach the callback even if its accompanying proof later fails.
`false, nil` never bypasses proof binding, freshness, replay protection, or
the rejection of a bound token presented as plain Bearer.

A nil callback preserves previous behavior: local validation does not gain
revocation visibility or a backend dependency, tokens without JTI remain
accepted under the existing policy, and remote mode still makes its normal
uncached introspection request. Existing JWKS caching, fetch debounce,
clock-skew rules, and introspection time limits are unchanged.

## Errors and HTTP responses

No new error sentinel or wire code is introduced. Missing JTI at the check,
revocation, callback errors, and cancellation observed by the check all return
`rs.ErrTokenInactive` with no validated claims. Backend errors are deliberately
not wrapped or exposed. Failures before the check retain their existing SDK
errors (for example, a canceled introspection HTTP request can return
`rs.ErrIntrospection`).

For these revocation-check denials, `HTTPMiddleware` uses its existing coarse
response, indistinguishable across the hidden causes:

```http
HTTP/1.1 401 Unauthorized
Cache-Control: no-store
Pragma: no-cache
Content-Type: application/json
WWW-Authenticate: Bearer error="invalid_token", error_description="token validation failed"

{"error":"invalid_token"}
```

DPoP requests keep the existing DPoP challenge scheme and advertised `algs`;
backend details never enter its description. The SDK emits no automatic
backend-detail logs or audit events. Application-specific backend diagnostics
must stay out of credential responses.
