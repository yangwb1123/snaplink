# Design: `interfaces/ssoclient` Direction 2 — unify and harden the validation contract

Implements the requirements in
[`interfaces-ssoclient-direction2-spec.md`](interfaces-ssoclient-direction2-spec.md):
three additive hardening decisions for the `AuthClient` facade — mandatory issuer
pinning (`remote`), audience enforcement (`remote` + `local`), and a loud-failure
logout/revocation contract (`remote`). All evidence below was re-verified against
the code before writing.

## Contract principle (restated)

The `AuthClient` facade must never be weaker than the layer it wraps or the endpoint
it calls:

- `ssoclient/rs` enforces `iss` (required, exact) + `aud` (when `ExpectedAud` set);
  the facade must enforce at least the same gates.
- The server's RFC 7009 `POST /token/revoke` answers definitively (200 on valid
  credentials, regardless of token existence); the facade's `Logout` must never
  silently claim success when no revocation happened.

Non-goals (unchanged from the spec): no token-acquisition surface (direction 1), no
`rs` changes, no server route/handler changes, no DPoP/mTLS client-auth helpers.

Verified callers and fixtures that constrain the design:

| Caller | Location | Impact |
|---|---|---|
| `cmd/sso-mcp` (nested module, own `go.mod`) | `cmd/sso-mcp/snaplink.go:33` `remote.NewAuthClient(jwks)` | Compiles, fails loudly at runtime under fail-closed issuer; `Config.Issuer` field already exists (`cmd/sso-mcp/config.go:26`) |
| `docs/examples/remote-app` | `docs/examples/remote-app/main.go:39` `remote.NewAuthClient(jwks)` | Same runtime break; issuer derivable from the `--jwks` base URL |
| `docs/examples/embedded-app` | `main.go:35-38` `clientID=""` workaround | The documented `aud` gap; fixed by minting `aud` |
| `remote/auth_test.go` `signerAndCache` + `auth_multialg_test.go` | both fixtures construct `remote.NewAuthClient(cache)` bare | Must wire the new options |
| `TestRemoteAuth_LogoutWithoutURLIsNoop` | asserts the silent-nil contract being removed | Must assert `ErrLogoutNotConfigured` instead |

`grep` over non-test callers finds zero `.Logout(` consumers of `ssoclient.AuthClient`
outside the packages themselves — the Logout behavior change breaks no production
caller. `cmd/sso-mcp` and `docs/examples/remote-app` are the only production-ish
`remote.NewAuthClient` callers.

---

## Decision 1: API surface — issuer pinning (`remote`)

### Shape

```go
// interfaces/ssoclient/remote/auth.go
type AuthClient struct {
    jwks      *JWKSCache
    httpc     *http.Client
    issuer    string // required; WithIssuer
    logoutURL string // OIDC end-session (POST /logout); optional
    revokeURL string // RFC 7009 (POST /token/revoke); optional
    // + revoke client credentials
}

// WithIssuer pins the expected `iss` claim. Required: ValidateToken fails
// closed with ErrIssuerRequired until set — the facade must not be weaker
// than rs.Config.Issuer ("REQUIRED", rs/rs.go:88).
func WithIssuer(issuer string) AuthOption
```

- Constructor stays variadic (`NewAuthClient(jwks, WithIssuer(...), ...)`), so every
  existing call site compiles; the fail-closed gate turns the missing option into a
  loud runtime error at first `ValidateToken`, mirroring
  `rs/validate.go:26-28` (`ErrConfig: Issuer required`).
- The claim gate is an exact string match (`p.Iss != c.issuer` → error), byte-for-byte
  rs parity (`rs/claims.go:162-164`). Error text keeps rs's `iss %q` shape; the
  attacker-controlled claim is echoed only as far as rs already echoes it.

### Gate placement and ordering

Fail-closed ordering in `remote.ValidateToken`, chosen to mirror
`rs.ValidateToken` (`validate.go` + `claims.go:160-190`) as closely as the facade
shape allows:

1. `token == ""` → argument error (existing).
2. `c.issuer == ""` → `ErrIssuerRequired` — config gate BEFORE any token work, like
   rs's `ErrConfig` gate.
3. Parse header, resolve kid, `VerifyCompactJWS` (existing; alg/typ gates unchanged).
4. Unmarshal payload.
5. `p.Iss != c.issuer` → `ErrIssuerMismatch` — the FIRST claim gate, before
   exp/nbf, matching rs's `validateClaims` order (iss → exp → nbf → iat → aud).
6. Time gates (`validateTokenTime`, unchanged — no clock-skew change in this
   direction; rs's skew tolerance is out of scope and stays an asymmetry).
7. Audience gate (Decision 2).

The spec's prose ("after signature + time verification") is tightened here to rs's
iss-before-time order deliberately: a wrong-issuer token must report
`ErrIssuerMismatch`, not `token expired`, so both layers return the same sentinel
class for the same token. This is a parity decision, not a security one — both
orders fail closed.

### `Subject.Issuer` — surface the verified identity

`ssoclient.Subject` gains `Issuer string` (new field, additive, no wire contract):

- `remote`: `subjectFromPayload` maps `p.Iss` (today parsed at `remote/auth.go:74`
  and dropped).
- `local`: maps `claims.Issuer` (today dropped at `local/auth.go:42-50`; the claim
  exists on `shared/core.TokenClaims` at `types_token.go:44`).

Rationale: the verified identity becomes observable at the facade boundary, and the
"parsed-but-dropped" claim can no longer rot silently (the exact failure that made
Improvement 1 necessary). The local implementation does NOT get a `WithIssuer` pin:
its trust anchor is the in-process `sso.TokenIssuer` instance — the signing key IS
the issuer binding, so a pin would be redundant. This asymmetry is documented on
`WithIssuer` and in the package docs.

---

## Decision 2: API surface — audience enforcement (`remote` + `local`)

### Shape

```go
// remote
func WithExpectedAud(aud string) AuthOption          // -> c.expectedAud
// local
func WithExpectedAud(aud string) Option              // -> c.expectedAud
```

Semantics mirror `rs.Config.ExpectedAud` exactly (`rs/rs.go:100-101`,
`rs/claims.go:179-181`, `rs/introspect.go:124-127`):

- Empty expectation (the default) → gate skipped; byte-identical behavior for
  existing callers.
- Non-empty → the token's `aud` (string or array form) must contain the value
  exactly; otherwise `ErrAudienceMismatch`. Missing `aud` with an expectation set is
  a mismatch (fail closed), never a pass.
- Sentinels are bare in rs; keep them bare in the facade (no claim echo, no oracle
  text).

### Implementation notes

- `remote` already has `normalizeAudience` (string/`[]any` → `[]string`); the gate is
  a containment scan over the normalized slice. Importing `rs` from `remote` is
  impossible (rs imports remote for `JWKSCache` — `rs/rs.go` — a cycle), so the
  ~6-line containment helper is duplicated with a comment pointing at
  `rs/claims.go:HasAudience` for the canonical semantics. Parity is enforced by
  tests, not shared code.
- `local` gates on `claims.Audience` (a `[]string` already) with the same helper.
  Gate runs after `issuer.Validate` + `IsAccessTokenClaims` (`local/auth.go:42`),
  i.e. only on signature-verified claims.
- Gate order in both: issuer (remote only) → time → audience, matching rs.

### The pin VALUE is a claim expectation, not a client registry lookup

Verified mint-path facts that the docs must state:

- Server login path stamps `aud = client.ID` (`interfaces/sso/server_finish_login.go:298`).
- Server token path stamps `aud = req.Audience` — RFC 8707 resource indicators
  (`interfaces/sso/server_token.go:203,440`); `client_id` is a separate claim
  (per `handle_revoke.go` `authenticateRevokeAllBearer` comment).
- `defaultimpl` issuers stamp `aud` only from `sso.Subject.Resources`
  (`infrastructure/defaultimpl/issue_payload.go:91`), as a compact string for a
  single element (`audClaim`, verified by `aud_claim_fuzz_test.go`).

Consequence: `WithExpectedAud` pins whatever value the App's mint path actually
puts in `aud` — a client ID for login-path tokens, a resource URI for token-path
tokens, `Resources` for `defaultimpl` mints. The design rejects the tempting
"derive the expectation from a client registry" shortcut: the facade has no client
store and must not invent one (that would be a new storage dependency; see
Decision 5).

---

## Decision 3: API surface — logout revocation contract (`remote`)

### Problem confirmed

`remote.Logout` first line (`remote/auth.go:106-107`):

```go
if c.logoutURL == "" || req == nil {
    return nil
}
```

Silent success when nothing was sent. `local.Logout` already rejects empty requests
(`local/auth.go:64-66`). The two facade implementations disagree; the spec's
"unify" half requires making them agree.

### New behavior

1. `req == nil` (or both `SessionID` and `AccessToken` empty) → argument error,
   mirroring local's contract. (`local` message stays as-is; `remote` gains an
   equivalent.)
2. Non-empty request where the required endpoint is not configured → typed
   `ErrLogoutNotConfigured`, wrapped with the missing capability
   (e.g. `ErrLogoutNotConfigured: access-token revocation requires WithRevokeURL`).
   Never `nil`.
3. Field-to-endpoint routing (each field routed to the endpoint whose server
   contract it matches — verified against `interfaces/sso/server_routes.go:182,194`
   and the handlers):

   | `LogoutRequest` field | Endpoint | Wire shape (unchanged from what the server binds) |
   |---|---|---|
   | `SessionID` | `POST /logout` via `WithLogoutURL` (OIDC end-session path) | JSON `{"session_id": ...}` + optional `Authorization: Bearer` — exactly what `handleLogout` binds (`server_logout.go`, `ErrSessionIDOrBearerRequired` on both-empty) |
   | `AccessToken` | `POST /token/revoke` via `WithRevokeURL` (RFC 7009) | form-encoded `token` + `token_type_hint=access_token`, HTTP Basic client credentials — exactly what `revokeRequest` + `BasicClientCreds` bind (`handle_revoke.go`) |

   With both fields set and both URLs configured, both calls run; the error from the
   first failure aborts (short-circuit) — a partial logout is a failure, never a
   silent half-success.

4. `WithLogoutURL` is retained and re-documented as the session-logout path ("OIDC
   end-session, not token revocation"), matching the server's `POST /logout`
   handler. The spec's worry that the current wire shape "does not match" is
   resolved by the routing split: the JSON+session_id shape matches `/logout`; it
   was only wrong as a revocation mechanism. The existing test
   `TestRemoteAuth_LogoutCallsConfiguredURL` (JSON body + bearer) stays valid for
   the `/logout` path.

### New option

```go
// WithRevokeURL targets the SSO server's RFC 7009 POST /token/revoke endpoint.
// Logout requests carrying an AccessToken are revoked here as form fields
// token + token_type_hint=access_token with HTTP Basic client credentials
// (server precedence: Basic wins over body creds — handle_revoke.go). The
// server answers 200 on valid credentials regardless of token existence, so a
// 2xx response IS the revocation confirmation; any non-2xx is an error.
func WithRevokeURL(url, clientID, clientSecret string) AuthOption
```

- Client credentials are mandatory parameters: the server 401s without valid creds
  (`authenticateRevokeClient`), and an unauthenticated revoke attempt would be a
  configured-but-broken path — the design refuses to allow constructing it.
- Success = 2xx, with an empty body (the server's "always 200" response is
  `map[string]any{}`); the client does not parse the body.
- Non-2xx (400 invalid_request, 401 invalid_client, 5xx) and transport failures
  (timeout via the existing 5s `http.Client`, DNS, TLS) all return an error.
  HTTP status is wrapped into the error text for operator diagnosability;
  401 maps to a client-configuration problem.
- `WithAuthHTTPClient` continues to customize the transport for both logout
  endpoints.

### Interface doc (client.go)

`AuthClient.Logout` doc changes from "Best-effort..." to the loud contract:

> Returns an error if revocation could not be performed (not configured, bad
> request, or transport failure); success means the server accepted the
> revocation. A nil error no longer implies downstream caches are invalidated
> — it means the revocation request was actually sent and answered.

`AuthClient.ValidateToken` doc gains: "`aud` is enforced when the implementation
is configured with an expected audience; `remote` also requires the configured
issuer."

---

## Decision 4: API surface — error taxonomy and sentinel placement

### Where the sentinels live

New file `interfaces/ssoclient/errors.go` (facade package), NOT duplicated per
implementation:

```go
var (
    ErrIssuerRequired     = errors.New("ssoclient: issuer required")     // remote, fail-closed config gate
    ErrIssuerMismatch     = errors.New("ssoclient: issuer mismatch")     // remote, exact iss match
    ErrAudienceMismatch   = errors.New("ssoclient: audience mismatch")   // remote + local, containment
    ErrLogoutNotConfigured = errors.New("ssoclient: logout not configured") // remote
)
```

Rationale:

- `local` and `remote` both need `ErrAudienceMismatch`; a single facade-level
  sentinel lets an App write `errors.Is(err, ssoclient.ErrAudienceMismatch)` and
  behave identically regardless of backend — the whole point of the facade.
- `rs` keeps its own sentinels untouched (non-goal: zero `rs` changes); the
  duplication between `rs.Err*` and `ssoclient.Err*` is accepted and documented —
  the packages are already independent by design (rs must not import the facade).
- `interfaces/ssoclient` is at 6 non-test files; adding `errors.go` is far below any
  budget. The `interfaces/sso` 60-file ceiling is untouched (zero new files there).
- Per AGENTS.md §5.6: these sentinels never surface on a wire endpoint, so
  `docs/error-codes.md` is NOT updated (SDK-side errors only); the contract lands
  in package docs, `client.go` docs, and the example.

### Error-priority table (single token, multiple defects)

Order is load-bearing and mirrors rs: config → malformed/typ/alg/signature →
`iss` → time → `aud`. A token that is wrong-issuer AND wrong-audience reports
`ErrIssuerMismatch`; wrong-issuer AND expired reports `ErrIssuerMismatch`; a
forged-alg token never reaches claim gates. This keeps cross-layer error classes
identical for the same token (rs: iss → exp → aud) and avoids turning any gate
into a probe oracle for a downstream one.

---

## Decision 5: Storage model

**None — this is an SDK-side, in-memory change. There is no new persistent state,
no new config schema, and no server-side store.**

What actually changes:

| Concern | State | Lifecycle |
|---|---|---|
| `AuthClient` options | four new in-memory fields on `remote.AuthClient` (`issuer`, `expectedAud`, `revokeURL`, `revokeCreds`) + one on `local.AuthClient` (`expectedAud`) | process-local, immutable after construction (options are construction-only, matching every existing option) |
| `JWKSCache` | unchanged | caller-owned, shareable across clients, as today |
| Revocation correctness | relies on the SERVER's existing stores (per-issuer revocation chain + refresh-token store behind `POST /token/revoke`; session store behind `POST /logout`) | the facade holds no copy of any credential state |

Implications:

- No migration, no cache invalidation, no cross-replica concerns, no audit events
  (these are client-side calls; the server's existing audit points — e.g.
  `AuditPartialRevokeFailure` in `handle_revoke.go` — already cover the wire).
- The design deliberately does NOT add a client-registry or issuer-registry store to
  the facade: pin values are construction-time constants, which is what makes the
  gate trivially auditable (read the wiring, know the pins).
- `cmd/sso-mcp` reuses its existing `Config.Issuer` flag (`config.go:26`) — no new
  config surface there either.

---

## Decision 6: Failure modes

| # | Failure mode | Trigger | Result | Oracle-safety / notes |
|---|---|---|---|---|
| 1 | Unconfigured issuer | `remote.ValidateToken` with no `WithIssuer` | `ErrIssuerRequired`, no subject | Fail closed at call time; mirrors `rs` `ErrConfig`. Breaks bare `NewAuthClient(jwks)` callers LOUDLY (migration in Decision 7) |
| 2 | Wrong issuer | Token from issuer B, client pinned to A; valid signature/time/aud | `ErrIssuerMismatch` (`iss %q`) | Exact match; the multi-App central-SSO cross-tenant case from the spec. Echo bounded to rs parity |
| 3 | Missing `iss` | Validly-signed token with no `iss` claim | `ErrIssuerMismatch` (`iss ""`) | `"" != pin` — same path as #2, fail closed |
| 4 | Audience mismatch | `aud` (string or array) lacks the pinned value, or `aud` missing | `ErrAudienceMismatch`, bare sentinel | Fail closed when expectation set; skip when empty (opt-in, no regression). Horizontal App boundary enforced in both implementations |
| 5 | Malformed/expired/unknown-kid/tampered | existing remote gates | existing errors, unchanged | No behavior change; time gates deliberately untouched (no skew change) |
| 6 | `Logout` nil/empty request | `req == nil` or both fields empty | argument error (remote gains this; local unchanged) | Both implementations now agree |
| 7 | `Logout` with no endpoint for the field | `AccessToken` set, no `WithRevokeURL`; or `SessionID` set, no `WithLogoutURL` | `ErrLogoutNotConfigured` (wrapped with the missing capability) | Replaces the silent-nil; the spec's core complaint. Never claims success without a request |
| 8 | Revoke endpoint rejects | 400 (bind/empty token), 401 (bad client creds — config error), 5xx | wrapped error with HTTP status | Server contract: 200 on valid creds regardless of token existence — so a 2xx is definitive; the client trusts it |
| 9 | Revoke transport failure | timeout (5s client), DNS, TLS, conn refused | wrapped error | Never nil; caller can retry (revocation is idempotent server-side per RFC 7009 §2.2) |
| 10 | Partial logout | `SessionID` + `AccessToken` set, first leg fails | error from the failing leg, second leg NOT attempted | Short-circuit; a half-logout is reported, not hidden |

All failure modes are deterministic and unit-testable with `httptest` servers; none
require the real SSO server (the acceptance tests for #2/#4 need two `defaultimpl`
issuers + two JWKS fixtures — same pattern as the existing
`TestRemoteAuth_RejectsWrongKey`).

---

## Decision 7: Caller migration and contract docs (same change)

Fail-closed gates only ship with their callers wired, per AGENTS.md §5 (smallest
cohesive change, no broken intermediate states):

1. **`cmd/sso-mcp`** (nested module, own `go.mod`): pass `remote.WithIssuer(cfg.Issuer)`
   in `newSnaplinkClient` (`snaplink.go:33`). `Config.Issuer` already exists and is
   already required for PRM (`auth.go:72`), so this is a one-line wiring change;
   optionally also `WithExpectedAud(cfg.ResourceURI)` — the MCP server already knows
   its required `aud` (`config.go:27`), which is exactly the claim the token path
   stamps. `make ci` covers nested modules.
2. **`docs/examples/remote-app`**: add an `--issuer` flag (default
   `http://localhost:8080`, the server origin the `--jwks` URL derives from) and wire
   `WithIssuer`. `WithExpectedAud` is left unwired with a comment: the demo's
   login-path tokens carry `aud = client.ID` but the demo registers no client, so an
   aud pin would make the demo fail — the example documents the pin decision rather
   than faking one.
3. **`docs/examples/embedded-app`**: the `clientID=""` workaround is deleted.
   The demo mints `aud` by setting `Resources: []string{appClientID}` on the
   `sso.Subject` passed to `issuer.Issue` (the `defaultimpl` aud path,
   `issue_payload.go:91`; single element → compact string form, which the remote
   `normalizeAudience` and the local `claims.Audience` both parse), registers roles
   under the real `appClientID`, and wires
   `local.WithExpectedAud(appClientID)` — proving the gate end-to-end through
   `appcore.Handler`'s `aud[0]` client resolution (`appcore` firstAudience).
4. **Tests**: `signerAndCache` and the multi-alg fixture gain
   `WithIssuer(issuerURL)` (and `WithExpectedAud` where the token mints `aud`);
   `TestRemoteAuth_LogoutWithoutURLIsNoop` becomes
   `TestRemoteAuth_LogoutWithoutURLFails` asserting `ErrLogoutNotConfigured`; new
   cross-issuer, cross-client, missing-`iss`, string/array-`aud`, and
   `WithRevokeURL` wire tests per the spec's acceptance list.
5. **Docs**: `client.go` (`ValidateToken`, `Logout`), `remote` package doc
   (issuer requirement, revoke-vs-logout split), `WithLogoutURL` doc (session path,
   no "silently skips" wording), `types.go` `Subject.Issuer` doc.

---

## Decision 8: What could break the design

1. **Fail-closed issuer gate breaks un-migrated callers at runtime.** The variadic
   constructor means everything compiles, then `ValidateToken` starts failing with
   `ErrIssuerRequired`. The design's mitigation is same-change migration (Decision
   7), and the gate greps for bare `remote.NewAuthClient(` call sites in CI review.
   The residual risk is a caller outside this repo (the SDK is embeddable). This is
   the intended price of the fix — the spec explicitly chooses loud failure over
   silent weakening — but it must be called out in the change description.

2. **`aud` pin value mismatch is a false-denial trap.** An operator who pins
   `WithExpectedAud(clientID)` but issues tokens through the token path (which
   stamps RFC 8707 resource indicators in `aud`, not the client ID —
   `server_token.go:203`) will reject every valid token with
   `ErrAudienceMismatch`. Mitigation: Decision 2's "claim expectation, not registry
   lookup" documentation, plus the sso-mcp wiring that pins `ResourceURI` (the
   correct value for token-path tokens). A wrong pin fails loudly and identifiably,
   which is acceptable; a silently-weak pin would not.

3. **Single-issuer-per-client limitation.** One `AuthClient` pins one issuer; a
   central deployment serving multiple issuer strings (e.g. per-region or per-tenant
   issuer URLs) needs one client per issuer. This matches the existing per-App
   wiring model and rs's single-`Config.Issuer` design, but a future multi-issuer
   facade would need a set, not a string — deliberately out of scope; the error
   text and sentinels are set-safe to evolve (a set only changes the option
   signature, not the errors).

4. **`rs` parity drift.** The facade gates are duplicated (remote cannot import rs —
   import cycle) and only test-enforced for parity. If `rs` semantics change (e.g.
   `ExpectedAud` becomes multi-value), the facade must follow; the design pins the
   reference (`rs/claims.go:HasAudience`) in comments at both duplication points.

5. **Silent-aud-drop on non-string `aud` elements.** `normalizeAudience` and
   `audienceValues` drop non-string array items. With an expectation set this is
   fail-closed (drops → no containment → mismatch); with no expectation it stays a
   pass-through, unchanged from today. No new risk, but the interaction is worth a
   test (array containing `aud` + a non-string item must still validate).

6. **Logout behavior change.** Any current consumer of the silent-nil path would
   start seeing errors. Verified: zero non-test callers of `AuthClient.Logout` in
   the repo (only `remote/auth_test.go`'s no-op test, which is rewritten). The
   remaining risk is out-of-repo SDK consumers; the loud contract is the point of
   the change and is documented in `client.go`.

7. **Budget drift.** `remote/auth.go` grows ~217 → ~290 lines (options + two gates +
   revoke path) — under the 500-line file limit; `local/auth.go` grows to ~120.
   No new packages, no `interfaces/sso` files, no new upward imports (the new
   `errors.go` imports only `errors`). The `interfaces/sso` 60-file ceiling and the
   nested-module rule (`cmd/sso-mcp` owns its `go.mod`) are both respected.

8. **Time-gate asymmetry stays.** `remote.validateTokenTime` has no clock skew where
   rs does. This direction deliberately does not touch it (spec non-goal); the
   asymmetry is pre-existing and should be tracked separately — if a future change
   adds skew, the gate order in Decision 1 must be re-checked.

9. **`ssoclient/dev` stub divergence.** The dev stub (`dev/auth.go`) remains a
   stub that ignores token bytes — it is, by construction, weaker than the
   contract. It is explicitly out of scope (dev-only, stderr-warned) and must not
   be mistaken for a real implementation; the facade docs name it as a dev tool so
   the "facade never weaker" principle is not silently violated by `WithSubject`.

---

## Verification plan

- Per-edit: `go build ./... && go vet ./...` and
  `go test -run 'TestMaintainability_|TestArchitecture_' .` (mandatory gate).
- Per-change: `go test ./interfaces/ssoclient/... -race` (new tests included),
  `go test ./cmd/sso-mcp/...` (nested module, its own gate), `go build ./docs/examples/...`
  and a smoke run of `embedded-app` with a real client ID.
- Handoff: `make ci` (full gate incl. nested modules), `go test ./test/ -run TestE2E -v`.
- Grep gates: no `clientID=""` workaround in `embedded-app`; no "silently skips"
  wording in `remote` docs; no bare `remote.NewAuthClient(` in non-test code.
