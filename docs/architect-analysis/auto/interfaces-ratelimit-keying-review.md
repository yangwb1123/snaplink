# Review: interfaces-ratelimit design — keying scheme pass

Independent review of `docs/auto/interfaces-ratelimit-design.md` (the
post-auth rate-limiting design) against the current tree and the
requirements spec (`docs/auto/interfaces-ratelimit-requirements.md`),
focused on the five load-bearing claims: the public-client IP fallback, the
`client:`/`admin:` namespace-collision invariant, admin tier-1 rekeying
being load-bearing, oracle-safe 429 shapes, and whether
checkpoint-before-residency leaks timing or state.

## Evidence standard

**Verified** = read from executable code this session (file:line anchors
below); **Partial** = verified with a caveat; **Missing** = absent from the
design; **Proposed** = design intent, no code. Checks run: the full
`/token` auth ladder (`server_token.go`, `server_token_clientauth.go`), the
grant limiter, the admin `HTTPMiddleware` ordering, the oidc
`HandleUserInfo` ordering, the mesh path (`mesh_authz.go`,
`server_userinfo.go`), all `HandlerContext` implementations, the
`MemoryLimiter`/`SQLiteLimiter`/Redis `Limiter` fail-open paths, the
config/reload hook, the error-codes contract, and user-ID generation. No
gates ran (review-only; no code changed). Where the design and the tree
disagree, the tree wins.

## Verdict

The scheme is sound. The credential gate is exactly right — and *necessary*:
the spec's letter (`client:<client_id>` for every authenticated client)
would have shipped a spoofable bucket, because a public client's `/token`
authentication is credential-free presentation of a publicly-known
`client_id`. The namespace invariant is correct as far as it goes (needs one
extension to the admin tier-1 store). Tier-1 rekeying is correctly
identified as load-bearing, with one conditionality the design does not
state. All four 429 shapes are oracle-safe in the cross-party sense.
Checkpoint-before-residency leaks neither timing nor state on any surface —
with one placement correction: the *mesh* checkpoint does not protect the
user lookup the design claims it protects. Three doc-level corrections and
two optional hardening notes are listed in §6.

## 1. Public-client IP fallback (Decision 3) — Verified, sound

The gate

```go
credentialed := client.Secret != "" || req.ClientAssertion != "" ||
    client.TokenEndpointAuthMethod == ClientAuthTLS ||
    client.TokenEndpointAuthMethod == ClientAuthSelfSignedTLS
```

is the exact negation of the public test in `denyPublicClientCredentials`
(`interfaces/sso/server_token.go:387-399`), and every branch is a verified
credential by the time the checkpoint runs:

- `client.Secret != ""` — the stored, registered credential
  (`shared/core/types.go:24`, `json:"-"`). `authenticateTokenClient`
  succeeds only if `VerifyTokenClientAuth` → `ValidateSecret` passed
  (`server_token_clientauth.go:196-208`); the empty-vs-empty match in
  `CompareClientSecret` (`shared/security/client_secret.go:19-26`) is what
  lets a secret-less public client authenticate at all, so
  `client.Secret != ""` at the checkpoint ⟺ a real secret was presented and
  verified. HTTP Basic is folded into `req.ClientSecret` *before* the
  checkpoint (`server_token_clientauth.go:148-152`), so Basic is covered by
  the same branch.
- `req.ClientAssertion != ""` — `resolveAssertedClientID`
  (`server_token_clientauth.go:47-83`) verified it: `private_key_jwt`
  against the client JWKS, workload-identity against the cloud JWKS, SPIFFE
  via the same assertion leg. Federation-derived clients (vouched JWKS)
  ride this branch. **Verified** — including the subtlety that
  `req.ClientID` is *overwritten with the asserted ID* on the
  private_key_jwt path, so the bucket key is the verified identity, not the
  form input.
- mTLS methods — `authenticateMTLSClient` succeeded
  (`server_token_clientauth.go:203-214`); a registered-TLS client that
  fails mTLS never reaches the checkpoint.

The spoof argument holds: an attacker can fill `client:<victim>` only if
they can *authenticate as the victim*, which requires the victim's secret /
assertion key / certificate. A secret-less client's ID is presentable by
anyone, so its bucket is keyed by IP. This is not a deviation from the
spec's security premise — it is the only reading consistent with the spec's
own `KeyByClientIDOrIP`-UNSAFE analysis (requirements doc lines 18-28); the
spec's letter would have created the exact flaw class it condemns. The
acceptance tests use `client_credentials` (confidential) and pass
unchanged.

**Residual, verified and understated in the design.** A public client's
auth at `/token` is credential-free, so an attacker holding a *single valid
auth code* can replay it indefinitely: client-level auth succeeds for any
secret-less `client_id` (the code is consumed only inside the grant
handler), each replay burns the phase-2 IP bucket. This is not a new vector
— phase-1's IP bucket is burnable with zero-credential garbage today — but
it means the phase-2 fallback delivers *zero marginal protection* for
public clients; it is a second IP bucket, not a public-client bucket. The
config-reference note should say exactly that ("public-client floods are
IP-bounded by both phase-1 and the fallback" is currently the extent of
it).

## 2. `client:`/`admin:` namespace-collision invariant — Verified, needs extension

**Verified.** `KeyByClientIDOrIP` (UNSAFE, pre-auth, Basic username) and the
new post-auth `KeyByClientID` share the `client:` prefix
(`interfaces/ratelimit/middleware.go:57-71`); `KeyBySubject` uses `sub:`
(`middleware.go:94-106`); admin tier-2 uses `admin:<subject>`; admin tier-1
uses the bare key `"admin"` (`interfaces/admin/governance.go:275-280`).

Within-store collisions are impossible: the token store's keys are
`client:<id>` (credentialed) or bare IPs (public fallback) — an IP string
never carries a `client:` prefix — and the userinfo store's keys are
`sub:<subject>` or bare IPs. Cross-store collisions require a shared
limiter instance; the design's hard rule covers the phase-1↔phase-2 case.

**Partial — two gaps:**

1. *Extension needed to the admin tier-1 store.* After the Decision 5
   rekey, tier-1 keys are **bare IPs — the same key strings the SSO
   phase-1 policy uses** (`KeyByClientIP`). The "never share an instance
   across phases" rule should name all four stores (SSO phase-1, token
   client, userinfo, admin tier-1/tier-2): sharing one limiter instance
   between admin tier-1 and SSO phase-1 would merge the two IP budgets,
   and an operator could then drain the SSO login bucket by flooding the
   admin surface from the same IP (or vice versa). The invariant is
   documentation-only today; a cheap enforcement exists — a
   `serverbuildplatform` unit test asserting the four `PolicyStore`s wrap
   distinct limiter instances.
2. *Bare-key reservation.* `"admin"` (tier-1) and `admin:<subject>`
   (tier-2) live in different stores today, so no collision; but a future
   tier consolidation would put a bare key inside a namespace where
   credentialed actors own `admin:*`. The invariant doc should reserve the
   bare keyspace for pre-auth tiers. (The same applies to `"sub"`-vs-`sub:`:
   today the userinfo store's IP fallback keys are bare IPs and the
   credentialed keys are `sub:*`; a bare-IP value can never equal a
   `sub:`-prefixed value, so this is a forward-looking reservation, not a
   live hazard.)

## 3. Admin tier-1 rekeying is load-bearing — Verified, with one conditionality gap

**Verified.** Today: constant key `"admin"` (`governance.go:275-280`),
checked pre-auth (`middleware.go:330`), one shared bucket; admin A's
authenticated flood starves admin B at tier-1 before B ever authenticates.
Per-IP tier-1 is therefore *required* for the tier-2 per-admin promise to
hold. The design's argument is correct, and the accepted tradeoff
(distributed spray now bounded per-IP, not globally) matches the phase-1
doctrine.

**Missing — the tier-1 store is conditional.** `wireAdminMW` calls
`mw.SetRateLimit` only when `srv.AdminRateLimit() > 0`
(`cmd/sso-server/build_app.go:305-307`), and `WithAdminRateLimit` is opt-in
(`options_httpstack.go:174-175`) — there is no default admin rate limit.
An operator who configures only `admin.rate_limit.per_admin.*` therefore
has a **nil tier-1 store → tier-1 unlimited**; "configuring per_admin also
switches tier-1 to per-IP" is then a no-op. That outcome is *fine* (no
global bucket exists to starve B), but the design should state it: the
rekey applies to an existing `admin.rate_limit.*` store, and the
"load-bearing" property only exists in the *combination* configuration.
The e2e must configure both blocks.

**Precision fix — e2e sizing.** With both tiers configured, A flooding at
rate R from the shared NAT IP consumes the per-IP tier-1 bucket; B's
requests pass tier-1 only while the *aggregate* (A+B) stays under the
per-IP budget. The verification-mapping line "tier-1 sized above A's flood
rate" should read "sized above A's flood rate **plus B's test traffic**"
(the failure-table row already half-says this).

**Restated tradeoff.** Per-IP tier-1 means the unauthenticated aggregate
bound on the *control plane* is now N-source-IPs × per-IP budget (today:
one global budget). For an admin surface this is a materially weaker
spray bound than for SSO. Optional hardening: keep a global cap alongside
the per-IP key (two pre-auth tiers: per-IP coarse + global cap sized well
above any single legitimate admin's rate) — that restores the botnet bound
without breaking the shared-NAT acceptance. At minimum, the N× math should
appear in config-reference.

## 4. Oracle-safe 429 shapes — Verified, all four surfaces clean

**Verified, current state.** `writeTooManyRequests`: `application/json`,
`{"error":"rate_limited"}`, Retry-After ceiling-rounded ≥1
(`interfaces/ratelimit/middleware.go:172-189`, `consts.go:23-26`). Admin
today: `http.Error` → `text/plain`, body
`{"error":"rate_limit_exceeded"}\n` (trailing newline, `governance.go:306-330`).
Grant limiter today: 429 + `errorBody(ErrUnsupportedGrantType)`, no
Retry-After (`server_token.go:365-373`). Both drifts are real; both fixes
are spec-mandated (`docs/error-codes.md:921` documents `rate_limited` as
the SPA-branchable 429 code). The byte-identical-default acceptance holds:
unconfigured admin is untouched; configured mode moves *both* tiers to the
canonical JSON shape — the design's 429 table is accurate, including the
subtle point that tier-1's wire also changes in configured mode (this is
implied by "both tiers" and should be called out once explicitly, since the
unconfigured/configured asymmetry is easy to misread as tier-1-unchanged).

Cross-party oracle analysis of the new 429s, all **Verified clean**:

- `/token` client bucket: only client-auth-success consumes. The
  precedence change (429 now beats `403 tenant_mismatch` / `400
  unauthorized_client` / FAPI rejects for rate-limited authenticated
  clients) is observable only by the credentialed requester about their
  own bucket — inherent to post-auth limiting, and worth one sentence in
  the design as intended behavior.
- `/userinfo`: sub-keyed buckets are fillable only by the subject's own
  valid tokens (validation precedes the checkpoint, `handle_userinfo.go:50-58`);
  pairwise subs keep keys unguessable; 429-vs-403-residency reveals
  nothing about residency state (checkpoint precedes the residency read;
  a requester can always stop flooding to learn their own residency
  outcome — no new channel).
- Admin tier-2: post-auth, pre-idle-timeout (`middleware.go:325-349`
  ordering). Once rate-limited, the shape is constant across
  session-expiry states — the design's no-new-expiry-oracle claim is
  exact. (Pre-flood, 401-vs-200 expiry signaling is pre-existing and
  unchanged.)
- Retry-After reveals bucket deficit to the requester only.

**The one genuine side channel is the shared-IP bucket**: on phase-1
(pre-existing) and on the new phase-2 public-client fallback, same-NAT
actors modulate each other's 429 probability — victim activity raises the
attacker's 429 rate. Inherited, not new, and inherent to IP keying; one
sentence in the design makes it a conscious residual.

## 5. Checkpoint-before-residency: no timing or state leak — Verified, one placement correction

**`/token` — Verified.** Ordering in `handleToken` (`server_token.go:17-46`)
is exactly as claimed: the checkpoint lands between `authenticateTokenClient`
and `residencyGateTokenGrant`, i.e. before residency store reads, FAPI
(audit spam), idempotency-cache writes, and the grant handler. The
rate-limited path skips all of that — a *faster* path, but its timing is
observable only by the requester about their own bucket. Residency
fail-open (governance) and limiter fail-open are independent; no
state-distinguishing interaction during outages. Rate-limited replays are
not cached by the idempotency capture (checkpoint precedes
`beginTokenIdempotency`), so a refilled bucket lets the replay proceed to
the grant and fail `invalid_grant` — consistent, no replay-oracle.

**`/userinfo` — Verified.** The hooks land exactly between
`authenticateUserInfoBearer` success and `ResidencyDeniedForAccess`
(`protocols/oidc/handle_userinfo.go:41-58`), i.e. before
`ResolveLocalSubject`/`GetByID` — the store reads the limiter protects are
genuinely protected. Key = `claims.Subject` (the wire sub) is the right
choice: the local ID is not yet known, and pairwise subs alias one user
into a bounded handful of buckets. Cross-tenant sub collision is
negligible (user IDs are UUIDv4 — `internal/adminuser/service.go:347-349`),
with one documented exception: setup-provisioned accounts use the username
as ID (`server_setup.go:202-206`), so two tenants with the same setup
username would share a bucket; single-tenant bootstrap in practice, worth
one line in config-reference.

**Mesh — the one substantive correction.** `MeshAuthorize` internally runs
`deriveMeshIdentity` → `resolveLocalSubject` + `permissions.Roles`
(`interfaces/sso/mesh_authz.go:309-330`) — the exact user lookup the
design's "mirrors /userinfo" framing claims to protect — *before* the
proposed checkpoint (which sits between `MeshAuthorize` and
`writeMeshAuthzResponse`). The mesh checkpoint therefore bounds neither
the validation CPU nor the lookup; it bounds only the endpoint's response
work, per subject. The fairness property (one flooding subject cannot
starve other subjects' mesh decisions) still holds, and the HTTP-wrapper
placement is the right layering call — the gRPC ext_authz module reuses
`MeshAuthorize` and must not inherit an sso-owned store — but the design's
cost-bounding rationale must be restated for mesh, or a future reader will
"fix" the placement by moving the checkpoint into the dep-free seam.

**Timing, summary.** No cross-party timing channel exists on any surface:
every bucket is chargeable only by (a) the requester's own credentials or
(b) shared-IP peers (the pre-existing channel of §4). Checkpoint-before-
residency leaks neither timing nor state; the ordering is in fact the
design's best property (cost-bounding before store work, constant 429
shape before stateful gates).

## 6. Corrections and residuals (design doc deltas)

| # | Severity | Item | Action |
|---|---|---|---|
| 1 | Medium (doc) | Mesh checkpoint cost-bounding claim (§5) | Restate: mesh checkpoint protects response work only; validation + roles lookup already ran inside `MeshAuthorize`; fairness property unchanged; keep HTTP-wrapper placement |
| 2 | Medium (doc) | `HandlerContext` ripple undercounts: four production implementations, not two — `core.Context` (`shared/core/router.go:111-128`), `backgroundHandlerContext` (`interfaces/sso/sso_wiring.go:304`), `ginContext` (`interfaces/adapters/gin/adapter.go:171`), `echoContext` (`interfaces/adapters/echo/adapter.go:196`). The binary uses `sso.NewStdRouter` (`cmd/sso-server/build_app_core.go:155`), so only `core.Context` matters today, but the SDK-facing adapters break compile too. The "compile error lists them all" mitigation holds; `SetRequest` is trivial on all four (gin: field assignment on the embedded `*gin.Context`; echo: `echo.Context.SetRequest` via the embedded interface) | Name all four in the ripple list so the change is planned, not discovered at compile time |
| 3 | Medium (doc) | Tier-1 store is conditional: per_admin-only config leaves tier-1 nil/unlimited; "rekeying is load-bearing" applies only to the combination config (§3) | State it; e2e configures both blocks |
| 4 | Low (doc) | E2E sizing must be "tier-1 per-IP budget > A's flood + B's test traffic", not just "> A's flood rate" (§3) | Fix the verification-mapping line |
| 5 | Low (doc) | Public-client fallback delivers zero marginal protection (replay of one valid code burns the shared IP bucket; phase-1 already bounds it) (§1) | Say it in config-reference |
| 6 | Low (doc) | Shared-IP side channel (victim activity modulates same-NAT attacker's 429 rate) — pre-existing, inherited by the fallback (§4) | One sentence as conscious residual |
| 7 | Low (doc) | Extend "never share an instance" to all four stores (admin tier-1 keys are bare IPs after rekey — same strings as SSO phase-1) + reserve the bare keyspace for pre-auth tiers (§2) | Extend the invariant paragraph; optional `serverbuildplatform` distinct-instance unit test |
| 8 | Low (doc) | Fail-open is silent: both `SQLiteLimiter.Allow` (`sqlite_limiter.go:145-158`) and the Redis `Limiter.Allow` (`infrastructure/redis/ratelimit.go:121-135`) return `(true, 0)` with no log on error. The design's "fail-open-with-log doctrine" phrasing overstates the codebase for this subsystem | Either log once in the backends' error paths (tiny change) or state "silent fail-open, unchanged from phase-1" |
| 9 | Low (doc) | `KeyByClientID` (new, safe, post-auth) vs `KeyByClientIDOrIP` (UNSAFE, pre-auth) name proximity | Doc comment on the new function must carry the authenticated-only warning and cross-reference the UNSAFE sibling |
| 10 | Low (doc) | 429-vs-400/403 precedence change on `/token` for rate-limited authenticated clients (§4) | One sentence as intended behavior |
| 11 | Low (doc) | Setup-account username-as-ID sub collision across tenants (§5) | One line in config-reference |

No decision in the design needs to change. Items 1-3 are corrections to
claims; 4-11 are precision/residual statements that should land in the
same commit as the config-reference/error-codes updates (AGENTS.md §5.6),
not as separate "while here" work.
