# Design: interfaces/grpcserver — Transport-level governance parity for the gRPC admin plane

> Companion to `docs/auto/interfaces-grpcserver-transport-governance-spec.md`
> (direction 1 of `docs/auto/interfaces-grpcserver-analysis.md`). Design only —
> no code was modified. Every file/line cited was re-verified against the
> executable code at the current commit.
>
> The three improvements are one coherent change: a single transport-agnostic
> governance gate that both transports invoke (D1), the two HTTP-only controls
> (destructive confirmation, idle timeout) re-expressed on that gate for gRPC
> (D2, D3), and a startup posture that can no longer silently ship an
> ungoverned or plaintext gRPC plane (D4). Each `##` decision covers API
> surface, storage model, failure modes, and what could break the design.

**Fixed constraints discovered while verifying (bind every decision):**

- `interfaces/admin` has exactly 10 non-test files — the fan-out ceiling
  (`AGENTS.md` §2, frozen). **No new file may be added to the package.** All
  gate code lands in existing files, so the ~155–190 lines of new production
  code must be balanced against the 500-line file budget: `middleware.go`
  (492, headroom 8) and `governance.go` (483, headroom 17) are both near the
  cap, and every other file is within 64 lines of it except `deps.go` (177,
  headroom 323). The only viable rebalance is moving the generic
  change-approval HTTP handler block (~200 lines: the section at
  `governance.go:30` through `recordChangeEvent`, ending before the
  "Transport-level governance checks" section at `governance.go:231`) into
  `deps.go` — that block
  is Deps-typed handler code, the same shape as `deps.go`'s stated role
  ("what the admin management-plane handlers need"), and `deps.go` then
  lands at ~375 lines. The freed space in `governance.go` hosts the shared
  gate, the pure predicates, and the RPC→HTTP mapping table (net result:
  `governance.go` ≈ 480, `middleware.go` ≈ 472 — both under the cap with
  margin).
- `interfaces/grpcserver/grpcadmin` is at its 10-file fan-out ceiling and is
  out of scope anyway (direction 2 debt, per the spec); the interceptors
  stay in `interfaces/admin/middleware.go` and all wiring in
  `cmd/sso-server/main_servers.go` / `build_app.go`.
- The HTTP chain order is fixed and documented (`middleware.go:317-345`):
  `checkIPPolicy` → `checkRateLimit` → `checkDestructiveConfirm` → bearer
  auth → `enforceIdleTimeout` → `checkWriteQuota`. The gRPC gate must
  reproduce this order exactly. Because IP policy, rate limit, and
  confirmation need no claims, the gate splits naturally into a pre-auth
  phase and a post-auth phase — see D1 (the spec's minimal call-site
  "immediately after `authorizeGRPC`" would reorder the first three checks
  after auth; the split preserves the documented order and the
  "disallowed network never reaches auth machinery" property
  (`governance.go:330-334`) on both transports).
- `authorizeGRPC` (`middleware.go:220-252`) already resolves the claims
  (JTI included) and actor; the interceptor is the only gRPC execution path,
  shared by unary and stream (`middleware.go:262,298`). Governance state
  (`rateLimitStore`, `ipPolicy`, `quota`, `destructive`, `sessionTTL`,
  `adminTokenStore`) already lives on the shared `Middleware`
  (`middleware.go:76-98`), wired at `cmd/sso-server/build_app.go:309-338` —
  gRPC has the data; only the execution path is missing.
- `DestructiveSet.Match(method, path)` (`platform/lifecycle/admingovernance/destructive.go:31-37`)
  matches HTTP-method + path **prefix**. The canonical RPC→(HTTP method,
  path) mapping exists today in the proto `google.api.http` annotations
  (`proto/admin/v1/*.proto`); the grpc-gateway surface already applies the
  confirmation guard through those paths (`build_http.go` →
  `HTTPMiddleware`). A conformance test can parse the proto files to catch
  mapping drift (see D2). Audit and netpolicy RPCs carry no `google.api.http`
  annotations, so their table entries are hand-derived and unit-tested.
- gRPC metadata keys arrive lower-cased on the server (`grpc-metadata-x-confirm`
  is received as `x-confirm`); `HeaderConfirm = "X-Confirm"`
  (`governance.go:255`) is reused via `strings.ToLower`.
- `geo.DefaultIPExtractor` is `*http.Request`-shaped (`platform/geo/middleware.go:130`)
  and honors XFF — safe on HTTP only because the trusted-proxy chain strips
  and re-sets XFF upstream (`security.trusted_proxies` per AGENTS.md §3). On
  gRPC the only trustworthy source is the transport peer address
  (`peer.FromContext`; precedent at
  `interfaces/grpcserver/grpcadmin/admin_paginate.go:228`). gRPC metadata is
  client-controlled and must never be trusted for IP policy.
- No new storage: the gate composes the existing
  `ratelimit.PolicyStore` (memory/sqlite backends), `WriteQuotaStore`
  (`MemoryWriteQuotaStore` today, durable backends allowed by the
  interface), `core.AdminTokenStore` (`GetByID`/`Touch`), `DestructiveSet`,
  and `geo.Provider`. Zero schema or migration surface.
- e2e gRPC harness precedent exists (`test/admin_grpc_base_test.go`,
  bufconn + `insecure.NewCredentials()`); startup tests can reuse the
  config-level harness in `cmd/sso-server`.
- `-grpc-listen` defaults to `:8081` (enabled, `cmd/sso-server/main_wiring.go:59`);
  TLS is added only when both `-tls-cert` and `-tls-key` are non-empty
  (`cmd/sso-server/main_servers.go:170-181`). Self-signed-cert generation
  precedent exists in tests (`x509.CreateCertificate`, e.g.
  `interfaces/sso/header_client_cert_extractor_test.go:35`) but nowhere in
  production code — the ephemeral-cert path is new production code in
  `cmd/sso-server`.

---

## Decision 1 — One shared governance gate, invoked by both transports in HTTP order

**Rule.** Add one transport-agnostic gate to the shared `Middleware` with two
phases, so the HTTP order is preserved exactly and the two transports can
never drift again:

```text
preAuthGRPC(ctx, fullMethod) error        // IP policy → rate limit → confirm
authorizeGRPC(ctx, fullMethod)            // unchanged (bearer + scope)
postAuthGRPC(ctx, fullMethod, claims) error  // idle timeout → write quota
```

Both `UnaryServerInterceptor` and `StreamServerInterceptor` call
`preAuthGRPC` before `authorizeGRPC` and `postAuthGRPC` after it, on gated
methods only (`isGatedGRPCMethod`, unchanged). Streams run both phases once
at stream open; the write quota charges one unit per stream (not per
message), and idle `Touch` happens at open and close (bounded).

**API surface.**

- New unexported methods on `admin.Middleware` (in `governance.go`):
  - `preAuthGRPC(ctx, fullMethod) error` — `checkIPPolicy` on the peer IP,
    `checkRateLimit` on the shared bucket, `checkDestructiveConfirm` via the
    D2 mapping; returns a `*status.Status` error or nil.
  - `postAuthGRPC(ctx, fullMethod, claims) error` — idle timeout via
    `adminTokenStore.GetByID`/`Touch` (D3), then write quota for
    `admin:write`-scoped RPCs; returns a `*status.Status` error or nil.
- The four HTTP checks in `governance.go` are refactored into pure
  predicates with thin HTTP wrappers, so `HTTPMiddleware` stays
  byte-identical while the predicates are shared:
  - `rateLimitDenied(store) (retryAfter time.Duration, denied bool)` —
    wrapper keeps writing `Retry-After` + the 429 JSON body.
  - `ipPolicyDenied(ctx, ip net.IP, p) bool` — wrapper keeps extracting the
    IP via `geo.DefaultIPExtractor(r)` and writing the 403 body. The gRPC
    side extracts the IP from `peer.FromContext(ctx).Addr` via
    `net.SplitHostPort`; **no XFF/forwarded metadata is ever honored on
    gRPC** (client-controlled metadata would be an IP-policy bypass).
  - `writeQuotaDenied(ctx, q, isWrite, actorID, tenantHint) (resetAt, denied)`
    — wrapper keeps the 429 body + `Retry-After`.
  - `checkDestructiveConfirm` gains a gRPC-side sibling `confirmDeniedGRPC(fullMethod, md)`.
- Error mapping (constant per class, oracle-safe — denial text carries no
  per-cause detail):
  | Check | gRPC code | Constant message | HTTP today |
  |---|---|---|---|
  | IP policy | `PermissionDenied` | `admin_ip_denied` | 403 JSON literal |
  | Rate limit | `ResourceExhausted` | `rate_limit_exceeded` | 429 + `Retry-After` |
  | Write quota | `ResourceExhausted` | `admin_write_quota_exceeded` | 429 + `Retry-After` |
  | Destructive confirm | `FailedPrecondition` | `destructive_confirmation_required` | 409 JSON literal |
  | Idle/expired | `Unauthenticated` | `session_expired` | 401 JSON literal |
  `Retry-After` has no gRPC equivalent; trailers were considered and
  rejected (non-standard, and an oracle when per-rule). The status code +
  constant message is the whole wire signal; details go to audit only
  (`EventAdminGRPCCalled` metadata, bounded reason set:
  `rate_limited`, `ip_denied`, `quota_exceeded`, `confirm_required`,
  `session_expired` — mirrored in `docs/observability.md`).
- New exported accessor `GovernanceConfigured() bool` (any of
  `quota`/`ipPolicy`/`destructive`/`rateLimitStore`/`sessionTTL` non-zero)
  and `GRPCGovernanceArmed() bool` (true only after the gated interceptors
  were constructed — see D4). These are the fail-closed guard's inputs.
- Budget mechanics: the gate + predicates + mapping table (~155–190 lines
  net; the predicate refactor is mostly line-neutral — the existing check
  bodies become the predicates)
  go into `governance.go` after the ~200-line approval-handler block moves
  to `deps.go`; the small interceptor additions (+~20 lines) and the
  relocated `bearerFromMetadata` + actor helpers (−40 lines, moving to
  `governance.go` with the gate) keep `middleware.go` under 500. Both files
  stay under the cap with margin (see constraints above).

**Storage model.** None new. The gate is stateless; it composes the stores
already on the `Middleware`:
- `rateLimitStore` — one shared bucket key `adminRateLimitKey`
  (`governance.go:272`), so HTTP and gRPC admin traffic now draw from the
  same token bucket (this is the intended semantics of "shared"; see What
  could break).
- `quota` — `WriteQuotaStore.Consume` keyed by
  `admingovernance.QuotaKey(keyBy, actorID, tenantHint)`; the
  `tenantHint` comes from `claims.Extra[core.KeyTenantID]` exactly as on
  HTTP (`tenantHintFromClaims`). Write-scope is decided by
  `scopeForGRPC(fullMethod) == ScopeWrite` — the same classification that
  decided the authz grant, so the gate cannot disagree with itself.
- `ipPolicy` — `admingovernance.Allowed(ip, geoInfo, cfg)` unchanged; the
  `geo.Provider` lookup reuses `srv.GeoProvider()` (already wired).
- Store outages fail open exactly as today (nil checks; `Consume` error →
  `Allowed=false` path on HTTP is written as a 429; see D1 failure modes).

**Failure modes.**

- Denial ordering is identical to HTTP: a request that would fail IP policy
  on HTTP fails `PermissionDenied` on gRPC before any token work; rate-limit
  exhaustion is `ResourceExhausted` before auth; quota is checked after auth
  and only for write-scoped RPCs.
- `peer.FromContext` absent/nil (defensive): treat as IP-policy denial when
  an IP policy is configured (fail closed — an unobservable peer must not
  bypass an allowlist), pass otherwise. `net.SplitHostPort` failure on the
  peer address: same fail-closed treatment.
- Store errors: `rateLimitDenied` with a failing limiter returns denied
  (429 semantics preserved); `writeQuotaDenied` on store error returns
  denied with no `ResetAt` (matches HTTP's `err != nil || !res.Allowed`
  branch, `governance.go:406-414`); idle-timeout store error fails open
  (matches `enforceIdleTimeout`'s `err == nil &&` guard,
  `middleware.go:395-403`).

**What could break the design.**

- **Shared-bucket coupling changes HTTP availability.** Today gRPC consumes
  zero rate-limit budget; after D1, automation traffic drains the same
  `admin` bucket as UI admins, so HTTP admins can observe earlier 429s.
  Per-request HTTP behavior is byte-identical, but aggregate behavior is
  not. This is the point of the feature, but operators must size
  `admin_rate_limit` with the gRPC workload included; document it in
  `docs/config-reference.md`.
- **Order drift between transports.** The split phases depend on the
  interceptor calling both phases around `authorizeGRPC`. If a future
  refactor drops a phase, HTTP and gRPC silently diverge again. Mitigation:
  `GRPCGovernanceArmed()` is set only when both phases are attached, and D4's
  startup guard refuses to start with governance configured but the gate
  unarmed — drift becomes a startup error, not a silent gap.
- **Oracle widening.** If any denial message starts embedding per-rule
  detail (e.g. the destructive rule's `Action` label), the gRPC surface
  becomes a confirmation oracle. The constant-message table above is the
  contract; the unit tests assert byte-identical strings across rules.
- **File budgets.** The relocation is load-bearing: if the approval block
  does not move out of `governance.go`, the gate code pushes it past 500 and
  the change is unmergeable. `deps.go` absorbing handler code is a cohesion
  cost, not a correctness one; the alternative (moving transport checks into
  `deps.go`) would be worse.
- **IPv6 / proxy topologies on gRPC.** gRPC sees the transport peer only.
  An operator whose gRPC clients sit behind a load balancer must allowlist
  the LB egress IPs, not client IPs; XFF-style trust on gRPC is
  deliberately refused. Documented as a first-class difference.

## Decision 2 — Destructive confirmation on gRPC via a canonical RPC→(method, path) map

**Rule.** The confirmation gate is defined by the operator's existing
`(method, path_prefix)` rules (`admin_destructive_actions`), so the gRPC
surface must present each RPC as the (HTTP method, canonical path) the
gateway would use for it. That mapping already exists authoritatively in the
proto `google.api.http` annotations; the design mirrors it into a static
table beside `isGatedGRPCMethod`, with a conformance test that re-derives
the table from the proto sources so it cannot silently rot.

**API surface.**

- Wire convention: gRPC clients send `grpc-metadata-x-confirm: true`
  (server-side key `x-confirm`; read via `md.Get(strings.ToLower(HeaderConfirm))`,
  value matched `strings.EqualFold(..., "true")` — same acceptance rule as
  the HTTP header). Checked once per stream at open, in `preAuthGRPC`.
- Matching: for a gated RPC with mapped `(method, canonicalPath)`, run
  `set.Match(method, canonicalPath)` (unchanged `DestructiveSet.Match`).
  Because rules match by path **prefix**, the canonical template path
  (`/api/v1/admin/tenants/{id}`) is matched directly — a rule with
  `path_prefix: /api/v1/admin/tenants/` catches every tenant-id RPC exactly
  as it does on the gateway path.
- Mapping table (`governance.go`):
  `var grpcMethodHTTP = map[string][2]string{ "/snaplink.admin.v1.TenantAdminService/DeleteTenant": {"DELETE", "/api/v1/admin/tenants/{id}"}, ... }`
  covering every gated RPC of the annotated admin services (~50 entries,
  derived from `proto/admin/v1/*.proto`). Entries for
  `audit.v1.AuditWriter` and `netpolicy.v1.PolicyService` (no annotations;
  `StreamEvents`/`Record` → `POST /api/v1/audit/`, `Apply`/`Delete` →
  `POST|DELETE /api/v1/netpolicy/policies`) are hand-derived and
  unit-tested. Read-scoped RPCs still get table entries (the drift test
  requires completeness) but are never matched by write-method rules.
- Conformance test (in `interfaces/admin`, `_test.go` — test files do not
  count against the fan-out ceiling): parse `../../proto/admin/v1/*.proto`
  (regex over `rpc Name` + the first `option (google.api.http)` verb/path),
  assert the table is exactly the annotation set. Any new RPC or changed
  path fails the build until the table is updated — the drift is a
  compile-time-style test failure, not a silent guard gap.
- Failure semantics: absent/not-true on a matched mutation →
  `FailedPrecondition` with the constant string
  `destructive_confirmation_required`, identical for every rule (no rule
  `Action` label on the wire); detail in `EventAdminGRPCCalled` metadata
  only. Non-matching RPCs pass untouched.

**Storage model.** None. `DestructiveSet` is immutable config captured at
wiring (`SetDestructiveActions`, `build_app.go:338`); the table is a
`var` map in `governance.go`.

**Failure modes.**

- Rule matches a read RPC: impossible by construction (rules carry HTTP
  methods; the mapped verbs for reads are GET). Rule path prefix matches
  nothing on gRPC (e.g. operator wrote a path for an RPC that has no table
  entry): the RPC passes — same as an HTTP path that matches no rule. No
  startup error for unmatched rules (identical to today's HTTP posture).
- Duplicate/conflicting rule set: first-match-wins is already defined in
  `DestructiveSet.Match`; unchanged.
- Metadata absent on a matched mutation: `FailedPrecondition` — the
  expected denial, indistinguishable from a wrong value.

**What could break the design.**

- **Mapping drift is the cardinal risk.** A proto annotation change (new
  RPC, renamed path) without a table update means the guard silently misses
  the new mutation (fail-open) or matches a stale path (false positive).
  The conformance test is the mitigation and is mandatory, not optional;
  it also enforces that the table never grows beyond the annotated surface.
- **Hand-derived audit/netpolicy entries.** These have no proto annotation
  to re-derive from; a future RPC in those services is unguarded until
  someone adds a table entry. Mitigation: the conformance test asserts every
  `isGatedGRPCMethod` prefix family is represented, and the D4 startup guard
  could warn on configured rules that match no gRPC method — deliberately a
  warning, not an error, because rules are also used by the HTTP surface.
- **Verb ambiguity.** Proto `post:`/`put:` are explicit, so there is no
  PUT-vs-PATCH guessing; the table stores the annotation verb verbatim.
  `SetTenantStatus` (`post: /api/v1/admin/tenants/{id}:set-status`) is a
  POST, not a PUT — the table must mirror the annotation exactly, which is
  why the conformance test compares full method+path, not just presence.
- **Rule semantics differ between transports for prefix granularity.**
  On HTTP, a rule prefix can target one concrete route (e.g.
  `/api/v1/admin/tenants/:id/domains` — actually `/api/v1/admin/tenants/{id}/domains`
  in gateway form). On gRPC the template path from the annotation preserves
  the same granularity, so rule expressiveness is equal; the test must
  include one prefix-granularity case per resource family.

## Decision 3 — Idle timeout and token Touch on the gRPC plane

**Rule.** `authorizeGRPC`'s caller path already resolves claims; the
post-auth phase enforces the same idle-timeout semantics as HTTP
(`middleware.go:395-403`): when `sessionTTL > 0`, `adminTokenStore != nil`,
and `claims.JTI != ""`, `GetByID` and reject expired/revoked with
`Unauthenticated` (`session_expired`), then `Touch`. Streams additionally
`Touch` on close. Store-error behavior mirrors HTTP exactly (fail open).

**API surface.**

- No new public API. `postAuthGRPC` calls the existing
  `core.AdminTokenStore.GetByID(ctx, claims.JTI)` and
  `Touch(ctx, claims.JTI)`; the HTTP `enforceIdleTimeout` is refactored to
  share the same pure helper (`idleExpired(ctx, store, jti, ttl) (expired bool)`
  + `touchToken(ctx, store, jti)`), keeping its exact fail-open shape
  (`GetByID` error → not expired → proceed, then touch).
- Revoked tokens: `GetByID` returning "not found"/revoked is treated as
  expired → `Unauthenticated` (matches HTTP's contract where the store's
  absence of the token means no valid session; the oracle-safe constant
  string is the same).
- Stream lifecycle: touch at open (post-auth) and once at close (in
  `StreamServerInterceptor`, after the handler returns — bounded at two
  store writes per stream, never per message). A stream that failed
  authorization never touches (auth happens before the gate).
- `docs/config-reference.md` gains the note that the admin session controls
  (the `WithAdminTokenStore`/`WithAdminSessionTTL` `sso.Option`s, surfaced
  via `Server.AdminTokenStore()`/`AdminSessionTTL()` and wired at
  `cmd/sso-server/build_app.go:309-311`) now apply to the native gRPC
  plane, and `docs/observability.md` gains the `session_expired` audit
  reason.

**Storage model.** `core.AdminTokenStore` unchanged (`GetByID`, `Touch` —
see `shared/core/admin_token.go:37`). No schema change; `LastUsedAt`
semantics are identical on both transports.

**Failure modes.**

- Store outage → fail open (proceed without rejecting), identical to HTTP —
  an admin plane must not lock out operators because the token-metadata
  store is down; audit records the touch failure.
- `JTI` empty (tokens minted without one, or non-admin flows): skip
  entirely, identical to HTTP.
- Expired token: `Unauthenticated` — indistinguishable from a bad token to
  the caller (same constant string as `authorizeGRPC`'s invalid-token
  branch), preserving oracle safety for the session store.

**What could break the design.**

- **Automation tokens now expire.** Long-lived automation tokens that never
  hit HTTP admin endpoints previously never idled out; after D3 they do.
  This is the point of the improvement, but the design must document the
  operational consequence (renewal loops in scripts) in
  `docs/config-reference.md`; e2e must prove an idle-expired token is
  rejected identically via native gRPC and gateway REST.
- **Touch on close for long-lived streams.** A `Watch` stream that runs for
  days keeps the token alive via close-touch only at the end; the open-touch
  is the operative one. If a stream outlives `sessionTTL` with no other
  traffic, the token expires mid-stream — the stream itself is NOT torn
  down (gRPC has no mid-stream authz hook in this design; the gate runs at
  open). Document: idle expiry is enforced at call open, not mid-stream;
  terminating mid-stream on expiry is deliberately out of scope (would
  require per-message touch, violating the bounded-writes constraint).
- **Touch write amplification.** Two writes per stream, one per unary call —
  bounded, but automation-heavy deployments now write `LastUsedAt` for
  every gRPC admin call. The existing HTTP path already pays this cost; the
  design accepts the same cost on gRPC rather than adding a cache (a cache
  would reintroduce the idle-expiry bypass the improvement exists to close).

## Decision 4 — Transport hardening: TLS never silently optional, governance never silently unwired

**Rule.** Two startup invariants in `cmd/sso-server`:

1. **TLS posture** — when the gRPC listener is enabled (`-grpc-listen`
   non-empty) and no `-tls-cert`/`-tls-key` are supplied, the server must
   not silently serve plaintext. The new `admin.grpc_tls` knob
   (`docs/config-reference.md`, new section under `admin.*`) selects:
   - `required` (default): startup **refuses** with an explicit error naming
     the missing certificate pair — the fail-closed default.
   - `ephemeral`: start with an auto-generated self-signed ECDSA P-256
     certificate (SANs `127.0.0.1`, `::1`, `localhost`), logging the
     SHA-256 fingerprint at startup; documented for local/dev only (remote
     automation must pin real certs; a fingerprint that changes every
     restart is not an operational credential).
   - `plaintext`: explicit, documented-as-unsafe opt-out for legacy
     loopback/trusted-network deployments; requires `admin.grpc_tls:
     plaintext` in config — never the absence of config.
2. **Governance arming guard** — `startGRPCServer` validates, before
   binding the listener: if `a.adminMW != nil` and
   `a.adminMW.GovernanceConfigured()` and the listener is enabled, then
   `a.adminMW.GRPCGovernanceArmed()` must be true; otherwise startup fails
   with an error naming the control(s) that would be ungoverned on gRPC.
   `GRPCGovernanceArmed()` is set to true only by the gated interceptor
   construction path (D1), so a future refactor that detaches the gate from
   the chain turns into a startup error, not silent drift.

**API surface.**

- `config/config_admin.go`: `AdminConfig` gains
  `GRPCTLS string \`yaml:"grpc_tls"\``; empty string is normalized to
  `required` at load (the default must be explicit in code, not in the
  zero value). Validation: unknown value → config error at startup.
- `cmd/sso-server/main_servers.go`: `grpcServerOptions`/`startGRPCServer`
  take the resolved posture (cert pair + knob); new helpers
  `ephemeralServerCert() (tls.Certificate, fingerprint string, err error)`
  (stdlib `crypto/x509` + `crypto/ecdsa` only — no new dependencies) and
  `validateGRPCTransport(a, grpcListen, cfg) error` performing both
  invariants before `net.Listen`.
- `interfaces/admin/middleware.go`: `GovernanceConfigured()` and
  `GRPCGovernanceArmed()` accessors (armed flag flipped in
  `UnaryServerInterceptor()`/`StreamServerInterceptor()` construction).
- `docs/deployment.md`: the `:8081` row gains the TLS-default change and
  the migration path (supply `-tls-cert/-tls-key` or set
  `admin.grpc_tls: plaintext` explicitly).

**Storage model.** None. The ephemeral certificate is in-memory for the
process lifetime; no persistence, no key file, no rotation (restart
regenerates — acceptable because ephemeral is a dev posture, not a
production credential).

**Failure modes.**

- `required` + no certs → hard startup error, process exits. Operators
  relying on plaintext loopback automation see an immediate, named failure
  at boot (the intended fail-closed behavior).
- `ephemeral` + cert generation failure (entropy/rand failure) → startup
  error (never silently fall back to plaintext).
- Governance configured + gate unarmed → startup error naming the control;
  this branch is unreachable in the current design (arming is
  unconditional) and exists as the regression tripwire.
- `admin.grpc_tls` set while gRPC disabled (`-grpc-listen ''`): knob is
  inert; no error (enablement is the flag's job, posture is the config's
  job — documented precedence).

**What could break the design.**

- **Existing plaintext deployments stop booting.** This is the point, but
  it is a breaking default change; the migration path (explicit
  `plaintext` or certs) must be in the release notes and
  `docs/deployment.md`. Any e2e that boots the real binary with gRPC
  enabled and no certs must set the knob or supply certs — the test
  harness change is part of this design.
- **Ephemeral false security.** If clients disable verification to consume
  the ephemeral cert, the deployment is *less* secure than honest
  plaintext (silent MITM). The design mitigates by logging the fingerprint
  and documenting that ephemeral is for local development; `required` stays
  the default.
- **Guard depends on interceptor construction.** If a future refactor
  constructs the interceptors without flipping the armed flag, the guard
  fires — correct. If a refactor flips the flag without attaching the gate,
  the guard is a lie; the flag is set only inside the interceptor
  constructors themselves, so the two cannot separate without the diff
  being visible in review.
- **Config/flag duality.** `-grpc-listen` (flag) + `admin.grpc_tls`
  (config) is two places to get wrong. Accepted: enablement is
  deployment-shape (flag, consistent with `-tls-cert/-tls-key`), posture is
  governance policy (config, consistent with the other `admin_*` sections);
  the precedence rule is documented and unit-tested.
- **`Admin.Enabled=false` case.** `adminMW` is nil, so no admin/audit/
  netpolicy services register on gRPC at all (`main_servers.go:198-201`) —
  the governance guard is vacuously satisfied and TLS posture still applies
  (authz/discovery RPCs remain on the listener). The TLS rule is
  independent of admin enablement, deliberately.

---

## Cross-cutting: contracts, tests, and gates

- **Contract docs in the same change** (AGENTS.md §5): `docs/config-reference.md`
  (new `admin.grpc_tls` knob + statement that `admin_rate_limit` /
  `admin_write_quota` / `admin_ip_allowlist` / `admin_destructive_actions`
  and the `WithAdminSessionTTL`/`WithAdminTokenStore` options now apply to
  the native gRPC plane + the
  `grpc-metadata-x-confirm` convention + shared-bucket sizing note);
  `docs/error-codes.md` (no new `Err*` — the gRPC denials reuse the
  existing literal strings as constant status messages; the HTTP surface
  is byte-identical); `docs/observability.md` (bounded audit reasons
  `rate_limited`, `ip_denied`, `quota_exceeded`, `confirm_required`,
  `session_expired` on `EventAdminGRPCCalled`); OpenAPI (note the
  `grpc-metadata-x-confirm` convention for clients of the gateway-proxied
  services); `docs/deployment.md` (TLS-default change).
- **Unit tests** (`interfaces/admin`, package-internal, mirroring the
  existing `middleware_test.go`/`governance_test.go` patterns — hand-written
  stubs, no mocks): gate denials per control with `peer.NewContext`-injected
  peer addresses; `grpc-metadata-x-confirm` acceptance/refusal and
  byte-identical `FailedPrecondition` strings across rules; idle expiry +
  `Touch` recording (open and close for streams); the proto-annotation
  conformance test (D2); unchanged HTTP-path tests stay green unmodified.
- **e2e** (`test/`, `package ssotest`, new `admin_grpc_governance_test.go`
  beside `admin_grpc_base_test.go`): drive the same mutation via native
  gRPC (bufconn) and gateway REST, assert identical accept/reject outcomes
  per control; idle-expired token rejected identically on both; TLS e2e
  with generated certs; startup cases in `cmd/sso-server` config tests for
  the two D4 invariants (including the guard error naming the control).
- **Mandatory gates**: `go build ./... && go vet ./...` and
  `go test -run 'TestMaintainability_|TestArchitecture_' .` after every
  `.go` edit; `go test ./... -race`, `go test ./test/ -run TestE2E -v`,
  and `make ci` at handoff. Architecture: no new packages, no
  `layerExemptions`, imports stay on the `interfaces/admin` →
  `platform/lifecycle/admingovernance` / `interfaces/ratelimit` /
  `shared/core` edges that already exist.
- **Sequencing**: D1's relocation (approval block → `deps.go`) lands first
  as a pure move (no behavior change, existing tests prove it), then the
  gate, then D2/D3 on top of the gate, then D4's guards — each step leaves
  `go build`/`vet`/maintainability green.
