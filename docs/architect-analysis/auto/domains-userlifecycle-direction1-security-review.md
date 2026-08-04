# Security review: `domains/userlifecycle` direction 1 (lifecycle state becomes an enforced auth gate)

Review of `docs/auto/domains-userlifecycle-direction1-design.md` against the
working tree. Advisory only; no files were modified. Evidence labels:
**Verified** = source-inspected in this revision, **Proposed** = design-only,
**Missing** = could not be established. No gates ran (no `.go` edits).

## 1. Assets, trust boundaries, attacker capabilities, entry points

### Assets in scope

| Asset | Store / SPI | Design's use |
|---|---|---|
| Lifecycle state + history | `userlifecycle.Store` (`domains/userlifecycle/memory/memory.go`; memory-only today) | Read on login/refresh hot paths; write via admin API; reactions via bus |
| Sessions | `core.SessionManager` (`shared/core/spi.go:133`) | Read `ListByUser` / write `Destroy` in reactions |
| Refresh-token families | `oauth.RefreshTokenSubjectIndex` → `oauthspi` (`protocols/oauth/aliases.go:24`, `handle_revoke.go:174-197`) | `DeleteAllForSubject` per client in reactions |
| Audit trail | `audit.Recorder` (`platform/audit/recorder.go`) | Event backbone for the bus (D3) and gate metadata (D1) |

### Trust boundaries

- **Untrusted**: `/token` (all grants), `/auth/login` + ceremony endpoints,
  federated `/callback`, admin API (behind `admin:write` — trusted once
  authenticated). The design adds **no new request input**: both gates key off
  server-resolved identities (`result.UserID` from the authenticator,
  `info.UserID` from the consumed refresh record), never off client-supplied
  user IDs. Verified: no new headers, no new query/body params.
- **Trusted**: composition root (`cmd/sso-server/build_stores.go`
  `wireUserLifecycle`), admin lifecycle handlers (`interfaces/admin/lifecycle.go`),
  `audit.Recorder` as the synchronous event backbone.
- **Attacker capabilities assumed**: (a) a user who was suspended/archived and
  wants to keep authenticating or keep rotating tokens; (b) a token thief with
  a captured pre-suspension credential (access token, refresh token, auth code,
  device secret, id_token); (c) an unauthenticated remote attacker probing
  error shapes. Admin-write capability is out of scope (already trusted).

### Entry points for the lifecycle decision

Verified coverage of every session-minting login path (all funnel through the
five sites; `createSession` has no other caller reachable without one of
them — `server_finish_login.go:16`, `server_login.go:65`,
`server_mfa_trust.go:41-44`, `server_oauth.go:122`):

| # | Site | Verified denial shape today |
|---|---|---|
| 1 | `authenticateUser` (`server_login_auth.go:98`) — ALL credential authenticators (password/LDAP/OTP/magic-link/TOTP/WebAuthn/device) | 403 `account_locked` |
| 2 | `resumeLoginAfterMFA` (`server_mfa.go:359`) | 403 `account_locked` |
| 3 | `resumeLoginTransaction` (`server_mfa_trust.go:256`) | 403 `account_locked` |
| 4 | `finalizeCallbackSession` inline SCIM check (`server_oauth.go:221-227`) | 401 `callback_failed` (no `login.Request` exists on this path — see Finding 7) |
| 5 | `HandleRefreshGrant` (`token_refresh.go:92-97`), insertion between liveness and resolve | 400 `invalid_grant` |

Token-grant paths **not** covered by the design (see Findings 1-2):
`HandleAuthCodeGrant`, `HandleTokenExchangeGrant`, `HandleDeviceSecretExchange`,
`HandleJWTBearerGrant`, `HandleSAML2BearerGrant`, device/CIBA polling.

## 2. Findings

### F1 (Medium, High in exchange-enabled deployments) — Token-exchange and Native-SSO device-secret exchange bypass suspension; absent from the design's residual list

- **Evidence** (**Verified**): `HandleTokenExchangeGrant` validates the
  subject token only via stateless `ValidateAnyToken` (signature/expiry/JTI) —
  `token_exchange.go:22-110`; no lifecycle or session-liveness check. It mints
  an access token with a **fresh** `client.AccessTokenTTL`
  (`token_exchange_stages.go:417`) and, when `requested_token_type` is
  `refresh_token`, mints a refresh token ("FAIL-OPEN" comment,
  `token_exchange_stages.go:457-482`). The only chain bound,
  `MaxTokenExchangeChainLifetime`, is **default-off** (0 = disabled,
  `token_exchange.go:96-101`). `HandleDeviceSecretExchange`
  (`server_native_sso.go:77-115`) checks subject/session **match** between the
  secret and the id_token but never checks the session is **alive**, so a
  pre-suspension device secret + pre-suspension id_token survive the D3
  reaction. The design's Decision 6.6 residual list names only the auth-code
  gap; the exchange paths are not mentioned.
- **Preconditions**: deployment enables token exchange (or Native SSO); the
  user holds a still-valid pre-suspension access token / id_token / device
  secret (TTL-bounded window to start the chain); a registered client
  authenticates at `/token` (the user's own client or a compromised one).
- **Steps**: suspend user → user (or thief) re-exchanges the surviving token
  before expiry → fresh access token, fresh TTL → repeat hop-by-hop
  indefinitely (chain cap off); each hop also mints a refresh family that the
  D2 gate only kills at first rotation attempt.
- **Impact**: suspension's "revoke access" promise (Decision 3) is bypassable
  for the exchange surface; fresh tokens keep flowing past the point where the
  admin got the 200. Same class as the documented auth-code gap but
  unbounded-in-time (chainable) instead of TTL-bounded.
- **Remediation**: add the same `userlifecycle.AllowsAuthentication` gate to
  `HandleTokenExchangeGrant` (after subject-token validation, collapsing to
  `invalid_grant`) and to the device-secret exchange ladder; at minimum,
  document the gap next to 6.6 and ship the chain-lifetime cap default-on in
  exchange-enabled builds.
- **Regression test**: suspend → exchange a pre-suspension access token →
  assert 400 `invalid_grant`, byte-identical to an unknown-subject exchange;
  same for `actor_token_type=device_secret` with a destroyed session.

### F2 (Medium) — Multi-replica divergence is real and unguarded; the design's risk-10 mitigation claim is inaccurate

- **Evidence** (**Verified**): the lifecycle store is memory-only
  (`domains/userlifecycle/memory`); `haCoherenceIssues` (`build_stores.go:95-120`)
  checks oauth/session/JTI/CIBA/identity/MFA/identity-link/pairwise backends but
  **not** the lifecycle store, so a declared multi-replica topology with
  `user_lifecycle.enabled` boots clean. On replica B the record never exists,
  so `Store.Get` returns `DefaultState` = ACTIVE (`memory.go:34`) — B's login
  gate, refresh gate, and sweep all treat the user as active forever. The
  design's risk 10 ("the refresh gate narrows the blast radius (families die on
  every replica's next rotation attempt)") is wrong for the gate read: B's gate
  *allows*, because no-record = ACTIVE by contract. The D3 reaction legs do hit
  shared stores in a conformant HA deployment (session/refresh backends are
  coherence-checked), so revocation mostly lands — but the gates never do.
- **Preconditions**: `topology.mode: multi` (or a shared backend hint) +
  `user_lifecycle.enabled: true` — both currently permitted together.
- **Impact**: suspension enforced on the replica that served the admin request;
  other replicas keep minting sessions and rotating tokens for the suspended
  user indefinitely.
- **Remediation**: add `user_lifecycle` to `haCoherenceIssues` (refuse/flag
  multi-replica while only a memory backend exists), or gate the boot; the
  SQL peer (analysis direction 3) is the structural fix. Correct the risk-10
  wording in the design.
- **Regression test**: `enforceHACoherence` unit — multi-replica +
  `user_lifecycle.enabled` produces an issue entry; wiring test asserting the
  new check.

### F3 (Medium/Low) — Synchronous reactions run on the admin request context; client disconnect cancels revocation mid-flight while the API still returns 200

- **Evidence** (**Verified**): `applyLifecycleTransition` calls
  `RecordTransition(ctx.Request().Context(), ...)` then writes 200
  (`interfaces/admin/lifecycle.go:85-97`); `audit.Recorder.Record` is
  synchronous (`recorder.go:143-178`), `MultiSink.Record` iterates inline
  (`multi_sink.go:24-34`), and `bus.Record` invokes `On` reactions in the
  caller's goroutine with the same ctx (`bus.go:116-137`). A canceled admin
  request aborts `Destroy`/`DeleteAllForSubject` with ctx errors that are
  joined + logged but never fail the transition. Note `OnAsync` already uses
  the bus's own context (`bus.go:invokeAsync` uses `b.ctx`) — the sync path
  has no equivalent.
- **Preconditions**: admin client disconnects between `Append` and reaction
  completion (e.g. load-balancer timeout, tab close).
- **Impact**: the design's "admin response implies revocation completed"
  (Decision 3.2) is false under cancellation; sessions/tokens survive and only
  the gates backstop them.
- **Remediation**: run sync reactions with `context.WithoutCancel(ctx)` (or the
  bus's own long-lived ctx, as `OnAsync` does) so request cancellation cannot
  truncate a security-critical revocation.
- **Regression test**: cancel the admin request context mid-reaction (inject a
  blocking `SessionManager`), assert revocation still completes and the
  transition still 200s.

### F4 (Low) — `audit.enabled: false` + `user_lifecycle.enabled: true`: transitions never revoke, boot warning only

- **Evidence** (**Verified**): `wireAudit` returns early when disabled
  (`build_app_core.go:198-202`), so `b.recorder` is nil, `AddSink` is a no-op
  (`recorder.go:131-141`), and `RecordTransition` no-ops on nil
  (`sweep.go:162-176`). The design adds a loud boot warning (Decision 3.2) but
  keeps the config valid. Admin 200s are written with zero revocation effect.
  Same coupling the webhook engine and CAEP transmitter already have
  (design risk 7).
- **Impact**: bounded — the read gates (D1/D2) still hold, so no new
  login/rotation; surviving sessions/tokens decay by TTL, and every presented
  refresh token is consumed+denied. Operators who expect revocation from the
  200 are misled.
- **Remediation**: acceptable if documented as a hard requirement in
  `docs/config-reference.md` ("user_lifecycle requires audit.enabled for
  transition-time revocation"); optionally refuse the config pair at boot.
- **Regression test**: config-validation unit asserting the warning path (or
  refusal) and the byte-identical gates under the disabled pair.

### F5 (Low) — `AllowsAuthentication(StateNone) == true` contradicts the design's own "gates never special-case missing" claim and fails open on a zero-value record

- **Evidence** (**Proposed**): the design's predicate allows `s == StateNone`
  while Decision 4 asserts "no-record = ACTIVE is enforced by `Store.Get`
  itself — the gates never special-case 'missing'". A compliant store can never
  return `StateNone` (memory store maps to `DefaultState`), so the branch is
  dead code today — but a future SQL peer with a buggy row-read that returns a
  zero-value `Record` would be **allowed** by the predicate exactly when the
  fail-closed philosophy says uncertainty must deny.
- **Impact**: theoretical today; a latent fail-open in the single most
  security-critical predicate of the feature.
- **Remediation**: keep the predicate pure (`s == StateActive`) so the
  no-record mapping lives exclusively in the store contract, and corrupt reads
  deny; or keep the branch and document it as a deliberate second mapping point
  (single source of truth either way).
- **Regression test**: unit — `AllowsAuthentication("")` asserts the chosen
  policy; store-fault injection in the ssotest harness returns a zero-value
  record and asserts the chosen outcome.

### F6 (Low) — Timing oracle on the refresh denial (valid-token-but-denied is slower than unknown-token)

- **Evidence** (**Verified**): the D2 gate adds a store read after `Consume`
  succeeds, so a suspended user's denial is measurably slower than the
  unknown/expired/consumed path that returns immediately after
  `refreshHandleConsumeError` (`token_refresh.go:83-99`). The existing
  `refreshCheckSessionLiveness` already has the identical asymmetry (valid
  token + dead session = extra read), so this is a pre-existing class, not a
  new one.
- **Impact**: a token thief can infer "this token was valid but the account is
  suspended" — information they largely already hold (they presented a valid
  token). No wire-shape leak.
- **Remediation**: none required; document next to the oracle-collapse note.
  Do not "fix" by adding dummy reads to the unknown path (latency cost, no
  security gain).

### F7 (Info) — D1 helper signature does not fit site 4

- **Evidence** (**Verified**): `finalizeCallbackSession(ctx, result)` has no
  `*login.Request` (`server_oauth.go:212`), yet the helper is specced as
  `rejectLifecycleBlockedUser(ctx HandlerContext, req *login.Request, userID string) bool`
  and its sketch writes `authzErrorBodyWithState(ctx, ..., req.State)`.
  Site 4 must render `errorBody(ctx, ErrCallbackFailed)` with no state and use
  `recordCallbackFailure` instead of `recordLoginFailure` (the design's table
  1.2 already says this, but the signature does not).
- **Impact**: none (implementation detail); the nil-`req` branch must be
  specced before coding so the site-4 leg does not accidentally write a 403.
- **Remediation**: spec the nil-`req` branch explicitly.

### Not findings (checked, no defect)

- No new request input, headers, or proxy-trust consumers anywhere in the
  design — SSRF/XFF/header-forgery surfaces are untouched.
- No new error codes, event types, or `auditreport` classification; state
  reaches only audit meta (`MetaLifecycleState`, bounded by the six-state
  enum) and server logs (**Verified** against `recorder_events_session.go:134-182`,
  which take no meta today — the variadic extension is compatible).
- Gate ordering (post-credential, post-SCIM, pre-`RegisterSuccess`, pre-any
  mint) matches `rejectDeactivatedUser`'s contract exactly
  (`server_login_auth.go:94-106`).
- D3 synchronous chain is real: `applyLifecycleTransition` →
  `RecordTransition` → `Recorder.Record` (inline) → `MultiSink` →
  `bus.Record` (inline) → reactions, all before the 200 write — modulo F3.
- `AddSink` is wiring-time only (documented not concurrent-safe with `Record`,
  `recorder.go:131`); the bus copies handlers under RLock and invokes outside
  the lock (`bus.go:116-137`) — no lock held across reaction I/O.
- Layer rules hold: `internal/handler/tokengrant` (interfaces) importing
  `domains/userlifecycle` (rank 2) is a downward edge; `interfaces/sso`
  already imports the domain (`options_admin.go`).
- Budgets verified by `wc -l`: 493/471/491/495 (sites), 413 (move target),
  474 (accessor file, 26 headroom), 431 (`token_refresh.go`, 69 headroom);
  the 73-line device-context block (268-340) is referenced only from
  same-package files (`server_finish_login.go:138,486`,
  `server_login_gates.go:463`), so the move is mechanical.
- No new `sso.Option`; `userlifecycle_wiring_test.go:65-122` pins opts counts
  0/1/2.
- `AuthCodeStore` has only `Issue`/`Consume` (`oauthspi/auth_code.go:114-125`)
  — the design's "no per-subject delete SPI" claim for the auth-code gap is
  accurate.

## 3. Abuse-case table

| Case | Path | Verdict | Notes |
|---|---|---|---|
| Identity spoofing: attacker submits another user's ID to the gates | D1/D2 read server-resolved `result.UserID`/`info.UserID` | **Not exploitable** | No client-controlled userID reaches the gate; auth-code/refresh records are bound at issue. |
| Replay: suspended user exchanges a pre-suspension auth code | `HandleAuthCodeGrant` (no gate; session liveness not consulted at exchange) | **Reachable, TTL-bounded** | Design risk 6.6, verified: mints access token + refresh family + device secret; family dies at first rotation; access token lives to TTL. |
| Replay: suspended user re-exchanges a surviving access token / device secret | `HandleTokenExchangeGrant` / `HandleDeviceSecretExchange` | **Reachable, unbounded** | F1. Fresh TTL each hop; chain cap default-off; session-match check is binding-only, not liveness. |
| Replay: refresh-token retry after D2 denial | Reuse path kills the family | **Desired behavior** | Design risk 11; the acceptance test must wire the gate without the bus to observe an intact family. |
| Replay: JWT/SAML2-bearer assertions by a suspended user | Bearer grants (no gate) | **Bounded by assertion TTL; IdP-owned** | IdP controls issuance; Snaplink-local suspension cannot invalidate a still-valid assertion. Document as residual. |
| Cross-tenant: admin suspends a user visible only in another tenant | Admin API has no tenant param; users are global subjects | **Consistent with existing admin model** | `UserProvider.GetByID` 404s unknown users; reactions revoke across clients by design (one subject, all tenants). No new cross-tenant surface. |
| Proxy/header forgery to reach the gates | No new header consumers | **Not applicable** | XFF/forwarded/mTLS/mesh trust surfaces untouched; gates read request context, not headers. |
| Resource exhaustion: mass fail-closed 403s during lifecycle-store outage | D1/D2 read-error → deny | **Deliberate (design risk 8)** | Memory store cannot error today; a future SQL peer makes this reachable. Byte-indistinguishable from suspension — operator must watch the fail-closed log line; document in `config-reference.md` as planned. |
| Resource exhaustion: audit cardinality blow-up | `lifecycle.state` meta | **Bounded** | Six-state enum; per-login-failure events already exist. |
| Sensitive-data leakage | Wire, logs, audit | **None found** | State only in audit meta + logs; log lines carry user_id/family, never credentials; `account_locked`/`invalid_grant`/`callback_failed` shapes byte-identical to existing SCIM/unknown-token paths. |
| TOCTOU: login reads ACTIVE just before a suspension commits | Gate → reaction window | **Accepted (design risk 5)** | New session survives to TTL; refresh gate cuts rotation; same class as the SCIM race. |
| Multi-replica: suspension applied on replica A | Replica B gates read no record | **Reachable, unguarded** | F2. No convergence; B treats the user as ACTIVE indefinitely. |

## 4. Positive controls verified, residual risks, prioritized validation plan

### Positive controls verified (this revision)

1. Oracle-safe collapse at all five sites with per-site byte-identical shapes
   (403/401/400); no new wire codes; state confined to audit meta + logs.
2. Gate ordering preserves the `rejectDeactivatedUser` contract (credential →
   SCIM → lifecycle → lockout-success → side effects) at every site.
3. Refresh gate runs after single-use `Consume` (no token leak) and before
   `RecordRotation` (no rotation side effect before the decision); reuse/grace
   semantics unchanged.
4. No-record = ACTIVE and nil-store = no-op are store/accessor-enforced;
   backward compatibility anchor intact.
5. D3 revocation chain is genuinely synchronous through the audit recorder
   (modulo F3's context issue); reaction idempotency and
   best-effort-across-stores legs already proven by `RevokeAccessOnArchive`.
6. Wiring order, `AddSink` discipline, no new `sso.Option`, layer rules, and
   line-budget arithmetic all verified as claimed.
7. `account_locked` doc drift (423 vs code 403) confirmed at
   `docs/error-codes.md:139`; the design correctly pins the code's 403 and
   requires the doc reconciliation.

### Residual risks (accepted by the design)

- Auth-code exchange gap (6.6) — TTL-bounded; **extend the residual list with
  F1's exchange/device-secret paths**.
- Login↔reaction TOCTOU (6.5); grace-window family kill (6.11);
  INVITED/future-invitation coupling (6.9); fail-closed self-lockout (6.8);
  audit-disabled coupling (6.7); AddSink wiring discipline (6.12);
  multi-replica divergence (6.10 — see F2 for the corrected blast-radius
  statement).

### Prioritized validation plan

1. **Before coding (spec amendments)**: F1 remediation decision (exchange
   gates or documented residual + cap default), F2 `haCoherenceIssues` entry,
   F3 `context.WithoutCancel` for sync reactions, F5 predicate purity,
   F7 nil-`req` branch.
2. **Per-change gates**: `go build ./... && go vet ./...`,
   `go test -run 'TestMaintainability_|TestArchitecture_' .` after every edit
   (the D1 device-context move is the line-budget linchpin).
3. **Unit**: `AllowsAuthentication` table (including the F5 zero-value case);
   `RevokeAccessOnSuspend` idempotency + leg isolation; refresh-gate placement;
   `haCoherenceIssues` multi-replica entry (F2).
4. **Integration (`package ssotest`)**: Decision 7 acceptances with
   byte-compare against SCIM/unknown-token bodies; new tests: exchange-after-
   suspend → `invalid_grant` (F1), canceled-admin-ctx reaction completion (F3),
   `audit.enabled:false` boot warning + gate behavior (F4).
5. **Full handoff**: `go test ./... -race`, `go test ./test/ -run TestE2E -v`,
   `make ci`.
6. **Doc contract updates in the same change** (AGENTS.md §5.6): the three
   stale "NEVER gates authentication" statements (`options_admin.go:277`,
   `docs/config-reference.md:695`, package doc `userlifecycle.go:9-10`),
   `account_locked` 403 reconciliation, fail-closed outage posture in
   `config-reference.md`, and the F1 residual-list addition.

**Bottom line**: the design is sound on oracle safety, ordering, fail-closed
philosophy, and engineering constraints — all mechanical claims verified. The
two security-relevant gaps it must absorb before implementation are F1
(token-exchange/device-secret chains bypass suspension and are absent from the
residual list) and F2 (multi-replica divergence is unguarded by the HA gate,
and risk 10's mitigation claim is factually wrong). F3-F5 are cheap hardening
changes; F6-F7 are documentation/implementation notes.
