# Protocol review: `domains/userlifecycle` direction 1 — lifecycle state as an enforced auth gate

Reviewed artifact: `docs/auto/domains-userlifecycle-direction1-design.md` (454
lines). Review revision: working tree at `f0b83ce96526799bcd8a71b45055a8798cf59a0a`.

Method: static source inspection + targeted greps only. The design makes no
`.go` edits, so no build/gate runs were required; **no `go build`/`go test`
was executed for this review** — every evidence citation below is a source
location, not a test result. Claims are labeled **Verified** (source-confirmed
at the cited location), **Partial** (confirmed with a caveat), or **Proposed**
(design intent, not yet implemented).

Standards actually engaged by this design: OAuth 2.0 refresh grant and error
responses (RFC 6749 §5.2, §6), OAuth 2.0 Security BCP refresh rotation (RFC
9700 §4.13), SCIM deprovisioning semantics (RFC 7643 §8.2 `active`), OIDC
Core §3.1.2.6 (by analogy only — Snaplink's `/auth/login` is a JSON login API,
not the OIDC authorization redirect), RFC 7009 §2.2 / RFC 7662 (unaffected,
referenced for shape), and CAEP/SSF (explicitly out of scope — the transition
trigger is the admin lifecycle API, not SSF events). The design adds **no new
endpoints, no discovery metadata, no claims, no token formats**, so discovery
(`/.well-known/openid-configuration`), `userinfo`, and token claim surfaces are
out of scope except where the gates touch error responses.

---

## 1. Protocol/profile scope and authoritative references

| # | Reference | Why it is in scope |
|---|---|---|
| R1 | RFC 6749 §6 — refresh token grant; §5.2 — error responses | D2 changes the set of conditions collapsing to `400 invalid_grant` on `/token` |
| R2 | RFC 9700 §4.13 — refresh rotation, reuse detection, grace window | D2 consumes the presented token before denial; retry semantics interact with family reuse-kill and the grace window |
| R3 | RFC 7643 §8.2 — SCIM `active` (deprovisioning) | The five existing `active=false` denial sites the lifecycle gate mirrors; per-site denial shapes are pinned to the existing SCIM shapes |
| R4 | OIDC Core §3.1.2.6 — authentication error response (by analogy) | `/auth/login` 403/401 denial shapes carry the request `state` back (`authzErrorBodyWithState`), preserving the login-CSRF binding that an OIDC authorization error redirect would preserve |
| R5 | RFC 7009 §2.2; RFC 7662 | `/token/revoke` and `/token/introspect` are untouched by the design; D3's revocation is store-level, not protocol-level |
| R6 | RFC 6749 §4.1.2 — authorization code single-use | The design's declared residual gap: a pre-suspension code can still be exchanged after SUSPENDED (D6.6) |
| R7 | OpenID CAEP/SSF (current draft family) | Out of scope by design; `protocols/caep` exists but the suspension trigger is the admin API. Noted for the SSF-fed suspension follow-up |

Profile posture: the lifecycle state machine is a **profile extension** layered
on OAuth/OIDC. Nothing in the design relaxes a MUST, changes token formats, or
alters discovery. All new denials reuse existing wire codes (`account_locked`,
`callback_failed`, `invalid_grant`) — no new error code is introduced, which is
the correct move for both oracle-safety and client compatibility.

---

## 2. Compliance matrix

Columns: Section/claim · Requirement · Evidence · Status · Deviation · Test.

| # | Section / claim | Requirement | Evidence (source) | Status | Deviation | Test |
|---|---|---|---|---|---|---|
| C1 | Five enforcement points, not three (spec correction) | Design must gate every post-credential session/token mint | `rejectDeactivatedUser` call sites: `interfaces/sso/server_login_auth.go:98` (in `authenticateUser`), `interfaces/sso/server_mfa.go:359` (in `resumeLoginAfterMFA`, starts :320), `interfaces/sso/server_mfa_trust.go:256` (in `resumeLoginTransaction`); inline SCIM check at `interfaces/sso/server_oauth.go:221-227` (in `finalizeCallbackSession`) | **Verified** | none | `test/scim_deprovision_login_test.go:77`; `test/mfa_test.go:913` (second-leg 403) |
| C2 | Per-site denial shapes | Lifecycle denial must be byte-identical to the site's existing SCIM denial | 403 `account_locked` via `recordLoginFailure` + `authzErrorBodyWithState` at `server_login_auth.go:79` (lockout path), :123 (SCIM path in `handleAuthFailure`), :153 (`rejectDeactivatedUser`); 401 `callback_failed` at `server_oauth.go:224` (`errorBody(ctx, ErrCallbackFailed)`); `authzErrorBodyWithState` at `server_discovery.go:290` | **Verified** | none | body byte-compare planned in D7 |
| C3 | `account_locked` wire status | Code and contract must agree | Code writes `http.StatusForbidden` everywhere (`server_login_auth.go:101,156`); tests pin 403 (`test/account_lockout_test.go:216-236`, `test/scim_deprovision_login_test.go:77`); **`docs/error-codes.md:139` documents 423**; `docs/openapi.yaml` lists `account_locked` only in notification enums (lines 14599/14614), never in the `/auth/login` 403 description (lines 489-506) | **Verified** | Doc drift (423 vs 403) + missing OpenAPI coverage — see Finding F-4 | existing lockout tests |
| C4 | Line-budget collision (D1 pre-step mandatory) | No file may exceed 500 physical lines (`maintainability_budget_test.go:56-135`, `countFileLines` counts `\n` bytes; exemptions frozen at zero, `maxFileSizeExemptions = 0`) | `server_login_auth.go` = 493; `server_login_resolve.go` = 413; `server_mfa.go` = 471; `server_mfa_trust.go` = 491; `server_oauth.go` = 495; `options_admin.go` = 474; `token_refresh.go` = 431; `interfaces/sso` non-test files = exactly 60 | **Verified** | none | `TestMaintainability_FileSizeBudget` |
| C5 | Device-context block is self-contained and movable (D1 pre-step) | Move must not change behavior | `deviceContext` struct at `server_login_auth.go:268`; `deviceCtxFrom` :328; `deviceTypeFromCtx` :334 (73 lines, 268-340); consumers (`deviceAwareTTL` :369, `registerLoginDevice` :419) are same-package | **Verified** | none | existing device-trust tests |
| C6 | Refresh-gate insertion point | Gate after session-liveness, before any rotation side effect | `HandleRefreshGrant` order (`token_refresh.go:79-121`): `Consume` → `refreshBindGuard` → `refreshEnforceAbsoluteMaxLifetime` → `refreshCheckSessionLiveness` (fail-closed "session not found" per doc comment) → `refreshResolveGrant` → `EnforceRefreshDepthPolicy` → `refreshVelocityGate` (calls `RecordRotation` — first side effect) | **Verified** | none | refresh e2e in `test/`; planned placement assertion |
| C7 | Oracle collapse on refresh | Byte-identical `400 invalid_grant` for unknown/expired/consumed/reused/lifecycle-denied | Unknown/expired/consumed collapse at `token_refresh.go:70-74`; reuse-kill at `refreshHandleConsumeError`; doc comment "ALL collapse to 400 invalid_grant (oracle-leak collapse)" (`token_refresh.go:44-49`) | **Verified** | none | D2 byte-compare test (planned) |
| C8 | Consume-before-deny on refresh | No token leak; reuse path handles retry | `Consume` at `token_refresh.go:62` precedes every gate | **Verified** | none | D6.11 acceptance note |
| C9 | `Store.Get` no-record contract | No-record reads as ACTIVE, never an error | Interface doc `domains/userlifecycle/userlifecycle.go:96-100`; impl `domains/userlifecycle/memory/memory.go:34-41` returns `{State: DefaultState}` | **Verified** | none | `domains/userlifecycle` unit tests |
| C10 | Bus is an `audit.Sink` on `EventAdminUserLifecycleChanged`; sync dispatch | Reactions run inside the transition before the 200; admin 200 implies revocation | `bus.go:164-186` (`Record` filters on the event type; `dispatchSync` in caller goroutine); `sweep.go:158-177` (`RecordTransition` emits for admin + sweep, `MetaTargetUser`/`MetaFromState`/`MetaToState`); admin handler `interfaces/admin/lifecycle.go:86-89` (`Append` → `RecordTransition` → 200) | **Verified** | none | D3 e2e (planned) |
| C11 | `OnUserSuspended` has zero production callers | No conflict with existing wiring | grep: only `bus.go:142` + `bus_test.go` | **Verified** | none | — |
| C12 | `AddSink` is wiring-time-only | No runtime registration race | `platform/audit/recorder.go:131-138` ("Not safe for concurrent use with Record — call it during wiring"); `wireUserLifecycle` runs in `wireGovernance` (`build_app_security.go:240` → `build_stores.go:328`), after `wireAudit`/`wireDomains` (`build_app_core.go:198-221`, `build_app_oauth.go:300`) and before `NewServer` | **Verified** | none | `cmd/sso-server/userlifecycle_wiring_test.go` |
| C13 | No new `sso.Option` | SDK surface unchanged | `userlifecycle_wiring_test.go:65-122` asserts `len(b.opts)` ∈ {0, 1, 2} | **Verified** | none | wiring test |
| C14 | `RefreshGrantDeps` growth is compile-enforced; no test doubles exist today | Interface change is loud, not silent | Guard `var _ tokengrant.RefreshGrantDeps = (*Server)(nil)` at `interfaces/sso/accessors_handlers.go:363`; grep for `RefreshGrantDeps` finds no test files implementing it (only `accessors_handlers.go`, `token_refresh.go`, `oauthspi/refresh_token.go`); `internal/handler` is classified `interfaces` (`architecture_layer_test.go:105`) so `tokengrant → domains/userlifecycle` is a downward edge, no `layerExemptions` needed | **Verified** | D2.1 cites `accessors_token_grant.go`, which does not exist — the guard lives in `accessors_handlers.go` (cosmetic, F-8) | compile |
| C15 | Variadic meta on `recordLoginFailure`/audit events | No new event types; bounded cardinality | `server_helpers.go:282-296` (`recordLoginFailure`, no meta param); `platform/audit/recorder_events_session.go:134-145` (`RecordLoginFailure`), :170-180 (`RecordCallbackFailure`); both event types already classified in `auditreport` (`control_areas.go:46`, `drift_test.go:29`) | **Verified** | none | audit assertions in D7 |
| C16 | Audit-disabled coupling | `audit.enabled: false` → recorder nil → bus inert | `wireAudit` early-returns on `!cfg.Audit.Enabled` (`build_app_core.go:200-202`); `Record` no-ops on nil recorder | **Verified** | see F-3 | boot-warning wiring test (planned) |
| C17 | Auth-code exchange gap (residual) | No lifecycle check at exchange; no per-subject delete SPI | `internal/handler/tokengrant/token_authcode.go` has no lifecycle reference; `AuthCodeStore` interface is Issue/Consume only (`oauthspi/auth_code.go:114-125`) | **Verified** | declared residual (D6.6) | none (documented) |
| C18 | `DeleteAllForSubject` empty-clientID semantics | Backends support revoke-across-every-client in one call | redis `infrastructure/redis/refresh_token.go:310-313` ("Empty clientID = every client"); sqlite `infrastructure/defaultimpl/sqlite/refresh_tokens.go:242-244`; memory `infrastructure/defaultimpl/memorystoreoauth/memory_refresh_token.go:319-322`; established callers use `""` (`interfaces/admin/users.go:399`) | **Verified** | see F-2: design's per-client loop is redundant | — |
| C19 | INVITED unreachable by the admin API today | Denying INVITED login is safe until the invitation flow lands | `transitions.go:26-27` (`StateNone → {INVITED, ACTIVE}` seed only); admin handler always passes `rec.State` from `Get` (`interfaces/admin/lifecycle.go:61-77`), which is `DefaultState`=ACTIVE for no-record users — `ACTIVE → INVITED` is illegal, so no production path seeds INVITED | **Verified** | none (D6.9 stands) | D1 state table (planned) |
| C20 | Stale "NEVER gates authentication" docs (3 sites) | Must be revised in the same change | `options_admin.go:274-278` (`WithUserLifecycle` doc); `docs/config-reference.md:695` (§User Lifecycle); `domains/userlifecycle/userlifecycle.go:12-15` (package doc) | **Verified** | doc drift to fix | doc/checker gates |

---

## 3. Findings

Sorted by severity. All are advisory.

### F-1 (High, profile requirement, multi-replica deployments) — Suspension enforcement is per-process; the D6.10 mitigation sentence overstates the refresh gate's reach

- **Evidence**: the lifecycle store is memory-only per process (`wireUserLifecycle` → `serverbuildplatform.BuildUserLifecycle`; `domains/userlifecycle/memory` package doc: "State is lost on restart… a multi-replica production deploy should swap in a SQL-backed peer"). Sessions may be shared (`BuildSessionManager` supports redis/postgres/sqlite, `cmd/sso-server/serverbuildstore/build_identity_stores.go:267-286`); refresh tokens are shared.
- **Impact**: a transition applied via replica A lands only in A's memory. Replica B (no record) reads `DefaultState` at both gates → **login succeeds and refresh rotation succeeds on B, indefinitely** — there is no convergence mechanism, so this is not "until convergence". D6.10's claim that "the refresh gate narrows the blast radius (families die on every replica's next rotation attempt)" holds only for families already deleted from the *shared* token store by A's reaction; a family minted on B after the suspension survives. This is the design's headline security invariant (suspension revokes access) failing in a documented deployment mode.
- **Caveat**: the design inherits this from the existing memory-only state machine and discloses it in Decision 4; direction 3 (SQL peer + cross-replica invalidation) is the acknowledged fix.
- **Corrective behavior (required before/with landing)**: (1) state the single-replica enforcement constraint explicitly in `docs/config-reference.md` §User Lifecycle, including the indefinite-window wording (not "until convergence"); (2) fix the D6.10 sentence to say the blast-radius narrowing depends on the reaction having run on the transition-serving replica plus a shared token store; (3) keep direction 3 as the tracked fix. No wire change is proposed.
- **Validation**: two-process integration test is not feasible with a memory store; validate via doc assertion + a grep gate that `BuildUserLifecycle` still returns only memory today.

### F-2 (Medium, correctness/robustness) — `revokeRefreshTokens` per-client loop is weaker than the SPI's own revoke-across-every-client call

- **Evidence**: the design (D3.1) reuses `revokeRefreshTokens` from `protocols/lifecyclereactions/revoke_on_archive.go:58-74`, which loops `clients.List()` and calls `DeleteAllForSubject(ctx, userID, c.ID)` per client. All three backends implement empty-clientID = every client (C18), and the established "logout everywhere" pattern (`server_logout.go`), admin user-delete (`interfaces/admin/users.go:399`), and token-portfolio purge (`interfaces/admin/token_portfolio.go:326`) all use the `""` form.
- **Impact**: (a) if `clients.List()` errors, the whole refresh leg fails and **zero** tokens are deleted even though the index could have completed — directly violating the design's own "never less locked out" best-effort contract in the exact failure mode the legs exist to survive; (b) tokens issued for clients since de-registered from the client store are never deleted; (c) N round-trips instead of 1.
- **Corrective behavior**: change the leg to a single `DeleteAllForSubject(ctx, userID, "")` and drop the `clients core.ClientStore` parameter from both reactions (surface shrinks to two SPIs). This strengthens `RevokeAccessOnSuspend` and the pre-existing `RevokeAccessOnArchive` alike; archive happy-path behavior is unchanged, so no regression.
- **Validation**: unit test injecting a failing `ClientStore` — with the fix, revocation still completes; today it would not.

### F-3 (Medium, operational) — Transition-time revocation rides the audit pipeline; `audit.enabled: false` silently disarms it

- **Evidence**: C16. The bus observes transitions only as an `audit.Sink`; `wireAudit` early-returns on disabled audit, so `b.recorder` is nil and the bus never fires. The design's mitigation is a boot warning.
- **Impact**: an operator who disables audit (a plausible cost/volume decision) keeps `user_lifecycle.enabled: true` and gets read-gate enforcement but **no revocation**: sessions and refresh families survive to TTL, and the refresh gate still blocks rotation only in-process. The security invariant depends on an unrelated subsystem.
- **Corrective behavior**: keep the loud boot warning, and consider a cheap hardening: pass the bus (or a nil-safe reaction dispatcher) directly to `applyLifecycleTransition` (`interfaces/admin/lifecycle.go:86-89`) and `SweepOnce` (`sweep.go:148`) as an explicit optional seam, so the reaction path does not depend on the audit sink chain. If that is rejected, the config-reference text must state the coupling plainly.
- **Validation**: wiring test with `audit.enabled: false` + `user_lifecycle.enabled: true` asserting the warning is logged and (after the hardening) that a transition still fires the reaction.

### F-4 (Medium, contract drift) — `account_locked` status and OpenAPI coverage

- **Evidence**: C3. Code and tests pin 403; `docs/error-codes.md:139` says 423; `docs/openapi.yaml`'s `/auth/login` 403 description (lines 489-506) lists denial causes but not `account_locked`, and the `/token` `invalid_grant` descriptions do not mention a lifecycle cause.
- **Impact**: doc/code disagreement is a contract-drift violation per AGENTS.md §1; clients generated from OpenAPI get no `account_locked` schema for login, and the design's gate adds a third cause to a code the docs misdescribe.
- **Corrective behavior** (part of the same change, per AGENTS.md §5.6): fix `docs/error-codes.md:139` to 403; add `account_locked` to the `/auth/login` 403 description; add the lifecycle cause to the `/token` refresh `invalid_grant` description. The design's D1.3/D6.3 list error-codes.md and config-reference.md but omit openapi.yaml — add it.

### F-5 (Low, declared residual) — Auth-code exchange gap after suspension

- **Evidence**: C17. `HandleAuthCodeGrant` performs no lifecycle check; `AuthCodeStore` has no per-subject delete SPI.
- **Impact**: a code captured before SUSPENDED can be exchanged after, minting a fresh family plus an access token valid to TTL. Narrow (short TTL, single-use, bound to client/redirect/PKCE). In multi-replica deployments this compounds F-1 (the exchange may be served by a replica with no record). The fresh family is rotation-blocked in-process; access tokens are never revoked by the design (standard OAuth limitation — no access-token enumeration SPI; introspection/CAEP is the lever).
- **Corrective behavior**: acceptable for direction 1. The design's follow-up (per-subject auth-code index + reaction leg) is the right shape; add "access-token revocation on suspension is not provided" to the declared-unsupported list in the contract update.

### F-6 (Low, documentation) — Fail-open/fail-closed asymmetry at adjacent gates needs an operator runbook line

- **Evidence**: `rejectDeactivatedUser` fails open on SCIM read error (`server_login_auth.go:148-150`: `u, uerr := s.userProvider.GetByID(...)`; `if uerr != nil || u.IsActive() { return false }`); the proposed lifecycle gate fails closed (D5). Both sit at the same five call sites; the SCIM gate's fail-open is itself an acknowledged divergence from tenant-suspension's fail-open-with-audit.
- **Impact**: during a lifecycle-store outage, mass 403s are byte-indistinguishable from real suspension (by oracle-safe design); an operator watching only HTTP status may misdiagnose (D6.8).
- **Corrective behavior**: the design already requires the fail-closed posture to be documented in `docs/config-reference.md`; make the operator-visible differentiators explicit (the `lifecycle gate lookup failed` log line; `login_failure` audit meta `lifecycle.state` empty), and note the asymmetry next to `rejectDeactivatedUser`'s comment.

### F-7 (Info) — `AllowsAuthentication`'s `StateNone` branch is unreachable today

- **Evidence**: `Store.Get` never returns `StateNone` (C9) and the nil-store accessor short-circuits; the memory backend and the documented SPI contract both map no-record to `DefaultState`.
- **Impact**: none — harmless defensive code that keeps the predicate total over the `State` type. Keep it (a future SQL peer must honor the same contract).

### F-8 (Info) — Cosmetic inaccuracies in the design doc

- D2.1 cites `accessors_token_grant.go`; the guard is at `interfaces/sso/accessors_handlers.go:363` and no `accessors_token_grant.go` exists.
- D6.2's "test doubles breakage" is currently theoretical: no test file in the tree implements `RefreshGrantDeps` (C14). The `test/` e2e harnesses construct real `*sso.Server`, so they are unaffected by the interface growth.
- D1.3 says the federated SCIM leg "only logs" while the lifecycle leg adds `recordCallbackFailure` — this creates an audit asymmetry between two denial causes at the same site. Not a protocol issue; either audit both or document why not.

### Explicit non-goals confirmed (no finding)

- The TOCTOU window (D6.5) is accepted and consistent with the existing SCIM/MFA challenge races; the second-leg re-checks shrink but cannot close it. Blocking logins during transitions is correctly out of scope.
- Grace-window interaction (D6.11): consume-then-deny plus reuse-kill for suspended users is the desired outcome; the acceptance test must wire the gate without the bus (or assert on a surviving family).
- No new error code, no new audit event type, no new `sso.Option`, no new storage — all verified against the tree (C10, C12, C13, C15).

---

## 4. Priority conformance tests, declared unsupported features, and certification evidence

### Priority conformance tests (in addition to the design's D7 plan)

1. **Oracle byte-compare, refresh** (`test/`, D2): lifecycle-denied refresh body byte-identical to unknown-token; plus a retry-of-the-same-token case asserting the family-kill path (D6.11).
2. **Oracle byte-compare, login** (D1): `account_locked` body from the lifecycle gate byte-identical to the SCIM-deprovisioned path, at all four 403 sites; federated variant at 401 `callback_failed`.
3. **Status pin**: assert 403 (not 423) for `account_locked` — already covered by `test/account_lockout_test.go`; extend to the lifecycle gate.
4. **Store-error injection → fail closed** at both gates (D1/D2) and **one-store-error isolation** (`errors.Join`) in the reaction, with a failing `ClientStore` to prove F-2's fix (or to expose the gap if unfixed).
5. **Audit-disabled wiring** (F-3): boot warning emitted; read gates still enforce; reaction behavior asserted explicitly.
6. **Placement assertion** (D2): denied refresh must not bump the rotation-velocity counter (`RecordRefreshRotationVelocity` / velocity metric) — proves the gate precedes `refreshVelocityGate`.
7. **INVITED denial table** (D1): the full six-state table plus no-record and nil-store rows, in `domains/userlifecycle` unit tests.

### Declared unsupported features (must be listed in the contract update)

- Token-exchange chain-store reaction leg (no `ChainStore` in the composition root — dropped, D3.3).
- PURGED-state reaction (direction 2 Eraser).
- SQL-backed lifecycle store + cross-replica invalidation (direction 3; F-1).
- Per-subject auth-code index + reaction leg (D6.6 follow-up; F-5).
- Access-token revocation on suspension (no enumeration SPI; introspection/CAEP is the lever; F-5).
- Blocking logins during transitions (TOCTOU hard fix; out of scope).
- SSF/CAEP-fed suspension triggers (the admin API is the only transition source today).

### Certification evidence

**None.** No OIDF or FIDO certification is claimed anywhere in the tree (consistent with `docs/architect-analysis-mfa-protocol-review-gaps.md:220`), and this review adds no such claim. The design touches no certified conformance surface (discovery, claims, token formats, redirect handling) — its entire protocol surface is error-response shape on the token and login APIs, which is profile behavior, not OIDC Core conformance. Remaining certification evidence, should it ever be pursued: a published OIDC Core conformance result for the authorization/token flows, and a published FIDO result for WebAuthn ceremonies — neither exists in the repository today.
