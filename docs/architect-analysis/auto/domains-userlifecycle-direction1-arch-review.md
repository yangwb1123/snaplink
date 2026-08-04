# Architecture review: `domains/userlifecycle` direction 1 — lifecycle state becomes an enforced auth gate

Review of `docs/auto/domains-userlifecycle-direction1-design.md` against the
working tree at this revision. Advisory only; no code was changed.

**Checks that actually ran:** `go build ./...` (clean), `go test -run
'TestArchitecture_|TestMaintainability_' .` (pass), plus ~30 targeted source
inspections (line counts, call sites, SPI shapes, wiring order, doc rows).
Not run: `make ci`, `-race`, E2E — none are needed to validate a no-code design
doc, but the acceptance list in §4 depends on them post-implementation.

---

## 1. Scope, assumptions, and verified architecture summary

**Scope.** The design converts `domains/userlifecycle` from governance-only
metadata into an enforced auth gate: (D1) a login-path denial at five
post-credential enforcement points, (D2) a refresh-grant denial inside
`internal/handler/tokengrant`, (D3) transition-time revocation wired through
the existing lifecycle event bus. No new storage, no new `sso.Option`, no new
files in `interfaces/sso` or `domains/userlifecycle`.

**Assumptions.** Layer ranking, budgets, and the oracle-safe table in AGENTS.md
§3 are the governing contracts; `docs/auto/*-analysis.md` is roadmap intent,
not shipped behavior. The design's "no-record = ACTIVE" anchor is correct and
is the backward-compatibility keystone.

**Verified architecture summary.** Every material claim in the design checks
out against the tree:

- **Five enforcement points, not three** — Verified. `rejectDeactivatedUser`
  has four call sites (`server_login_auth.go:98`, `server_mfa.go:359`,
  `server_mfa_trust.go:256`, plus the definition itself) and the federated
  callback carries an inline SCIM check at `server_oauth.go:221–227` writing
  **401 `callback_failed`** (not 403 `account_locked`). The design's
  per-site-collapse rule is correct and necessary.
- **Budget collision is real** — Verified. `maxFileLines = 500`, exemption map
  frozen empty, `countFileLines` counts `\n` bytes
  (`maintainability_budget_test.go`). `server_login_auth.go` = 493 lines;
  the `deviceContext` block at lines 268–340 is ~73 self-contained lines;
  `server_login_resolve.go` = 413 and already hosts the device
  options (`WithDeviceStore`/`WithDevicePolicy`/`WithLoginHistoryStore`),
  so the move lands at 420/486 and the ~30-line helper at ~450. The
  `interfaces/sso` 60-file ceiling (AGENTS.md §2) is a policy statement and
  the dir has exactly 60 non-test files — extending an existing file is the
  only legal placement. Arithmetic checks out.
- **`account_locked` doc drift** — Verified. `docs/error-codes.md:139`
  documents 423; every code site writes 403 (`http.StatusForbidden` +
  `core.ErrAccountLocked`). `openapi.yaml` references the code only in an
  enum, so only the error-codes row needs reconciling.
- **Refresh-gate seam** — Verified. `HandleRefreshGrant` order is `Consume`
  (line 80) → bind guard → absolute-max-lifetime → `refreshCheckSessionLiveness`
  (line 106, documented fail-closed) → `refreshResolveGrant` (109) → depth
  policy → `refreshVelocityGate` (which calls `RecordRotation`, a side
  effect) → `refreshIssueAndRotate`. The proposed insertion point sits
  exactly between liveness and resolve, before any side effect, and the
  unknown/expired/consumed path writes `core.ErrorBody(core.ErrInvalidGrant)`
  — the byte-identical collapse target. The `var _ tokengrant.RefreshGrantDeps
  = (*Server)(nil)` guard is at `accessors_handlers.go:363`; no test file
  currently implements the interface, so the compile-enforced breakage is
  zero-double today. `internal/handler` is classified `interfaces`
  (`architecture_layer_test.go:105`), and tokengrant already imports
  `domains/{region,tenant,tokenexchange}` — the downward edge is precedented,
  no `layerExemptions` entry needed.
- **Bus mechanics** — Verified. `LifecycleEventBus.Record` is an `audit.Sink`
  dispatching synchronously for `On` reactions on
  `EventAdminUserLifecycleChanged`; `OnUserSuspended`/`OnUserArchived` have
  zero production callers; `RecordTransition` (`sweep.go:162`) is called by
  both the admin handler (`interfaces/admin/lifecycle.go:89`) and the sweep
  (`sweep.go:148`), so the wiring observes both drivers with zero new
  instrumentation. `audit.Recorder.AddSink` (`platform/audit/recorder.go:131`)
  is documented not concurrency-safe with `Record` — wiring-time registration
  is compliant.
- **Composition order** — Verified. `wireFoundation` (sets `b.recorder`
  `build_app_core.go:221`, `b.sessionMgr` :53) → `wireDomains`
  (`b.refreshTokenStore` `build_app_oauth.go:300`) → `wireEdge` →
  `wireGovernance` (`build_app.go:251`) → `wireUserLifecycle`
  (`build_app_security.go:240`). All reaction inputs are populated before the
  bus can be built. `wireAudit` returns early when `audit.enabled: false`
  (`build_app_core.go:198`), so the nil-recorder warning path is real.
- **Scope cuts** — Verified. `AuthCodeStore` (`protocols/oauth/oauthspi/
  auth_code.go:114`) has only `Issue`/`Consume`, no per-subject delete;
  `HandleAuthCodeGrant` performs no lifecycle check. No `ChainStore` is wired
  in `cmd/sso-server` or `interfaces/admin.Deps` (only an SPI consumer at
  `interfaces/admin/lifecycle.go:109`). `protocols/lifecyclereactions` has 2
  non-test files and `revoke_on_archive.go` already exposes the package-private
  `revokeRefreshTokens`/`destroySessions` legs — `RevokeAccessOnSuspend` is a
  ~30-line twin, no refactor.
- **Stale "NEVER gates" docs** — Verified in exactly the three claimed places
  (`options_admin.go:277`, `docs/config-reference.md:695`, `domains/
  userlifecycle/userlifecycle.go:7–9`). `docs/feature-matrix.md` carries no
  such claim.
- **Audit plumbing** — Verified. `recordLoginFailure` (`server_helpers.go:282`)
  and `audit.RecordLoginFailure`/`RecordCallbackFailure`
  (`recorder_events_session.go:134/:170`) take no meta today; a variadic
  `meta ...map[string]string` applied via `audit.SetMeta` is backward
  compatible and bounded by the six-state enum. `authzErrorBodyWithState` at
  `server_discovery.go:290`. The SCIM denial's fail-open posture
  (`uerr != nil || u.IsActive() → allow`) is confirmed, making the design's
  fail-closed asymmetry a real, documented divergence.
- **Wiring tests** — Verified. `userlifecycle_wiring_test.go` asserts
  `len(b.opts)` ∈ {0, 1, 2}; the bus adds no `sso.Option`, so they stay green.

Layer mapping (who owns what in the design): the predicate and bus live in
`domains/userlifecycle` (rank 2); the reactions in `protocols/
lifecyclereactions` (rank 3, downward import of the domain — legal); the
refresh gate in `internal/handler/tokengrant` (classified `interfaces`,
downward edge — legal); the login helper and `LifecycleState` accessor in
`interfaces/sso` (rank 5); the wiring in `cmd/sso-server` (composition). No
boundary is crossed; no exemption is required. This is the correct physical
placement of every piece.

---

## 2. Findings

| # | Severity | Evidence | Impact | Recommendation |
|---|---|---|---|---|
| F1 | **Medium** | D1's helper `rejectLifecycleBlockedUser(ctx HandlerContext, req *login.Request, userID string)` writes 403 `account_locked` via `authzErrorBodyWithState(ctx, core.ErrAccountLocked, req.State)`. Site 4 (`finalizeCallbackSession`, `server_oauth.go:212`) has no `*login.Request` in scope, `core.AuthResult` (`types_auth.go:183`) carries no State, and the site requires 401 `callback_failed` + `recordCallbackFailure` — a different status, code, and audit event. The verification table correctly flags the shape difference (401 vs 403), but the API surface does not parameterize it. | As specced, the helper serves sites 1–3 only; the implementer must improvise at site 4. If a second helper is added to `server_login_resolve.go`, the arithmetic breaks (486 + 30 + ~15 = 531 > 500). | Generalize the helper to take the denial shape (`code`, audit-recorder callback, `state`) or spec an inline 3-line guard at site 4 (`server_oauth.go` 495 → ~498, fits) and pin that placement in the design. Either way the two helper variants must land in `server_login_auth.go` (450 → ~465 after the move). |
| F2 | **Medium** | D2's gate consumes the presented token before denial (`Consume` at `token_refresh.go:80` precedes the insertion point), and the reuse path kills the whole family on a second presentation. Under a lifecycle-**store outage**, every refresh attempt burns the presented token and a client's automatic retry triggers family deletion. Design risk #8 documents the login-side "mass 403" but not this refresh-side burn-and-kill interaction. | An operator troubleshooting an outage can silently destroy surviving families via ordinary client retries; the design's own D2 acceptance "family unchanged when no bus wired" becomes an outage-time footgun. | Keep the after-`Consume` placement (pre-Consume check is impossible without a second lookup SPI, and the invariant "no token leak" is right). Document in `docs/config-reference.md`'s failure-mode paragraph: during a lifecycle-store outage, refresh retries may kill families (reuse detection) — clients should back off on `invalid_grant`. Add a log line in the fail-closed branch that names the outage distinctly. |
| F3 | **Low** | `HandleTokenExchangeGrant` (`token_exchange.go`) can mint fresh families from a still-valid subject access token after suspension; the reaction deletes subject-indexed refresh tokens, but a token exchanged after the reaction but before AT expiry survives until first rotation. Risk #6 lists only the auth-code gap. | Bounded by access-token TTL; fresh families die at first rotation (D2). Same TOCTOU class as accepted risk #5. | List it as a residual in the same change (one paragraph, same shape as risk #6), or gate it in direction 1 if the spec owners want parity — owner decision, see §5. |
| F4 | Info | "Every `interfaces/sso` file is 488–500 lines" (design risk 1) is an overstatement: `server_login_resolve.go` = 413, `server_mfa.go` = 471, `options_admin.go` = 474. The operative claim (493 for `server_login_auth.go`, no headroom) is exact. | None — the conclusion stands. | Tighten the wording so the constraint reads as "the files the change touches have ≤29 lines of headroom; the helper's home file has none." |
| F5 | Info | Design D2 cites "line ~93" for the liveness check (actual: 106) and names `accessors_token_grant.go` for the guard (actual: `accessors_handlers.go:363`; the design's own code block correctly targets `options_admin.go`). | None — relative ordering claims are exact. | Fix line refs before implementation. |
| F6 | Info | `AllowsAuthentication`'s `StateNone` arm is unreachable: `Store.Get` maps no-record to `DefaultState` (`memory/memory.go:34`) and the nil-store accessor returns `DefaultState`. | None — defensive. | Keep (documents intent) but note it in the doc comment so a future reader doesn't "simplify" it into a bug. |
| F7 | Info | At site 4 the lifecycle denial records `callback_failure` while the SCIM leg only logs — an audit-side (not wire-side) distinguishability. D1.4's "indistinguishable" language covers the wire only. | None — oracle-safe rules bind the wire, and audit divergence is the point. | State the asymmetry explicitly in the design so it survives review as intent, not accident. |
| F8 | Info | Wiring `OnUserArchived` makes sweep-driven `INACTIVE → ARCHIVED` revoke sessions/tokens — net-new behavior for deployments already running `auto_deprovision` (previously archive was inert). `ARCHIVED → ACTIVE` restore remains legal and now requires re-login. | Expected semantics of the reference reaction; a release note. | Document in the change's release note; no code impact. |

No Critical or High findings. The design's own risk inventory (D6) is accurate;
F1–F3 are the three items it under-specified.

---

## 3. Decision options

The design's three decisions are the smallest viable options; I compared the
alternatives and concur with all three, with one API amendment (F1).

**D1 — Login gate.**
- (a) *Design's option:* pure `AllowsAuthentication` predicate + thin server
  helper, five call sites. Smallest surface; the predicate is unit-testable
  and shared with D2; per-site collapse is provably byte-identical.
- (b) Fold the lifecycle leg into `rejectDeactivatedUser` (one SCIM helper
  gains a second concern). Worse: mixes SCIM and lifecycle failure modes,
  couples the fail-open SCIM posture to the fail-closed lifecycle posture,
  and still requires extracting ≥15 lines from a 493-line file. Rejected.
- (c) A separate middleware/hook seam (e.g., an authenticator wrapper).
  Over-engineered: five call sites, one of which is not in the login chain
  shape; adds an extension point nobody asked for. Rejected.
- **Preferred: (a) with F1's amendment** — parameterize the helper's denial
  shape (or inline site 4), and pin that both helper variants live in
  `server_login_auth.go` post-move.

**D2 — Refresh gate.**
- (a) *Design's option:* direct `RefreshGrantDeps` method + `*sso.Server`
  accessor, gate between liveness and resolve. Compile-enforced by the
  existing `var _` guard; zero test doubles exist today; nil-store and
  no-record are byte-identical no-ops.
- (b) Optional-interface runtime assertion (`if lc, ok := d.(interface{...})`).
  Defeats the guard pattern, silently skips the gate if a future implementor
  forgets the method, and is the pattern the codebase explicitly moved away
  from for grant deps. Rejected.
- (c) Gate inside `*sso.Server`'s refresh wrapper instead of the handler.
  Duplicates the collapse logic at the edge, splits one invariant across two
  files. Rejected.
- **Preferred: (a).** Document the outage burn-and-kill interaction (F2) in
  the same change.

**D3 — Transition-time revocation.**
- (a) *Design's option:* `RevokeAccessOnSuspend` sharing the extracted legs,
  bus registered via `recorder.AddSink` in `wireUserLifecycle`, synchronous
  `On`, no new `sso.Option`. The bus and the reference reaction already
  exist; zero new machinery; the admin 200 implies revocation done; the
  wiring test's opt counts stay green.
- (b) Direct call from the admin handler and the sweep. Duplicates the
  reaction dispatch in two drivers, forks the seam, and bypasses the
  documented reaction pattern. Rejected.
- (c) New `sso.Option` exposing reactions to SDK embedders. Breaks
  `userlifecycle_wiring_test.go`, grows the frozen API, and the embedder path
  already exists (bus + `AddSink`, documented in `lifecyclereactions/doc.go`).
  Rejected.
- **Preferred: (a).** The audit-disabled warning is the right failure mode
  (reactions inert, read gates still hold); keep it a warning, not a boot
  failure.

**Build-vs-buy.** No external product supplies an embedded OAuth lifecycle
gate; the domain predicate + existing bus is the smallest in-tree option.
Nothing to buy.

---

## 4. Prioritized implementation sequence

**Milestone 0 — Contract updates in the same change (AGENTS.md §5.6).**
Revise the three stale "NEVER gates authentication" docs (`options_admin.go:277`,
`docs/config-reference.md:695`, `domains/userlifecycle` package doc); reconcile
`docs/error-codes.md:139` (423 → 403) for `account_locked`; add the
`config-reference.md` failure-mode paragraph (fail-closed self-lockout,
refresh burn-and-kill, monitoring guidance).
*Acceptance:* `grep -rn "NEVER gates" .` returns nothing; `docs/error-codes.md`
row matches the code.

**Milestone 1 — D1.** (1) Extractive move of the device block (lines 268–340)
to `server_login_resolve.go`; (2) `AllowsAuthentication` + `MetaLifecycleState`
const; (3) helper(s) per F1 in `server_login_auth.go`; (4) five call-site
guards; (5) variadic meta on `recordLoginFailure`/
`audit.RecordLoginFailure`/`audit.RecordCallbackFailure`.
*Acceptance:* `go build ./... && go vet ./...`;
`go test -run 'TestMaintainability_|TestArchitecture_' .`;
`wc -l` shows ≤500 on both touched files; table test over the six states;
byte-compare denied body against the SCIM path at sites 1–3 and the
callback-failure body at site 4; store-error injection → deny; nil-store →
byte-identical.

**Milestone 2 — D2.** (1) `LifecycleState` on `RefreshGrantDeps` +
`*sso.Server` accessor (`options_admin.go`); (2) gate between liveness and
resolve with `invalid_grant` collapse; (3) placement test in `tokengrant`.
*Acceptance:* `go test ./... -race`; refresh-denied body byte-identical to
unknown-token; family unchanged with no bus wired and no client retry;
store-error injection → fail-closed deny; reactivation restores rotation for
a surviving family; `grep -rn "RefreshGrantDeps" --include='*_test.go'`
reviewed for doubles before committing.

**Milestone 3 — D3.** (1) `protocols/lifecyclereactions/revoke_on_suspend.go`;
(2) `wireUserLifecycle` bus wiring + warning; (3) wiring-test extension.
*Acceptance:* `go test ./... -race`; transition → session cookie 401,
`RefreshTokenSubjectIndex` empty, refresh → `invalid_grant`; idempotent second
run; one-store-error isolation (`errors.Join`); `audit.enabled: false` boot
warning; `len(b.opts)` assertions unchanged.

**Milestone 4 — Full gates.**
`go test ./... -race && go test ./test/ -run TestE2E -v && make ci`.

**Compatibility plan.** Unwired builds (`user_lifecycle.enabled: false`) are
byte-identical by construction (nil-store no-ops, unregistered bus). No-record
users are unaffected (Store contract). The only behavioral deltas are gated
behind `user_lifecycle.enabled`: new denials (intended) and archive-time
revocation (F8, intended). The `account_locked` status in docs is the only
contract correction, and it aligns docs to code.

**Risks during implementation.** The device-block move must be pure (same
package, no behavioral delta — intra-package references make it safe); the
`RefreshGrantDeps` break is compile-enforced but must be checked for
uncommitted doubles; the site-4 helper shape (F1) is the likeliest source of
design drift; keep the gate ordering (after SCIM, before side effects) in
tests, since it is the security invariant.

---

## 5. Unknowns needing owner/product decisions

1. **Token-exchange parity (F3).** Should `HandleTokenExchangeGrant` carry the
   same lifecycle gate in direction 1, or is "document as residual, die at
   first rotation" acceptable? The design's scope says login + refresh only;
   ratify the boundary.
2. **Fail-closed self-lockout posture.** A lifecycle-store outage denies all
   logins/rotations byte-indistinguishably from suspension. The spec pins it;
   product must ratify the availability tradeoff and the monitoring story
   (log + `login_failure` stream as the only differentiators).
3. **INVITED semantics.** Denying INVITED login is safe only while no
   production INVITED writer exists. When the future invitation flow lands,
   "accept invite = first login" must advance INVITED → ACTIVE before
   authentication. Confirm the direction-2 plan carries that contract.
4. **Multi-replica convergence.** The memory-only store and per-process bus
   inherit the state machine's divergence (direction 3's SQL peer is the
   fix). Confirm direction 3 is still on the roadmap; the refresh gate's
   blast-radius narrowing is real but not convergence.
5. **Restore-from-archive UX.** `ARCHIVED → ACTIVE` remains legal but now
   requires re-authentication of every session (F8). Confirm that is the
   desired product behavior for the reference reaction.
6. **`account_locked` doc reconciliation.** The doc currently promises 423;
   the code ships 403. Aligning docs to code is the only non-breaking move,
   but the 423 row may reflect an earlier product intent — confirm 403 is the
   intended wire status before Milestone 0 locks it in.

---

## Verdict

The design is sound, thoroughly verified, and correctly maps to the layer
graph: predicate + bus in the domain, reactions in protocols, gates at the
interfaces edge, wiring in the composition root — no boundary crossed, no
exemption needed, no new storage. The three decisions are the smallest viable
options; the failure-mode inventory is honest and complete modulo F1–F3. The
mandatory device-block move is not cosmetic — it is the only legal way to add
the helper under the frozen budgets. Proceed to implementation with the F1
amendment (site-4 helper shape) and the F2 documentation, both folded into
Milestone 0/1 so contracts and code land in the same change.
