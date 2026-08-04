# Adjudicated worklist — adapters delivery path (devops × security × QA synthesis)

Adjudicates the three reviews of `docs/design/adapters-delivery-path.md`
(devops engineer, security engineer, QA lead) into one non-contradictory
worklist. Every claim below was re-verified against the working tree at
revision `85faff9f` + uncommitted changes before adjudication; disputed
numbers are resolved to a single measured value, not a compromise.

**Result in one line:** the design's structure stands; four amendments make it
implementable as written — (1) extend testkit wiring (F1), (2) amend the
requirements acceptance text (M1/F3), (3) correct the recovery-ordering claim
and use `gin.New()` in the example (F2), (4) register `adapters-check` in
`ci.yml` (H2) and land the uncommitted baseline before the capability row
(H1/M3). After these, every finding has a resolution and no residual
contradiction remains.

---

## 0. Independent verification performed for this adjudication

| Claim (disputed) | Measured result |
|---|---|
| testkit wires no auth-code store → 501 | Confirmed: `server_finish_login.go:385` `ErrAuthCodeNotConfigured` on nil store; testkit `NewServer` (`testkit.go:105-127`) passes no `WithAuthCodeStore` |
| testkit client has no redirect URIs → 400 | Confirmed: `seedClient` (`testkit.go:174-188`) sets no `RedirectURIs`; exact-match enforced at `shared/core/types.go:369-370` (`slices.Contains`) → `400 invalid_redirect_uri` (`server_finish_login.go:388-394`) |
| refresh token issued only with store | Confirmed: `server_finish_login.go:212` `if s.refreshTokenStore != nil`; `WithRefreshTokenStore` exists at `interfaces/sso/options_security.go:320` |
| Recovery ordering (design failure-mode 10 vs code) | Confirmed **design is inverted**: `wrapPanicRecovery` is the outermost wrapper (`server_routes.go:399`); `middleware.Recover` is a `defer` (`interfaces/middleware/middleware.go:27-45`); gin `Recovery` is a `defer` inside the engine chain (`gin@v1.12.0/recovery.go:52-60`). Defer LIFO ⇒ gin's Recovery fires first and owns panic bytes |
| `interfaces/sso` file count (devops: 62 / security: 60) | **60** non-test `.go` files (two independent counts) — devops L2 is a non-finding; the ceiling claim holds exactly |
| `storage.production` empty-module-capabilities precedent (design vs security F3) | Confirmed **design claim wrong**: `ops/build/capabilities.json` declares `"module_capabilities": ["storage.production.v1"]` (non-empty). The `[]` row is fine; the cited precedent does not exist |
| `adapters-check` absent from GitHub Actions (H2) | Confirmed: `ci.yml` runs vet (:92), build (:95), `go build ./docs/examples/...` (:106), `go test -race -count=1 ./...` (:117) — no `make ci`, no adapters step |
| PAT in git remote (M2) | Confirmed present in `.git/config` `remote.github.url` (redacted above); not in tracked files |
| `LoginResult` omits `refresh_token` (secF4) | Confirmed: `testkit.go:212-219` (AccessToken/IDToken/TokenType/ExpiresIn/Scope only) |
| `_test.go` exempt from filesize gate (qaF4) | Confirmed: `engineering.yaml` `filesize.ignore_patterns` includes `_test.go` |
| Store types for the fix | `defaultimpl.NewMemoryAuthCodeStore()` / `NewMemoryRefreshTokenStore()` (`aliases_memory.go:41,47`); options `WithAuthCodeStore(store, ttl)` (`options.go:359`), `WithRefreshTokenStore(store, ttl)` (`options_security.go:320`) |

---

## 1. Overlap resolution — duplicate findings merged

| Merge | Source findings | Adjudicated identity |
|---|---|---|
| 1 | security F1 ≡ QA F1 | Same root cause (testkit harness cannot run scenarios 1–3), same evidence, same impact. One work item: **W1** |
| 2 | devops M1 ≡ QA F3 | Same root cause (requirements acceptance text unachievable as persisted), same remediation. One work item: **W2** |
| 3 | security F4 ⊂ QA F6 | F4 is a plumbing detail of F1's fix; F6 is the assertion gap in scenario 2. One work item covering both: **W8** |
| 4 | devops H1 + M3 + QA G1/G3 | Three statements of one governance rule: declared truth must never precede executable evidence. One ruling: **R3 (landing order)** |
| 5 | devops L2 vs security (ceiling verified) | Contradiction resolved by measurement: **60 files, ceiling holds, L2 closed** |

---

## 2. Rulings

### R1 — F1 remediation path: **extend testkit wiring** (not per-scenario harnesses)

**Selected:** extend `test/testkit` with (a) `WithRedirectURI(uri)` (or redirect
URIs on the seeded client), (b) in-memory `AuthCodeStore` + `RefreshTokenStore`
wired by default (or explicit `WithAuthCodeStore`/`WithRefreshTokenStore`
options), (c) raw-body parse of `refresh_token` for scenario 2. All
`defaultimpl.Memory*` real implementations (AGENTS.md §4); zero production
code; `interfaces/sso` untouched (60-file ceiling).

**Rationale:**

1. **The design's single-option claim is only true under this path.** Decision 1
   exists so the matrix is the first real consumer of the testkit harness
   (confirmed: zero in-repo testkit consumers today). Per-scenario harnesses
   (the `dpop_authcode_test.go` shape) would keep the `WithRouter` call-site
   acceptance green while silently abandoning the harness intent — the exact
   "silent divergence" security F1 warns about.
2. **Cost is near-zero and one-directional.** The three protocol scenarios need
   exactly the wiring `auth_code_test.go` / `refresh_token_family_test.go` /
   `dpop_authcode_test.go` already construct: ~3 config fields + 1 option each
   in testkit. The alternative forks that wiring 3× per backend (9 harnesses)
   with no shared point, and testkit stays broken for the next consumer.
3. **The harness is the SDK's importable test-facing API.** Auth-code + refresh
   are canonical protocol flows; fixing the harness fixes every downstream RP
   test, not just this matrix.
4. **Absolute-outcome assertions are added regardless of path** (see W1):
   scenario assertions pin `200` + token presence, not only cross-backend
   equality — this closes QA F1's "all three backends fail identically and the
   semantic compare hides it" trap. With outcome-pinning, the harness-wiring
   choice becomes a structural preference, not a correctness risk.

**TDD proof required:** scenario 1 fails `501`/`400` on all three backends
before the fix; green after. Probe-route tripwire retained (verified sound:
testkit today would silently fall back to StdRouter).

### R2 — M1/F3 byte-identity: **amend the requirements text** (scoped contract)

**Ruled:** accept the design's scoping (byte-identity on the unmatched surface;
status + JSON value + Content-Type prefix + header-set for JSON error bodies)
and amend `docs/requirements/adapters-delivery-path.md` in the **same commit**
as the matrix. Both the acceptance criterion ("404/`token` 错误响应字节与
StdRouter 后端逐字节相同") and 预期行为 item 2 ("断言响应字节一致") get the
scoped wording, with a cross-reference to `docs/adapters.md` §2.

**Rejected:** serializer normalization inside the adapters (production-code
change, contradicts routertest's committed `fiveMethodDispatch` decision,
per-request cost for zero client value). The requirement file is the persisted
gate; the design's scope statement in a not-yet-created doc does not change the
spec — that is the governance gap both reviewers flagged. Post-amendment the
two documents agree and the gate is satisfiable.

**Verification:** `grep` the requirements file for "逐字节" returns nothing
outside the scoped contract wording; requirements and `docs/adapters.md` §2
match.

### R3 — M3/H1 row-commit ordering: **declaration never precedes evidence**

**Ruled:** adopt devops' landing order, which also resolves H1:

- **C1 (evidence):** land the uncommitted `interfaces/adapters` baseline
  (direction 1+2: adapter normalization, conformance suite, hooks) + testkit
  `WithRouter` and F1 wiring + `test/router_backend_matrix_test.go`.
- **C2 (usage):** `docs/examples/embed-gin` + `embed-echo` + smoke tests.
- **C3 (declaration, atomic):** `docs/adapters.md` + DIRECTORY_MAP sentence +
  capability row (`embedding.framework-routers`) + `adapters_check.py` + all
  four registrations **including the new `ci.yml` step (H2)** + requirements
  amendment (R2).

**Rule:** at every intermediate commit, `python cli.py capabilities check`
passes and `git grep embedding.framework-routers docs/feature-matrix.md` shows
the row absent until C3. The row's commit contains its executable evidence and
its CI pin in the same commit — drift window zero. This also converts the
requirement doc's "方向一与方向二均已落地" claim from worktree-only (true today
only in uncommitted state) to committed truth.

### R4 — F2 recovery ordering: **design's failure-mode 10 is factually inverted; correct design + example**

**Ruled:** adopt security F2 in full. Verified: gin's `Recovery` is a defer
inside the engine chain; sso's `wrapPanicRecovery` wraps outermost; defer LIFO
⇒ gin's Recovery catches the panic first, writes plain-text
`500 Internal Server Error`, and logs stack + `secureRequestDump` with only
`Authorization` masked (Cookie/query — which carries `code`/`state`/`iss` —
unredacted). The design's claim that "sso's recovery fires first" is wrong.

- `embed-gin/main.go` uses **`gin.New()`** (no Logger/Recovery), so the SDK's
  outer Recover produces the same normalized JSON `{"error":"internal_error"}`
  as std/echo — the two examples behave identically on the same failure.
- Failure-mode 10 row rewritten to state the true ordering; example comment +
  `docs/adapters.md` §3 document "gin Recovery (if an embedder attaches it) is
  innermost and owns panic bytes" + `GIN_MODE=release` note.
- Embed-gin smoke test adds a panicking route; asserts the SDK's JSON 500 —
  fails under `gin.Default()` today, passes under `gin.New()`.

---

## 3. Worklist

| ID | Sev | Findings | Resolution | Owner | Gate / validation |
|---|---|---|---|---|---|
| W1 | High | secF1, qaF1 | Extend testkit: `WithRouter` + auth-code store + refresh store + redirect URIs (R1); matrix asserts absolute outcomes (200 + valid tokens), not just cross-backend equality | agent | TDD: scenario 1 fails 501/400 pre-fix, green post-fix; `go test ./test/ -run TestRouterBackendMatrix -v` |
| W2 | Med | devM1, qaF3 | Amend requirements acceptance + 预期行为 2 to the scoped contract, cross-ref `docs/adapters.md` §2; same commit as matrix | agent | grep requirements for old literal → absent; both docs agree |
| W3 | Med | secF2 | `embed-gin` uses `gin.New()`; failure-mode 10 rewritten; comments + docs §3 document gin-Recovery-owns-panic-bytes + `GIN_MODE=release`; panicking-route smoke asserts JSON 500 | agent | smoke test red under Default()/green under New(); echo smoke unchanged |
| W4 | High | devH1, devM3, qaG1 | Landing order C1→C2→C3 (R3); row + check + registrations + ci.yml step + requirements amendment atomically in C3; row absent until C3 | agent | fresh `git clone` of merged commit → `make ci` includes green conformance + matrix + adapters entry |
| W5 | High | devH2 | Add `make adapters-check` step to `.github/workflows/ci.yml` (after the `go test -race` step); optional mirror in engineering.yml; check (g) behavioral run stays in the standalone command | agent | regression demo: delete one routertest scenario → GitHub Actions red on the new step |
| W6 | Med | qaF2 | Concurrency subtest outcome-pinned: every concurrent request 200 with expected body; `t.Errorf`/error channel from workers, never `t.Fatal`; post-loop assertion that a subsequently registered route works; no concurrent route registration (unchanged) | agent | inject racy adapter read (revert `snapshotMiddlewares`) → `-race` fails |
| W7 | Low | qaF4 | Check (c) additionally asserts `test/router_backend_matrix_test.go` ≤ 500 lines (and each example dir ≤ 500) | agent | `python cli.py adapters` fails past 500 lines |
| W8 | Low | qaF6, secF4, qaF5 | Scenario 2: first refresh → 200 + new token; old token reuse → 400 `invalid_grant`; rotated token → 200 (family-kill fully pinned). Parse `refresh_token` from raw login body (LoginResult omits it). `/token` error scenario asserts `Cache-Control: no-store` + `Pragma: no-cache` on all three backends | agent | strip `tokenNoStoreHeaders` → matrix fails; rotate-without-invalidating → matrix fails |
| W9 | Info | secF3, qaF7, qaF8, qaF9, devL1, devL2 | Docs corrections: (a) drop the false `storage.production` empty-module-capabilities precedent claim from Decision 5 — keep the verify-immediately-after-generate mandate; (b) note the race-coverage split (`python cli.py adapters` check (g) runs without `-race`; race lives in `make ci` race + `test-e2e`) in `docs/adapters.md` §6; (c) scenario 1 wording: code issuance is `POST /auth/login` returning the code — drop `/auth/callback`; (d) fix stale release.yml header comment (L1, one-line); (e) L2 closed: `interfaces/sso` = 60 files, ceiling exact | agent | doc review |
| W10 | High (ops) | devM2 | Revoke + rotate the PAT in `remote.github.url`; use credential helper; audit workflow secrets for the same value | maintainer | `git remote -v` clean; revocation confirmed |
| W11 | Info | devops §5.5 | Confirm SDK module-proxy/tag-based consumption path or state it explicitly | maintainer | — |

---

## 4. Amended design deltas (exact changes to `docs/design/adapters-delivery-path.md`)

1. **Decision 1** — config gains `router`, `authCodes`, `refreshTokens`,
   `redirectURIs`; `NewServer` appends `WithAuthCodeStore`/`WithRefreshTokenStore`
   when set (or wires memory stores by default); `seedClient` sets a demo
   redirect URI matching the `requestCode` shapes (e.g.
   `http://localhost:9999/callback`); note that `LoginResult` omits
   `refresh_token` so scenario 2 parses the raw login body.
2. **Decision 2** — scenario 1 wording: `POST /auth/login` issues the code
   (drop `/auth/callback`); scenario 2 adds positive path + no-store assertions
   (W8); concurrency subtest gains outcome assertions (W6); add the
   absolute-outcome rule (200 + tokens, not only cross-backend equality).
3. **Decision 3** — `gin.New()` replaces `gin.Default()`; add panicking-route
   smoke; add `GIN_MODE=release` note.
4. **Failure-mode table** — row 10 rewritten (gin Recovery innermost, owns
   panic bytes, unredacted Cookie/query dump); add row 12: requirements
   acceptance text vs tests — resolved by the W2 amendment; row 9's precedent
   reference corrected (F3).
5. **Decision 5** — replace the false empty-module-capabilities precedent
   claim with: "storage.production is the SPI-surface precedent; its
   module_capabilities are non-empty, so validator strictness for a `[]`
   row is a genuine unknown — verify `capabilities check` + `sdk-surface
   check` immediately after `generate`".
6. **Decision 6** — check (c) adds the line-cap assertion (W7); registration
   list gains the `ci.yml` step (W5); check (g) documents the race split (W9b).
7. **Storage model** — the requirements file joins the declared-truth store:
   the persisted acceptance criterion is amended in the same change as the
   matrix, so declared spec and executable tests never diverge.

---

## 5. Coverage verification — every finding resolved

| Finding | Resolved by | Residual risk after amendment |
|---|---|---|
| devops H1 (uncommitted baseline) | W4 / R3 C1 | none — baseline lands before any declaration |
| devops H2 (ci.yml registration) | W5 | none — regression demo proves CI red on scenario deletion |
| devops M1 (spec vs design byte-identity) | W2 | none — grep-verifiable agreement |
| devops M2 (PAT) | W10 | none (operational, out of tree) |
| devops M3 (row ordering) | W4 / R3 | none — zero drift window |
| devops L1 (release comment) | W9d | none (one-line doc fix) |
| devops L2 (file count) | closed | none — measured 60, ceiling exact |
| security F1 (testkit harness) | W1 | none — matrix green on 3 backends with absolute outcomes |
| security F2 (recovery ordering) | W3 | residual documented only: an embedder who *chooses* `gin.Default()` gets gin's panic surface — documented, `GIN_MODE=release` noted |
| security F3 (false precedent) | W9a | none — validator strictness verified immediately after generate |
| security F4 (refresh plumbing) | W1/W8 | none |
| QA F1 (harness blocker) | W1 | none |
| QA F2 (concurrent outcomes) | W6 | none — injected-race validation |
| QA F3 (spec amendment) | W2 | none |
| QA F4 (line budget unenforced) | W7 | none — mechanical check |
| QA F5 (no-store assertion) | W8 | none — strip-header validation |
| QA F6 (refresh positive path) | W8 | none |
| QA F7 (race split) | W9b | none — documented |
| QA F8 (validator strictness) | W9a + design failure-mode 9 | none — verify at implementation time |
| QA F9 (callback wording) | W9c | none |

## 6. Residual-contradiction check (explicit, post-amendment)

| Contradicting pair (pre-amendment) | Post-amendment state |
|---|---|
| Design failure-mode 10 ("sso recovery fires first") vs code (gin defer LIFO) | Rewritten (W3); design now matches code |
| Design D2 "reuse requestCode/exchangeCode" vs testkit wiring (501/400) | Testkit wired (W1); shapes work verbatim |
| Requirements acceptance "逐字节相同" vs design scoped contract | Amended (W2); both documents agree |
| Design D5 "empty module capabilities precedent" vs capabilities.json | Corrected (W9a) |
| "Matrix green" acceptance vs harness that cannot run scenarios 1–3 | Wiring landed (W1); TDD proof required |
| `make ci` gate vs GitHub Actions (H2) | ci.yml step added (W5) |
| Matrix file ~400-line target vs unenforced budget | Check (c) line-cap (W7) |
| devops L2 (62 files) vs security (60) | Resolved by measurement: 60 |

No residual contradiction remains: every design claim that tests or gates can
observe now matches the code, and the two persisted documents (requirements +
design) describe the same contract. The only intentional divergence left is the
documented embedder-choice surface (gin `Default()` panic behavior), which is
stated as a choice, not asserted as a guarantee.

## 7. Implementation order and gates

1. **C1** — land adapters baseline + testkit wiring + matrix. Gates:
   `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`;
   TDD fail-then-green on scenario 1; `go test ./test/ -run TestRouterBackendMatrix -v`;
   `go test ./test/ -race -run TestRouterBackendMatrix`.
2. **C2** — examples + smokes (incl. panic-route). Gate: `make examples`;
   `go test ./docs/examples/... -race`.
3. **C3** — contract doc + row + check + all registrations + ci.yml step +
   requirements amendment, atomically. Gates: `python cli.py capabilities
   generate && capabilities check && sdk-surface check` (immediately, per F3);
   `python cli.py adapters`; `python cli.py check-test`; `make ci`.
4. **Regression demos (once, throwaway branch):** delete a routertest scenario
   → CI red via `adapters-check`; delete `RegisterGated` → red via race +
   check (b); drop testkit pass-through → matrix probe fails.
5. **Fresh-clone proof:** `git clone` the merged commit → `make ci` green
   including conformance + matrix + adapters entry.
