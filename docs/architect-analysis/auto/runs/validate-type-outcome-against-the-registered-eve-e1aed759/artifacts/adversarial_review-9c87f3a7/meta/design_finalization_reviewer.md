Conformance pass complete. All three items processed on `task-1-design.md`; doc-only change, no `.go` edits, so no build gates apply.

## 1. Three-way double-misuse corner — added and aligned

- **§6 new row** (now row 3, inserted after the `--outcome bogus` + `--verify` row): `--verify <bundle> --dsn <store> --outcome bogus` → exit 2 + banner with the outcome diagnostic, "mutually exclusive" **not** emitted. Notes document today's baseline ("mutually exclusive", exit 2 + banner), the deliberate precedence (`validateOutcome` runs before the exclusivity check, consistent with the §4.2 `dispatch` snippet — verification precedes both the mode branch and the mutually-exclusive check), and that neither store nor bundle is ever touched.
- **§5 bullet aligned**: "`--verify` mode unchanged" now carries the double-misuse precedence clause — same exit class, different message text.
- **§8 mapped**: new deterministic named test `TestRun_UnknownOutcomeBeatsMutuallyExclusive` — `Run([--verify <nonexistent>, --dsn <any>, --outcome bogus])` → 2; asserts stderr contains `not a valid outcome` and does NOT contain `mutually exclusive`. The message, not the exit class, is the discriminator (both misuse paths exit 2), so it pins validation-before-exclusivity. No seeding needed (neither path is opened).
- **Mid-table insertion renumbered cross-refs**: positional refs updated — both-bogus `row 7 → row 8` (§8 AC-1a), dsn-missing `row 9 → row 10` (§8); `row 2` and the new `row 3` verified by grep. §8 intro count bumped "three added tests" → "four", Q2 enumeration now lists three rows gaining tests.

## 2. Stale-claim grep — one residual found and fixed; rest clean

| Check | Result |
|---|---|
| '7 call sites' | Clean — only "8 call sites + definition" (§7 step 2) |
| '44-46' | Clean — sole occurrence is the deliberate "(not 44-46)" correction marker in the §1 evidence table; every live ref (R-4, §4.1) says 29-32 |
| Registry-gap phrasing vs N-1 | **One residual fixed**: §10 claimed the stale "+2" comment is "owned by the MFA recovery-code feature's conformance test" — contradicting N-1 (the "+2" attribution matches neither list). Reworded to the §5-aligned framing: attribution matches neither list; real drift is the hand-transcribed snapshot (129) lagging the 172-entry registry; owned by audit-sink, not fixed here |
| False gap as live risk | None — every occurrence (§2 N-1, §5, §6 hypothetical row, §8 Q2) explicitly marks the gap closed at HEAD |

## 3. §6 ↔ §8 consistency vs AC-1..AC-4 — confirmed

Row-by-row mapping is exact, and the three required named tests are present and deterministic (compile-time registry lookups, return-value exit codes, substring stderr assertions, no timing/concurrency):

- **Both-bogus short-circuit**: `TestRun_UnknownOutcomeExitsTwo` (AC-1a) asserts stderr does NOT contain `not a registered sso event type` — §6 row 8 ↔ §8.
- **Verify-mode row**: `TestRun_UnknownOutcomeVerifyModeExitsTwo` — nonexistent bundle path makes exit 2-vs-1 the branch-order proof; §6 row 2 ↔ §8.
- **No-warning assertions**: `TestRun_TenantAndTypeFilter` (registered `logout`, captureStderr, no-warning assert — AC-2) and `TestRun_TokenTypeFilterExportsAndVerifies` (registered `token_issued`, `EventCount == N`, verifies — AC-3), plus the both-bogus no-type-warning assert.
- Wording parity with `requirements.md` §4 holds: exit 2 naming value + allowed set + no bundle (AC-1a), warning naming value + bundle verifies (AC-1b), empty-window exit 0 (AC-2), conditional `auth.token.issue` extension (AC-3), informational AC-4. Design only strengthens (seeded store, distinctive `not a valid outcome` substring), never weakens.

**Residual drift after this pass: none.** The artifact is internally consistent and AC-mapped; the only remaining out-of-scope drift is the pre-existing stale `auditsink/conformance_test.go` comment itself, which §10 explicitly declines to fix.
