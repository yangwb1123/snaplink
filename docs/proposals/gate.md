All review deliverables read; key claims re-verified against code at HEAD `0b382caf` before ruling: `matchPolicy` first-match (`registry.go:139–153`), `unmarshalPolicy` plain `json.Unmarshal` (`sqlite/policy_store.go:171`), strict-then-lenient config fallback (`config/source.go:257–290`), the three `build_governance_test.go` sites consuming the single `ActionResult` (516/544/569), and a repo-wide grep confirming **no parity test exists**. The design file (`mtime 19:14`) predates all reviews (19:21–19:29) and is unmodified — no amendment has been made.

# Gatekeeper cross-check: review findings vs. design

| # | Finding (sev) | Design status at HEAD | Ruling |
|---|---|---|---|
| C-1 | Accumulation contradicts the byte-identical hard constraint; spec §2 acceptance ("suspend only") fails under Decision 3 (High, release gate) | **Unresolved.** Design Decision 3 still replaces first-match with unconditional `matchPolicies`; header constraint text unchanged; no field-gating; failure-mode list #1–#9 never acknowledges it; no pinning test specified | **Not resolved, not dismissed** — T1 decision (maintainers + security) never made |
| C-2 | Mixed-version read side: old replica silently evaluates new-format policy as noop, no audit (High) | **Unresolved.** FM4 covers only write-side blob stripping; no mention of config-seeded path or read-side noop; verified plain `json.Unmarshal` + lenient fallback make it real | **Not resolved** |
| C-3 | "Existing cross-store parity test" does not exist (High for the guarantee) | **Unresolved, claim still factually wrong.** Design §Storage:197 and spec:136 still say "existing cross-store parity test … is extended"; grep confirms no `Parity` test anywhere in `domains/threataction` | **Not resolved** |
| C-4 | Blast-radius table omits the 3 `build_governance_test.go` sites that consume the return value (Medium) | **Unresolved.** Table lists only in-package tests + doubles; verified sites assert `result.Action`/`result.OK` and must move to `results[0]` | **Not resolved** |
| C-5 | Runner's executor-failure branch untested; dead for the composite after the change (Medium) | **Unresolved.** Design's "consequence to document" paragraph misstates the situation (runner_test.go has no failing double) and commits to no pre-change test | **Not resolved** |
| C-6 | Zero E2E/wire-level coverage of the whole feature (Medium) | **Unresolved.** No `test/` ssotest case, no mount/gate round-trip commitment anywhere in the design | **Not resolved** |
| C-7 | `default_action` silent takeover warning deferred (Medium per security; Info per QA) | **Dismissed with reasons.** FM9 explicitly defers with rationale (crosses `build_governance.go` scope); interplay documented, but no pinning test named | **Dismissed with reason — acceptable as a documented deferral, flagged** |
| C-8 | `invalid_policy` row enumeration goes stale (Low) | **Dismissed with an incorrect reason.** Design: "No `docs/error-codes.md` change (no new `Err*')" — reviewers agree no new `Err*` is needed; the concern is row enumeration drift, unaddressed | **Not resolved** |
| C-9 | `""` entries from config-seeded path: execution semantics unpinned (Low) | **Unresolved.** Admin rejection specified; config path bypasses validation (`BuildThreatAction` seeds via `store.Put`); "empty after resolution" edge wording is ambiguous | **Not resolved** |
| C-10 | `ActionResult.Detail` unpinned for panic path and all-noop fallback (Low) | **Unresolved.** Panic → `OK:false` + log + audit, no `Detail: "panic: …"`; all-noop → byte-identical legacy result but `Detail` (today `"policy action is noop"`, registry.go:107) not pinned | **Not resolved** |
| C-11 | Config-seeded negative `priority` accepted, sorts highest (Low) | **Unresolved.** Admin-only rejection stated; no config-reference note, no seed-time guard option recorded | **Not resolved** |
| C-12/C-13 | `threat_action_executed` unclassified in auditreport; "both set → Actions wins" overclaim (Info) | Pre-existing/PR-note class; overclaim not corrected | Info — non-blocking |

## Ruling

- **Resolved:** none.
- **Dismissed with reasons:** only C-7 (explicit, documented deferral in FM9); C-8's dismissal rationale is mistaken and does not address the actual concern.
- **Blocking:** C-1 and C-2 (both High, independently confirmed by multiple reviewers and my re-verification), plus the two factually wrong planning claims C-3 and C-4 that the design still asserts as true. C-5 and C-6 are the remaining Medium preconditions the principal listed as required before implementation.

The design has not been amended in response to any review; every High and most Medium findings remain open as of HEAD `0b382caf`.

VERDICT: FAIL - C-1 (accumulation contradicts the byte-identical hard constraint and spec §2 acceptance; no T1 decision recorded), C-2 (mixed-version read-side silent noop unaddressed), C-3 (parity test asserted as "existing" but must be created), C-4 (blast-radius table omits the consuming build_governance_test.go sites), plus unresolved preconditions C-5 (runner failing-executor test before the interface change), C-6 (zero E2E coverage). Only C-7 is explicitly dismissed with reasons; all other findings remain open. The design must be amended (constraint narrowing or field-gated accumulation with a pinning test, read-side mixed-version note, parity test creation, corrected blast-radius table) and re-reviewed before implementation starts.
