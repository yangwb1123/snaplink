All contested claims verified directly. Here is my gatekeeper cross-check.

# Gatekeeper Review — `token_policy_denied` audit event design

Verified myself: `allKnownEventTypes` is a hand-transcribed snapshot whose own comment states new consts "silently fall back... until a maintainer adds it here" (conformance_test.go:9–19), and the parity check logs via `t.Logf`, never fails (:157–163). `make ci` targets contain no `docs-check`; `docs-check` validates only `error-codes.md`, `openapi.yaml`, `SECURITY.md` existence/cross-refs — **not** `observability.md`. Federated callback passes `clientID=""` (server_oauth.go:220–223); `error-codes.md:262` documents `access_denied` as 400 while code returns 403 (server_oauth.go:226).

## Findings cross-check

| Review finding | Severity | Resolved in design? | Disposition |
|---|---|---|---|
| Compliance F1 — fail-open outage invisible in audit/metrics | Med | **No** | Design's failure-mode table documents the behavior but Decision 4(4)'s observability entry does not require the doc note; availability signal correctly deferred. Amend Decision 4(4). |
| Compliance F2 — no default retention; prune breaks chain | Med | Dismissed w/ reason | Pre-existing, inherited, ops-runbook follow-up; officer explicitly finds no blockers. Track, don't gate. |
| Compliance F3 — audit-query gate is composition-dependent | Low | No | Out of scope; requires one doc note in the observability entry. Amend Decision 4(4). |
| Compliance F4 — name-based attribution | Low | **Yes** | Design risk #4 self-identifies and mandates the doc limitation. |
| QA F1 / SRE F4 — design risk #9 is false (`make ci` does not gate `observability.md`) | Med | **No — design contains a factually wrong claim** | Verified false. A wrong "CI will catch it" assumption changes implementer behavior. Must be corrected. |
| QA F2 / Security F3 / Protocol F3 / SRE F4 — missing fifth registration (`allKnownEventTypes`) | Med/Low, **required before merge** by Security + Protocol | **No** | Verified: without it, OCSF silently falls back to generic class (classUID 0); design's own CEF/OCSF test-plan assertions are unenforced. One-line design amendment. |
| Security F1 / Protocol F1 / SRE F5 — pre-rate-limit, pre-code-validation amplification | Med | No | Verified ordering (server_token.go:168 before :181). Remediation = observability doc note (+ optional follow-up ordering fix). Amend Decision 4(4). |
| Security F2 / Protocol F2 / SRE F6 — `OutcomeFailure` mislabels successful auth-code login | Med/Low | No | Verified: `codeFlowSession` fails open (server_login_auth.go:489–493); design's field-table rationale "a deny is a failed issuance" is false on that path. Doc note + pinned test required. |
| Security F5 / Protocol F5 — empty `clientID` at federated seam | Info | No | Design's Seam B table implies client always present; verified false. Correct table + doc note. |
| Protocol F4 — `access_denied` 400-vs-403 drift | Low | No | Pre-existing, but the observability update should pin 403. Amend Decision 4(4). |
| Security F4 — untyped `reason`; set-membership assertion | Low | Partial | Signature correct as designed; add exhaustive `Reason ∈ {…}` assertion to test plan. |
| QA F3/F4/F5, Protocol F6, Compliance F5, SRE F7 | Info | Dismissed w/ reasons | SOC2 coverage mechanical (good); errStore fixture is test infra; refresh ordering correct; stale RFC citation pre-existing; jurisdiction out of repo scope. |
| SRE F1/F2/F3 — alert rules, engine-silent detection, evidence durability | High/Med (launch) | No | SRE frames as **launch blockers**, all detection/documentation surface, none touching the 493/500 and 481/500 seams. Gate on implementation, but the design must record them as launch-stage requirements so they are tracked, not lost. |

## Blocking issues

1. **Decision 4 is incomplete: a fifth registration is missing.** `allKnownEventTypes` (auditsink/conformance_test.go:20) must gain `auditspi.EventTokenPolicyDenied`, or the CEF/OCSF mappings are never conformance-guarded and OCSF silently degrades to the generic class. Flagged "required before merge" by Security F3 and Protocol F3, echoed by QA F2 and SRE F4. The design's "four registrations, each load-bearing" is authoritative-but-wrong.
2. **Design risk #9 is factually false.** No gate (`make ci`, `docs-check`, or any checks/ script) validates `docs/observability.md`. The risk item must be corrected so the implementation does not rely on a nonexistent CI docs gate (AGENTS.md §5.6 discipline is the only enforcement).
3. **Decision 4(4)'s observability entry is underspecified.** It must be expanded to include the documentation the reviews require in this change: fail-open outage invisibility (Compliance F1), deny-path amplification bounds + `audit.async` mitigation (Security/Protocol F1), `OutcomeFailure`-on-successful-login semantics on the auth-code path (Security/Protocol F2), empty `clientID` at the federated seam (Security/Protocol F5), `access_denied`=403 pin (Protocol F4), and the admin-gate requirement (Compliance F3) — plus the pinned tests: code-flow success-with-event, `Reason` set-membership, mixed unnamed-first-denier `DeniedBy` edge.

All three are cheap, additive amendments — none touches the two one-line seams, the budgets, or the core decisions (oracle safety, single-emission, fail-open/default-off all verified sound). SRE's alert rules and evidence-durability text are launch-stage requirements to be tracked in the design, not implementation blockers.

VERDICT: FAIL - Decision 4 registration list omits the required fifth registration `allKnownEventTypes` (auditsink/conformance_test.go), design risk #9 falsely claims `make ci` gates `docs/observability.md`, and Decision 4(4) omits required observability-doc entries (fail-open invisibility, deny-path amplification bounds, OutcomeFailure-on-success semantics, federated empty clientID, access_denied 403 pin, admin-gate note) plus their pinned tests; amend the design before implementation.
