All evidence gathered. Here is the verification report.

---

# Verification: sibling-campaign merge-idempotency, T-8(e) naming, landing order

**Artifacts compared:** sibling = `cmd-sso-ctl-b4-4-check-probes-form-{requirements,design}.md` (run `align-sso-ctl-check-probes-with-b4-4-form-urlenc-30afe1ff`, **design gate verdict: FAIL**); strict-mode server = run `enforce-form-urlencoded-credential-strict-mode-0a8df02f` (requirements + design + rollout-review); current = `cmd-sso-ctl-apiclient-b4-4-form-probes-{requirements,design}.md`. Working tree re-verified: all five token.go sites are JSON today (mint :72, revoke :244-246, post-revoke introspect :259-261, T-8d :297-303, T-9 :353-357, `%q` diagnostic at :368); `newLiveServer` fixture (check_test.go:71-92) sets no strict option.

## Claim 1 — Sibling flips the same five sites to the same form semantics: **CONFIRMED**

| Dimension | Sibling (T-8b design) | Current (T-8(e) design) | Verdict |
|---|---|---|---|
| Five sites | mint :72, revoke :244-246, post-revoke :259-261, T-8d :297-303, T-9 :353-357 | identical five | ✅ Same |
| Resulting bodies | `url.Values`; `scope` only when `!= ""`; `resource` repeated per entry; T-9 = `token=sweep-probe-dummy` | identical (incl. T-9 via `strings.NewReader(…Encode())`) | ✅ Same |
| Headers | `Content-Type: application/x-www-form-urlencoded` exact (no charset), `Accept: application/json`, bearer only when `c.token != ""`, `c.http` carries the pin | identical | ✅ Same |
| Pins | `{"error":"invalid_scope"}\n`, `{"error":"invalid_client"}\n` (:366-367), `{"active":false}`, refresh_token rejection (:96-99), T-9 bare bearer-less client | identical, all preserved | ✅ Same |

The **only** substantive divergence is the new row, and it is outside the five flips: sibling's T-8b (legs `text/plain` + **absent CT**, byte-identical `{"error":"invalid_request"}\n` modulo one top-level string `trace_id`) vs current's T-8(e) (legs `application/json` + `text/plain`, class-based 4xx + JSON envelope). Both rows converge to the same verdict against both real server states (permissive → 200 → FAIL; strict → `400 invalid_request` → PASS), because the strict contract (0a8df02f R3/R5) rejects `application/json`, `text/plain`, and absent CT identically. Nits only: `wantBody` line cited :316-317 vs :310/:326; design §3's "`%20` on the wire" should read `+` (wire reviewer). "Same headers, same pins" — exactly true.

## Claim 2 — Both campaigns' T-8(e) labels resolve without wire impact: **CONFIRMED**

- `docs/proposals/audit-contract-batch-snaplink.md:18` lists T-8(b/c/e) exact semantics as **unclaimed** — the label is free-floating by design.
- Three disjoint meanings coexist: **current** T-8(e) = its new wrong-CT row; **sibling** T-8e = the existing refresh_token rejection (verbatim from the supplied acceptance; its new row is T-8b); **strict-mode** T-8(e) = the constant-time timing test (0a8df02f R6/AC-5).
- Both sweep specs document the collision (current requirements finding 7: "This direction's T-8(e) is the wrong-Content-Type row itself…"; sibling requirements §3 non-goal: "here T-8e is only the existing refresh_token rejection").
- Wire impact: nil — labels appear only in prose; no body, header, pin, test name, or wire byte derives from a label, and each row's verdict is well-defined per server state (verified above). The strict-mode campaign never references either sweep label (its AC-1..AC-5 mapping is self-contained).

## Claim 3 — Landing order cannot leave the sweep half-green, falsely red, or conflicted at token.go:368: **CONFIRMED, with one real qualification**

The decisive fact: strict mode is **config-gated default-OFF** (R1 `security.strict_credential_content_type` default false; R2 `WithStrictCredentialContentType()`), and R4 leaves `BindParams` untouched (new `BindParamsFormOnly` entry only). Consequences:

- **Order-independent module suite.** The fixture never sets the option, so the REQ-0 gate (six root causes) and all five flipped probes behave identically whether strict-mode lands before or after — strict-first cannot falsely red the REQ-0 gate.
- **No half-green.** Flips-first: only the `content_type` row turns red against a permissive server — the intended, truthful detection, with every other row green. Strict-first with live servers: old JSON binary → loud `mint: FAIL` (sibling D1; rollout constraint M3 ships binary+server together) — fully red, not half-green, and truthful.
- **No conflicting REQ-0.6 edit.** `token.go:368` is touched only by the current campaign. The sibling's T-9 flip edits :353-357 and leaves :366-368 untouched (no diagnostic change anywhere in its spec); the strict-mode campaign has zero `cmd/sso-ctl` edits (its only intersection is `sso-ctl config validate-schema`, which is reflection-generated and needs no sso-ctl change); the ratelimit docs citing "token.go:363-377" refer to `interfaces/sso/server_token.go` — a different file. No conflict.

**Qualification (must fix before implementation):** the design's "`TestSweep_ContentTypeRowFailsToday` flips to green only when the strict-mode server campaign lands" (design §5, requirements §10, REQ-8.3) is **incomplete**: with default-off gating, the strict-mode landing alone does *not* flip the fixture-based pin — `newLiveServer` must opt in (`WithStrictCredentialContentType()`), and that edit plus the pin-expectation flip are filed in **no** campaign (0a8df02f's rollout-review references sso-ctl only as `config validate-schema`; the sibling's design gate FAILED on exactly this finding, cross_campaign_coordination_reviewer §A). Without an owner, the pin sits green-asserting-red and the module gate never reaches green. Not a false color — an unowned terminal-state edit. The current campaign should file it (or amend the strict-mode rollout-review to name the sweep as its verification instrument).

**Secondary observations (in-campaign, adjacent to the claims):**
- **F1 ordering** (security reviewer, must-fix): the current design schedules the `handleIntrospect` wire-agnostic fix in step 5, but it is the *enabling* harness fix for the step-3 flips — 10 stub tests break in between. The sibling's M1 already ships the harness rework with the flips; fold the fix into step 3.
- **Sibling-gate-class gap not yet enumerated:** `TestSweep_3xxTruthinessPasses`' custom `/token` handler (check_test.go:685-700) mints for any non-empty non-probe body → once runT8e is wired, its T-8(e) legs are served 200 → `content_type: FAIL` → exit 1 + golden mismatch. REQ-8 doesn't list that handler update (the sibling gate FAILED on the identical defect).
- **"Merge idempotently" scope:** true per-site for the five flips via rebase-on-first (the current design says exactly this: "If the sibling lands first, this design rebases onto single-point flips"). It does **not** extend to the full change set — both campaigns create `token_contenttype.go` and both rewrite `goldenGreenStdout`/`CheckRun`, so a second landing needs conflict resolution, not auto-merge. Moot in practice: the sibling's gate verdict is FAIL with all blocking findings unresolved, so the current campaign is the live successor. If both rows were ever merged, their verdicts agree on both real server states but could diverge on a hypothetical partial-enforcement server while emitting the identical `content_type:` line — the design's "line-order merge decision" row already concedes that ambiguity.

## Bottom line

Two of the three claims hold exactly (same five flips/headers/pins; T-8(e) labels are docs-only with three documented meanings). The landing-order claim holds for wire and color — no order produces a half-green or falsely red sweep, and token.go:368 has exactly one editor — **except** the "flips green when strict-mode lands" phrasing overstates the strict-mode campaign's scope: the fixture opt-in is unowned, and the two in-campaign suite gaps (F1 step-3 ordering, `TestSweep_3xxTruthinessPasses` handler) should be folded into the design before implementation.
