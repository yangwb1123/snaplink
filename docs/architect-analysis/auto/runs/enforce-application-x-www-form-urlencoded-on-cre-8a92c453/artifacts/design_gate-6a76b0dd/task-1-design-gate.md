Independent verification complete. Here is the evidence-based assessment.

## What I verified directly against the working tree

**Blocking findings and their current disposition:**

| Finding (source) | Severity | State in design doc (05:07:41, the only post-review revision) |
|---|---|---|
| **A1** — log emission must move to the 8 call sites; `oauthwire` cannot emit (`core.HandlerContext` has no logger; `oauthwire` is a leaf) | High, "must fix before implementation" | **UNRESOLVED.** §3.1 still specifies `oauthwire.BindParamsFormOnly(ctx core.HandlerContext, v any)` emitting the Info line inside `oauthwire`. I confirmed `shared/core/router.go:17-34` exposes no logger member, and the design exports no `IsFormOnlyRejection`/`FormOnlyRejectionClass` |
| **A2** — per-class token bucket (≤2/s/class, burst 10, global ≤8/s) + bounded-emission acceptance case | Medium, "must bound" | **UNRESOLVED.** Zero occurrences of token bucket/rate cap/Metrics counter/bounded emission in the design; the only "rate limit" text is the unrelated probes/middleware note |
| **IntrospectDeps lacks `SrvLogger()`** (perf reviewer's A1 gap) | Blocking (part of A1 fix) | **UNRESOLVED.** Verified `handle_introspect.go` has no `SrvLogger`/`Logger` today; the design adds only `RequireFormContentType() bool` |
| **setFormField `json.RawMessage` case** (migration_plan + sdk reviewers: form-PAR `authorization_details`/`claims` silently bind nil) | Blocking prerequisite | **UNRESOLVED — contradicted by the design.** §3.2 explicitly says "`RawMessage`/`claims` branch untouched"; step 8 does not adopt the sibling's F-A |
| **gensdk 4-op vs 8-site mismatch + absent `postCIBA`** (sdk reviewer: generated device/MFA flows 400 post-flip) | Blocking | **UNRESOLVED.** No `usesFormBody` reconciliation, no 7-op count, no `postCIBA` mention; step 8 unchanged ("form emission for credential ops") |
| **Migration sweep corrections** — 19 test files/48 posts + 24 interface files/92 posts + 3 protocol sites = 143 posts; per-call-site `rcovDo` mechanic; **four fakes, not six** | Blocking for `make ci` | **UNRESOLVED.** Design still says "Six fakes gain `RequireFormContentType() bool`" (:122; I confirmed `var _ IntrospectDeps` at `handle_introspect_test.go:78` and reviewer-verified four types); step 5 inventory unchanged |

**What is resolved:** the http_wire_reviewer's case-table gaps — §3.6a (24 rows U1-U15/E4b-E16), the §3.2 validated-wire-semantics bullet, and extended §3.6 rows are present in the design ("review-added" marker at :171). Security findings C and D needed no design change and are consistent with the design. The migration_plan_reviewer's "four corrections" live only in its meta artifact, not in the design.

**No explicit rejection with evidence exists anywhere:** `DECISIONS.md` contains only stage-pass logs; no disposition/wontfix file exists; the design doc (05:07:41) and requirements doc (04:55:49) both predate migration_sweep (05:12:53), migration_plan (05:18), sdk (05:19), and perf (05:20) reviews, and nothing newer than 05:20:42 touches the design. The design_gate stage has not run (HEAD = `67e257e1` adversarial_review).

VERDICT: FAIL - A1 (emission point unimplementable, High/must-fix), A2 (log-flood bounding), the `setFormField` json.RawMessage prerequisite, the gensdk 4-op/8-site mismatch, the 143-post migration corrections (incl. four-vs-six fakes), and the `IntrospectDeps.SrvLogger` gap are all neither resolved in the design nor explicitly rejected with evidence, leaving the log-flood exposure, silent nil-binding PAR claims, and a red `make ci` as accepted design states.
