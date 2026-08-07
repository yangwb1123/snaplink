**F1 disposition: CONFIRMED — raw paths (and op values) must be omitted.** Both deliverables are in place: the design doc corrected (9 edits) and the disposition report at `docs/architect-analysis/cmd-sso-operator-controller-b4-3-truthiness-f1-disposition.md`.

## Determination (Q1)

**Yes, as written the error text embeds cluster-B-response-derived bytes, and they reach the persisted CRD `Status.Message` unconditionally:** `validatePatch` errors embed `op.Path` and the op value (design §3.1 examples) → `runCheck` wraps in `cluster B diff response failed structural validation: %s` → `applyResult` sets `cr.Status.Message = result.message` unconditionally (`ssoconfigdrift_controller.go:180`) → `Status().Update` persists. `validateRunningSnapshot` is static — safe.

**Must they be omitted? Yes.** The decisive reason is a *boundedness* regression, not a secrecy one:
- Today's server-authored echo is capped at 200 bytes (`describeAPIError` `maxLen=200`), and a 2xx patch body contributes nothing to Message (only `len(patch)`). The design's path echo would be unbounded (`io.ReadAll` bounded only by the 15s timeout): a malicious cluster B streams a multi-MB path into `Status.Message` → `Status().Update` pushes an over-limit CR object → permanent reconcile backoff wedge. So "same trust class as `describeAPIError`" is only half-true as designed — the content class matches, the size bound does not.
- Omission also makes the corrected security claim *literally* true (only non-static content = bounded integer op index) and costs nothing actionable: the strict-superset property rules out false rejects (200k fuzz, zero), so every violation means the server left its documented emit set — remediation is identical for every shape.

## Confirmation (Q3) — no regression vs today's `describeAPIError`

- **Leak:** content class unchanged (server-authored ≤200 B already flows into Message today); tokens impossible (validators receive neither tokens nor requests; `TestReconcile_MessageNeverContainsBearerToken` + CRD doc pin it); corrected wording echoes *zero* response bytes — strictly more conservative than today.
- **Oracle-safety:** the operator is not an authentication oracle; cluster B already receives the snapshot in the POST body, so key-existence inferences convey nothing new; `failed=true` preserves `DriftDetected`/`PatchOpCount` exactly like every existing failure.
- **Audit:** the operator module has no audit sink/events (doc.go lists an audit trail among non-goals); nothing added or changed.

## Corrections applied (design doc only, no `.go` touched)

D-D rewritten (omission rationale, op-index retention), FM4 re-scoped to "response-derived bytes — none, static-only", FM2 "names the op index and reason class", §3.1 doc comment + error-format examples (`op[2]: unsupported operation`), §4 invariant clause, §7 case 1 (asserts offending op string absent) and case 8 (asserts the exact static message). The spec's "token-free reason" (requirements.md:30) is accurate and unchanged. Adjacent items F2 (file-count arithmetic) and the per-step build+vet wiring remain open for their own dispositions, as noted in the report.
