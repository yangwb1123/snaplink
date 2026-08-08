All checks pass (§4.5 is item 5 of §4's numbered list — same convention as the doc's §4.2/§4.3/§4.6 references; consistent). The reconciliation is complete.

## Summary

**`docs/architect-analysis/auto/cmd-sso-ctl-apiclient-design.md`** rewritten (475 lines) with all three reviews' amendments folded in, plus a new **§0 traceability table** mapping every amendment to its landing site.

### Required amendments incorporated

**CLI conventions (F-1/F-2/F-3, F-4/F-5):**
- **F-1** — no credentials is now missing-required-input **exit 2** + usage, nothing executes (tree convention: configcmd `--file`, importcmd `--format`, auditverify `--bearer`); row 25 rewritten, REQ-1's superseded "skip, exit unaffected" text flagged inline. New skip rule: a group is skipped only when its required advertised target is absent (T-9 without `introspection_endpoint`); any skip forces `check INCOMPLETE` + exit 1 (auditverify "not the full chain" precedent) — **`check OK` is never printed on a skip-run**, stated in §3.1, §5 header + skip-rule paragraph, §6, §7 A8.
- **F-2** — `flag.ContinueOnError` + explicit `errors.Is(err, flag.ErrHelp) → return 0` (usage on stderr), documented as the tree's first `ErrHelp` special-case; A1's `TestCheck_HelpExitsZero` pins it.
- **F-3** — preflight validates the **effective** addr (env `SSO_ADMIN_ADDR` wins, §2.1 four rules: absolute http(s), non-empty Host, no userinfo, no query/fragment); exit-2-for-bad-URL marked as a deliberate deviation from auditverify's exit-1 classification.
- **F-4/F-5** — `--addr` vocabulary note + collect-all-failures flagged as the tree's first non-fail-fast `Run`.

**Security (items 1–4):**
- **Item 1 (blocking)** — `WithNoRedirect()` additive option (~6 lines after `WithAddr`, opt-in, existing callers untouched) + `TestNew_NoRedirect`; 3xx semantics pinned (truthiness rows pass, content rows fail); §3.3 narrowed.
- **Item 2** — userinfo/empty-host/query-fragment rejection, never-echo, advertised-URL userinfo = row 2 failure.
- **Item 3** — R7 body-echo pin (non-2xx only, decode error only, ≤200 bytes) + shared `redactURL`/`sanitizeBody` global pin on rows 1/4/7/19/22/24, R20 body-less, scope never printed.
- **Item 4** — crypto/rand pins: failure → exit 1 (no `math/rand` fallback), 62-char charset, never on stdout/stderr.

**Test plan:** A1 relocated to `TestSubcommands_CheckIsWired` in `dispatch_test.go` (§7 header corrected); testkit line drift fixed (:21-50, :61-281, 290 lines); all six gap-closing tests + two data-driven extensions added; golden-determinism pins.

### Consistency verification (your checklist)

1. **§3.3 vs WithNoRedirect** — claim narrowed: *request/response surface unchanged; `New` gains exactly one additive opt-in option*; consistent across §0, §2.4, §3.2, §6 (implement/rollback steps), §8 (apiclient.go 188→194 lines).
2. **25-row table** — still exactly 25 rows (verified by grep); rows 1/4/7/19/20/22/24 carry the redaction/echo pins; redirect posture added as a pinned paragraph (truthiness 3xx-pass, content-row 3xx-fail) rather than a new row, keeping the test-mapping doc's row numbering intact.
3. **A8 + skip rule** — exit contract, skip rule, rows 24/25, §6 step 4, and §7 A8 (`TestCheck_NoCredentialsMisuse` replaces the old skip-run test; `TestCheck_T9SkippedIncomplete`; `TestExitCodes` covers env-side bad addr and `-h`→0) all state the same 0/1/2 + never-OK-on-skip contract.
4. **§7 vs amended rows** — every one of the 25 rows now maps to a test (verified: all 39 named tests present); A1 in `dispatch_test.go`; row-coverage block closes rows 1/4/7/8/9-14/17/18; A7 gained `TestIntrospect_SkipWhenNotAdvertised`; A3 gained the decoy canary and userinfo/empty-host row variants; A2's discovery test covers the 302 content-row case.

No stale contradictions remain (grep-verified: old line citations, `usageErr`, "never failures", "harmless there", "reused as-is" all gone; the remaining hits are explicit correction annotations). Doc-only change — no `.go` edits made, no gates triggered.
