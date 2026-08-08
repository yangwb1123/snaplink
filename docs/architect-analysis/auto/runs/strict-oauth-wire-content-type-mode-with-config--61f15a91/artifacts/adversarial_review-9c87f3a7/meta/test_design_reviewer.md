Audit complete. Report written to `docs/architect-analysis/auto/runs/strict-oauth-wire-content-type-mode-with-config--61f15a91/artifacts/adversarial_review-9c87f3a7/meta/acceptance_mapping_audit.md`.

## Summary

**Verdict: every acceptance claim is testable with a concrete owner, and every byte-level golden checks out against HEAD — with three fixable gaps that must be pinned in the implementation report.**

**What I verified against HEAD** (all 12 byte/behavior claims):
- `{"error":"invalid_request"}\n` = 28 bytes exactly (`ctx.JSON` → `json.Encoder` adds `\n`; no `trace_id` by default) and `"{}\n"` = 3 bytes (`handle_revoke.go:111`) — computed, both exact.
- `Cache-Control: no-store` + `Pragma: no-cache` stamped pre-bind on all four endpoints; strict 400 carries no `WWW-Authenticate` (bind fails before client auth).
- Permissive `default:` JSON branch (`bind.go:43-46`), `setFormField` (`:112-134`) has no RawMessage case → the PAR RAR/claims silent drop is real (`rar.go:153-156` passes empty), pinning the AC-8 caveat.
- JSON-acceptance regression lock exists (`postToken` :59, `TestToken_BadJSON_400` :87, `postIntrospect` :89, `postRevoke` :237 — all `application/json`).
- Fixture patterns all exist: A4 schema walk (`main_test.go:185`), `TestRun_Validate_ScopeRegistry_*` exit-code fixtures, `additionalProperties:false` (`generate.go:179`), loader warn-only (`source.go`), fan-out ceilings (12/12, 60/60), `newPARHarness` for `/par`.

**Findings:**
- **F1 (blocking)** — the AC-1..AC-8 numbering exists nowhere; the summary conflates this run's T-8(e) (byte-identical-off) with the lineage's timing test. Check set is complete; the implementation report must publish the canonical 8-row table.
- **F2 (blocking)** — C3's "key family" is unenumerated (live key only, or + dead lineage key?) and "raw scan" semantics undefined (line-anchored vs substring, comments/JSON configs). Four fixture outcomes must be pinned (`false`→1, wrong-block→1, `true`→0, absent→0); note rollback-by-`false` is thereby impossible by design.
- **F3 (blocking)** — `oauthwire/bind_test.go` is a pure new-file obligation: **zero** BindParams unit coverage exists today (only `FuzzBearerToken`/`FuzzBasicClientCreds`); without it, AC-4's unit half and the drift lock are ownerless.
- **F4–F7 (non-blocking)** — timing leg needs the every-position deterministic table (absent today); startup log line has no test owner (ops-observable); `/par` row needs the PAR dep set in the strict harness; byte-compares must use identical trace context.
