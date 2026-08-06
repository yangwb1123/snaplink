Independent verification complete. I re-checked every contested claim against the worktree rather than trusting the reports:

**Verified as correct (non-blocking):** seam ordering (server_token.go:132 before denyTokenScopeCombo :137), discovery pre-filter (server_discovery_cache.go:170), byte-identical plain `{"error":"invalid_scope"}` body (reject.go:37), build/vet clean, `TestScopeRegistry` 8/8 PASS.

**The critical finding — confirmed in code:** in the refresh flow `store.Consume` (token_refresh.go:116) runs **before** `RejectUnregistered` (:167). A registry rejection burns the leaf; a retry returns `ErrRefreshTokenReused` with non-nil `FamilyID` (memory_refresh_token.go:177, redis/refresh_token.go:239) → `DeleteFamily` → family kill + 400 `invalid_grant`. The migration reviewer's "rejections retryable / same token works post-rollback" is false, and the design's "drain / rollback-by-flip" framing rests on it.

**Unresolved in the design** (task-1-design.md finalized 14:31, before the 14:38–14:47 review, never revised): B-1 refresh ordering/restatement decision; B-2 rejection counter + `sso_scope_registry_enabled` gauge decision and the observability.md:59–60 "no new metric" contract amendment (grep confirms no metric exists); B-3 migration sequencing pins (code-before-flip, canary-config-final, no amend-while-enabled); B-4 the 6 named test pins + harness. Only the AC-2 deviation (D-1) is explicitly rejected with evidence, which is sound.

Report written to `docs/architect-analysis/auto/runs/add-a-global-scope-matrix-v2-registry-and-reject-a084fac6/artifacts/design_gate-6a76b0dd/task-1-design-gate.md`.

VERDICT: FAIL - the design was never revised to resolve or reject the blocking review findings: refresh Consume-before-check burns the leaf and a retry kills the family (falsifying the drain/rollback survivability claims, with no ordering/restatement decision), the rejection counter/gauge and observability.md "no new metric" contract amendment are undecided, and the migration sequencing and test pins are not adopted; only the AC-2 deviation is explicitly rejected with evidence.
