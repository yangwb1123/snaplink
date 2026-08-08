Design complete. Summary of what I did:

## Verification of the evidence (all claims TRUE)

Re-checked every citation against the tree — all 14 claims confirmed, including the exact line numbers (C1: `verifyOptions` at auditverify/main.go:82-92; C2: sqlite-only `--dsn` at auditexport/main.go:145/182-186; C3: `prev_hash`/`hash` in both sinks; C4: chainer primitives at 141/157/172/255/469; C5: `RecordTokenIssued` emits `token_issued`, `auth.token.issue` only `[PROPOSED]` in the proposal doc, zero `.go` hits; C6-C14 all confirmed). Two claims needed nuance, both folded into the design:

- **C8 hazard confirmed precisely**: `postgres.NewAuditSink` migrates (audit_sink.go:107-128); `postgres.Open` alone doesn't; postgres-local `CheckSchema` only rejects schema-*too-new* — so the new constructor needs an equality check, not `CheckSchema`.
- **C10 confirmed**: `auditverify/main.go` is exactly 499 lines.

## Two gate-breaking flaws found in the requirements doc's file plan (fixed in design)

1. **Subdir fan-out**: `directory_fanout_test.go` caps at `maxSubdirsPerDir = 16`; `cmd/sso-ctl` already has **16** subdirectories with no exemption. The spec's `auditstore/` + `auditagg/` (18) fails `TestArchitecture_DirectorySubdirFanout`. → Folded both into existing packages: shared reader/classifier into `cmd/sso-ctl/auditexport/store.go`, `audit-agg` as `auditexport.RunAgg`.
2. **500-line budget**: `--dsn` wiring (~20 lines) on a 499-line file exceeds it. → Move `readFromURL`/`fetchEventPage`/`reverseEvents` verbatim to `auditverify/url_source.go` first (T-9-provable pure move).

## Deliverable

`docs/architect-analysis/auto/cmd-sso-ctl-audit-dsn-design.md` with:
- **§1** evidence verification table (claim → verdict → this-tree evidence)
- **§2** the two gate-backed corrections
- **§3 API changes**: `--dsn` third source on audit-verify (exclusivity/bearer misuse → exit 2); postgres case on audit-export `--dsn`; new `audit-agg` subcommand (TSV, deterministic, PROPOSED-flagged); new `postgres.OpenAuditReadOnly(cfg)` (non-migrating, fail-closed `schema_migrations_audit` equality check); exported `ClassifyDSN`/`OpenStoreReadOnly`/`ReadAll`/`ReadChain` — `ReadChain` mirrors `readFromURL`'s newest-N-slice-before-reverse + probe-page truncation semantics exactly
- **§4 compatibility**: T-9 byte-identical surfaces, never-migrate contract, no new layers/imports upward, frozen files, budget table (16/16 subdirs, ≤3 files/dir, main.go ≤500)
- **§5 failure modes**: 11 rows with exit codes (incl. scheme-less postgres conn-string misclassification → guided exit 1; schema mismatch → exit 1 zero DDL; truncation honesty; empty-store contracts)
- **§6 migration**: zero DB migrations (mismatch = run stock server or pin binary); 5-step code order each leaving the tree green; rollback = previous binary
- **§7 acceptance mapping**: A1–A5 + T-9 → REQ criteria → named tests → gate commands
- **§8 non-goals**

No `.go` edits were made, so no build gates are triggered by this artifact; the §7 gate sequence is the implementation handoff contract.
