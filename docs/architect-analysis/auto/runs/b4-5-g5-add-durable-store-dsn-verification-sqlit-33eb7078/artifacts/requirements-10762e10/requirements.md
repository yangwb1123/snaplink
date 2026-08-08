The requirements specification is complete. Summary of the work:

**Deliverable:** `docs/architect-analysis/auto/cmd-sso-ctl-audit-dsn-requirements.md` (doc-only artifact; no `.go` edits, so no gates triggered).

**Verification of every cited symbol** (all confirmed against the working tree, with exact line numbers):

| Claim | Verdict |
|---|---|
| `auditverify` verifyOptions has no dsn (fromFile/fromURL/bearer/limit/pageSize/timeout/checkpoint/notaryKey/anchorHash) | ✅ main.go:82-92; exclusivity at 204-208 |
| `auditexport` sqlite-only `--dsn` via `auditsqlite.OpenReadOnly` | ✅ main.go:68 (only store import), 145 (flag help), 182-186 (open); never-migrate contract at 16-17 |
| sqlite + postgres backends store `prev_hash`/`hash` | ✅ sqlite/sink.go:103-104; postgres/audit_sink.go:49-50, 162; audit_query.go:24, 213-214 |
| chainer anchoring primitives | ✅ VerifyChain:157, VerifyChainSegment:172, NewEd25519CheckpointSigner:255 (+ VerifyChainAgainstCheckpoint:469, GenesisHash:141) |
| RecordTokenIssued + L1 aggregation absent repo-wide | ✅ recorder_events.go:19-24, EventTokenIssued=`"token_issued"` (event_types.go:15); `auth.token.issue` exists only as `[PROPOSED]` in docs/proposals/audit-contract-batch-snaplink.md:16 |
| No postgres `--dsn` in either tool | ✅ importcmd's `--backend postgres` targets the user store only |
| URL API pages newest-first at 1000/page | ✅ readFromURL main.go:403-444, MaxQueryLimit=1000 |

**New findings folded into the spec** (beyond the analysis): `postgres.NewAuditSink` *migrates* the schema (audit_sink.go:107-128) — a read-only verify tool must not call it, so REQ-5 mandates a non-migrating constructor with a fail-closed `schema_migrations_audit` version check; `auditexport.QueryPager` (auditexport.go:68) means `BuildExportBundle` needs zero changes for postgres; **`auditverify/main.go` is at 499 lines** — the DSN source must live in a new file; postgres tests skip without `SSO_TEST_POSTGRES_DSN` (postgres_test.go:13-19).

**Spec structure:** §1 citation-verdict table; §2 core invariants (read-only/never-migrate, chain-order reversal, honest truncation, one verification core, L1-is-proposed); §3 REQ-1..REQ-6 preserving the supplied T-9/G5 acceptance verbatim with an acceptance-sentence→requirement mapping (A1–A5) and 20+ testable Given/When/Then criteria (clean exit 0, single-flipped-hash exit 1, byte-consistency vs `audit.VerifyChain`, postgres-shares-the-path, volume-match, determinism, PROPOSED-flag misuse); §4 budget constraints; §5 files (create/modify/do-not-modify); §6 verification plan (incl. `make ci`); §7 explicit non-goals.
