Done. The task is complete and committed as `53b851f3`.

## Summary

**Design first** — `docs/design/config-apply-mode.md` (bounded, all references verified against code) decides the seven required questions:

1. **Authority**: single `POST /api/v1/admin/config/apply` with `admin:write` (default POST scope — no override, the opposite of cluster-diff's read downgrade) + mandatory `?approve=true` flag (rejects two-stage dry-run→commit since cluster-diff already *is* the dry run); approval/audit evidence recorded per write.
2. **Target semantics**: input = full peer snapshot + canonical sha256 digest + mandatory reason; write path = new `Store.Apply/Applied/Rollback` (not Record/List — the baseline+history update must be atomic); after success `applied` serves the peer baseline, `history` gains a `config` entry, `running` never mutates (live runtime mutation is out of scope).
3. **Rollback**: transactional (sqlite one transaction, memory one lock — no half-state), append-only version chain retaining every predecessor, explicit `POST .../config/rollback` (409 `config_apply_no_previous` when nothing to restore), full failure-mode table.
4. **Split-brain**: server recomputes `configaudit.Digest` over the raw snapshot and compares to the supplied fingerprint → 409 `config_apply_conflict` (reuses the drift loop's existing digest mechanism).
5. **Secrets**: `Redact`/`RedactOps` reused verbatim; only redacted snapshots stored; audit carries metadata only; a plaintext-secret scan test proves nothing leaks.
6. **Hard boundaries**: diff-only endpoints byte-identical until the first apply, unmounted unless both snapshot source + store wired, zero exemptions, no upward imports (platform layer, actor resolved via injected `HandlerDeps` accessor).
7. **Acceptance assertions**: 10 testable items, all covered by memory + sqlite store suites, handler tests, secret scan, and a full-server lifecycle e2e test.

**Implementation** — `Store.Apply/Applied/Rollback` (memory + sqlite with migration v2), handlers + route mounting, `admin_config_applied`/`admin_config_rolled_back` audit events registered in `auditspi`/`KnownEventTypes`/`auditreport` CC6.3, three new wire codes, openapi.yaml + error-codes.md + config-reference.md + deferred-backlog.md + CHANGELOG.md synced, no new config keys.

**Verification (all run, all green)**: build+vet, `go test ./platform/configaudit/... -count=1` (incl. sqlite suite), `go test ./interfaces/sso/... -run Config`, `cli.py check-routes` (243 runtime routes, 350 documented ops), `cli.py sdk-surface check`, maintainability/architecture/directory gates, plus `-race` on configaudit, full interfaces/sso, platform/audit, cmd/sso-server, and `test/` e2e. Pre-existing worktree changes (state.jsonl, campaign yaml, batch files) were preserved and excluded from the commit.
