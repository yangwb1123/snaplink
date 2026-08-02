Written to `docs/auto/domains-threataction-requirements.md`. I verified every claim against the code first:

**Evidence verification performed**
- `grep -rln "threataction/sqlite"` repo-wide: zero importers (only a doc-comment mention in `domains/tokenexchange/sqlite/chain_store.go`) — the SQLite store is confirmed dead code despite 6 passing tests.
- `BuildThreatAction` (`cmd/sso-server/serverbuildplatform/build_governance.go:310`) hardcodes `threatactionmemory.NewThreatPolicyStore()`; `ThreatActionConfig` (`config/config_snapshot.go:472`) has no `backend`/DSN knob.
- `registry.go`: `rateLimit map[string]*rateLimitEntry` + `allow()`/`rateLimitSweepThreshold` are strictly in-process; the sqlite schema has only the `threat_policies` table.
- Sibling patterns confirmed for reuse: `BuildConfigAuditStore` backend switch, `buildTenantStoreBackend` logging, `anomalyRuntime.close` lifecycle, `ThreatPolicyStore.Ping` ready-check.

**The 3 improvements** (## headings, each with name / problem / evidence / proposed behavior / acceptance check):

1. **Backend selection** — wire the dormant SQLite store into `BuildThreatAction` behind `threat_action.backend: memory|sqlite` + `threat_action.sqlite.dsn`, fail loud on missing DSN, with lifecycle (close + ready-check) mirroring `anomalyRuntime`; default stays byte-identical.
2. **Seed-once boot semantics** — the current unconditional `store.Put` seed loop would silently roll back admin-authored policies on every restart once the store is durable; seeds must apply only to an empty store, with a logged seed/keep decision.
3. **Cross-replica rate limiting** — per-process limiter gives an attacker N× budget across N replicas; add a `threat_rate_limits` SQLite table with atomic upsert keyed by `(subject, type, action, window_start)` behind the same backend switch, fail-open on store error, memory path unchanged.

Each acceptance check names concrete tests (restart-survival, two-replica shared-window, boot-error cases) plus the mandatory gates (`go build ./... && go vet ./...`, architecture/maintainability tests, `make ci`) and the `docs/config-reference.md` contract updates required by AGENTS.md §5.
