Design doc written to `docs/auto/domains-tokenexchange-design.md`. Summary of the decisions:

## Decisions

**## Decision 1 — `MutablePolicy` seam** — `Replace([]Rule) error` + `Rules()` + `DefaultAllow()`, defined beside `Policy` in `domains/tokenexchange/tokenexchange.go`. `Replace` gains an error return (free: zero production callers today, verified). `default_allow` stays config-owned/immutable — PUT moves only rules, avoiding a second mutation path. Unwired or non-mutable policies mount nothing (byte-identical).

**## Decision 2 — Admin API** — `GET`/`PUT /api/v1/admin/tokenexchange/policies` (admin:read/write), `{default_allow, rules, total}` envelope with rules in evaluation order; PUT is full-replace with validation (Name non-empty, 1000-rule cap, wildcard shape) failing `400` before any store call. Handlers in a new `interfaces/admin/tokenexchange_policies.go` (no ceiling there; owns `ActorFromContext`), thin wrappers + mount in `accessors_threat.go` (427→~465, ≤500) — **zero new `interfaces/sso` files**. New audit event `token_exchange_policy_updated` with actor + before/after counts.

**## Decision 3 — Matching dimensions** — `Scopes` ALL-of + trailing-`"*"` prefix wildcard (tokenpolicy precedent), `Resources` ANY-of (deliberate defensive divergence — exact equality would let a hop evade a deny by adding an unrelated audience), `RequestedTokenType` exact; empty = wildcard. Extracted `scopeMatches`/`resourceMatches` helpers keep `ruleMatches` ~25 lines; `Evaluate` stays pure; empty new fields = byte-compatible.

**## Decision 4 — sqlite store** — `tokenexchange_policy_rules` table (position PK preserves order, scalar columns + JSON for the two lists), full in-memory snapshot with copy-on-write (read path zero I/O), `Replace` = single tx delete+reinsert with rollback keeping disk+snapshot on the old set, loud boot load, `PolicyStoreMaxVersion` + `CheckSQLiteSchema` drift gate. `default_allow` deliberately not persisted (config-owned). Multi-replica staleness documented as a known limitation.

**## Decision 5 — Config/wiring** — `backend`/`default_allow`/`policies`/`policies_file` on `OAuthTokenExchangeConfig`, DSN reused from `oauth.sqlite`; strict-YAML bundle parser (deliberate deviation from lenient `tokenpolicy.ParseYAML`); `BuildTokenExchangePolicyStore` beside `BuildTokenPolicyStore`.

**## Decision 6 — Failure modes** — table covering boot, Replace, eval, audit, config, schema drift, torn reads.

**## Decision 7 — What could break it** — the biggest finding:

- **`build_app_oauth.go` has only 13 lines of headroom** (487/500, zero exemptions enforced repo-wide) — the requirement's literal "新增 `wireTokenExchangePolicy` in build_app_oauth.go" is inconsistent with the gate. Resolution: relocate `wireTokenExchangeChainLifetime` into a new `cmd/sso-server/build_app_tokenexchange.go` with the new wire function; fallback (inline into `wireOAuthGrantStores`, 487+10=497) if the team rejects new cmd files.
- Audit event must land in `KnownEventTypes` + `drift_test.go` + CEF/OCSF maps in the same change or `make ci` fails.
- `accessors_threat.go` (73 headroom) must keep only thin wrappers; `build_governance.go` (70) needs the builder lean with parsing in the domain package.
- E2E restart test needs two boots against one temp DSN (close server 1 first to avoid WAL locking).
- The analysis doc's false "tokenpolicy has sqlite backend" claim must not leak into `docs/config-reference.md`.
