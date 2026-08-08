Review written to `docs/architect-analysis/auto/runs/enforce-form-urlencoded-credential-strict-mode-0a8df02f/artifacts/rollout-review-3e9d3e61/task-1-rollout-review.md`. Every claim re-verified against the tree. Verdict: **the gate/binder design is sound, but the rollout plan is not executable as written** — the audit step has no tooling, and one existing observability system (config drift) interacts with this rollout misleadingly unless sequenced.

## Verified ground truth (code, not design text)

- **SIGHUP**: `config/reload/reload.go` allowlist → new key lands in `ignored_requires_restart`, logged by `applyReload` (main_shutdown.go:60-75) at **Info** level. Never applied.
- **Config typo is NOT silent**: `config/source.go` `decodeStrictWithFallback` + `checkSchema` warn on unknown keys — but both fire *before* `newSlogLogger` (main.go:92 vs :100), so they go to the process-default text/stderr handler, invisible in the structured JSON log. The design's "silently permissive" failure-mode row is wrong.
- **No CT observability exists**: zero access-log middleware; audit events carry no request headers; `HTTPRequestsTotal{status_class,method}` has no endpoint label; tracing has zero call sites by default. The server emits no signal that a request was JSON/CT-less.
- **Drift detector** (`config_audit.enabled` + `drift.interval>0`, opt-in): digest = `yaml.Marshal(full Config)` → new binary serializes `strict_credential_content_type: false` (no `omitempty`), old binary lacks the key → **drift alarms during the pre-flip mixed-binary window** — the same signal that correctly fires during the flip.
- **Precedent**: `oauth.scope_registry` row already documents "boot-time only, rollback = drop block" — but it also has a config pre-flight (`sso-ctl config validate`); strict-CT has no analog.

## Key findings

**Missing rollback paths**
- **R-1 (HIGH)** — no observer mode / audit mechanism: step 2 ("find every caller POSTing JSON") has zero tooling; missed callers break only after the flip. Fix: per-endpoint counters at the already-designed single binder-selection site ("would-be-rejected" in permissive mode, "rejected" in strict mode) — server-side only, oracle-safe.
- **R-2 (MEDIUM)** — binary rollback undocumented: works (unknown-key → permissive, fail-open), but the config keeps `true` and the **next binary upgrade silently re-enables strict mode**.
- **R-3/R-4** — one bool = all-or-nothing across four endpoints; no emergency bypass for a binder regression (blast radius = all credential endpoints until full restart).
- **R-5 (MEDIUM)** — rollback has no convergence verification (drift clear signal + `GET /api/v1/admin/config/running` exist and are never mentioned).

**Operator detection gaps**
- **D-1 (HIGH)** — flip verification is a presence-only Info log line; suppressed at `logging.level: error`, and absence is ambiguous across five failure modes. Fix: log effective state unconditionally (`"enabled", bool`).
- **D-2 (HIGH)** — post-flip stragglers invisible: byte-identical 400s are oracle-safe but telemetry-blind; no counter sizes the breakage.
- **D-3/D-4** — typo warning lands in the wrong sink; staging flip tests the server, not the converted callers.

**Sequencing hazards**
- **S-1 (HIGH)** — drift alarms fire spuriously during binary rollout (schema skew), habituating operators to the exact signal that means "mixed window" during the flip.
- **S-2 (MEDIUM)** — SIGHUP is a one-way trap, and the **rollback** direction is the dangerous one: drop key + SIGHUP → "config reload applied" logged, server **stays strict**, operator can declare rollback complete on opposite evidence.
- **S-3/S-4** — flip window blast radius unmeasured (incl. token→revoke cross-replica flows silently not revoked); audit step is unenforced manual work with no completion gate.

Seven concrete amendments are consolidated in §4 of the artifact; none touch response bytes, config schema, or the gate design.
