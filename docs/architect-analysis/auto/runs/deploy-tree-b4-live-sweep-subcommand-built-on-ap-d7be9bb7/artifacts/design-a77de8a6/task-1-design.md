Design complete. Here's the summary:

## Evidence verification — all claims checked against the tree

All 8 citations verify **true**, with two line-drift corrections and one path pin (no semantic claim failed):

| Citation | Verdict |
|---|---|
| `apiclient.go` (188 lines, DefaultAddr:24, New:47, Do:81, ReadBody:134, env fallback:58-61; zero tests) | ✅ exact |
| `main.go` 16-entry subcommands map (:46-63) | ✅ exact |
| `auditverify/main.go` `--from-url`/`--bearer` (:102-104), `readFromURL` :403, `fetchEventPage` :450 with hand-rolled bearer client | ✅ exact |
| `test/oidc_discovery_test.go` tests at :61/:80/:88, 13 total, zero `404`/`NotFound` references | ✅ exact; gap confirmed |
| `buildBaseMetadata` at server_discovery_config.go:142, endpoints :145-149, userinfo/end_session gated :158-163 | ✅ (function spans 142-163, not 139-152) |
| `PathToken="/token"` at consts.go:21 | ✅ exact |
| `rejectUnregisteredScopes` at :203; plain `{"error":"invalid_scope"}` at scoperegistry/reject.go:37; allowlist fallback emits same bytes (token_client_credentials.go:40, doc said :36) | ✅ line drift only |
| implementation-gate.md T-2 definition | ✅ content verified |

All load-bearing findings confirmed independently, including the two the requirements doc itself flagged: `smoke.sh` **does** exist (55 lines; discovery grep + curl cc round trip, no sweep probes — gap stands) and `cmd/sso-ctl` is at the **16/16 subdir ceiling** (directory_fanout_test.go:35, no exemption) — the sweep must live in `apiclient`. One citation correction of my own: `StdRouter.ServeHTTP` is at router.go **276-320** (not 376-412, which holds `GateHTTPHandler` docs); the method-mismatch→`http.NotFound` mechanism (:280, :319) is exactly as claimed.

## Deliverable

**`docs/architect-analysis/auto/cmd-sso-ctl-apiclient-design.md`** (268 lines, matching the audit-dsn design doc convention), containing:

- **§1** — verification table (citations + load-bearing findings with exact line evidence)
- **§2** — three design decisions beyond the requirements: fail-fast `--addr` URL validation (exit 2, preventing 5 confusing per-row transport failures), `crypto/rand` probe-scope pin (never on stdout — determinism), bare T-9 client construction pin
- **§3 API changes** — `sso-ctl check` CLI surface (8 flags, 0/1/2 exit contract, byte-deterministic stdout), `CheckRun(args []string) int` + probe helpers in `apiclient/check.go`, one `main.go` map entry; explicitly unchanged: server, `apiclient.go`, docs, `ops/deploy/*`
- **§4 Compatibility constraints** — fan-out ceilings (16/16, ≤3 non-test files), function budgets (50 lines/15 complexity/3 nesting) via data-driven probe matrix, stdlib-only imports, advertised-only sweep, credential hygiene (T-9 structurally bearer-less)
- **§5 Failure modes** — 25-row table: detection → exit code → exact stderr diagnostic (404 rows, byte-mismatch, enforcement-absent 200, issuer drift, deterministic `--expect-roles` cc failure, env-token leak prevention)
- **§6 Migration steps** — no server/config/data migration; implement → gate → ship additive binary → operate → optional smoke.sh wiring → stateless rollback
- **§7 Acceptance mapping** — A1–A8 → REQ → concrete test names with criteria, grounded in the proven `oidc_discovery_test.go` testkit (real `sso.NewServer` + seeded restricted client that doubles as T-8d's precondition) and the existing `dispatch_test.go` registration-test precedent
- **§8 Verification plan** — the AGENTS.md gate sequence

Doc-only change: no `.go` edits, so no build gates triggered.
