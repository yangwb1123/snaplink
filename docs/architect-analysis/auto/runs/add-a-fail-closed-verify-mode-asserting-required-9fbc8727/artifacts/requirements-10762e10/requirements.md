Requirements spec written to `docs/architect-analysis/cmd-sso-ctl-migratecmd-verify-requirements.md` (9 sections, 171 lines).

## Verification summary

Every citation in the selected direction was re-verified against HEAD:

| Citation | Result |
|---|---|
| `migratecmd/main.go:25-40` status-only dispatch | **Confirmed** — `Run` at 41, switch at 47–55 handles only `status`; unknown → exit 2 |
| `main.go:72-77` empty DB green | **Confirmed** — `renderStatus` at 109 prints `(no migrated namespaces — empty or non-SSO database)` and returns nil (lines 116–117) |
| `migrate.go:286-297` Status `nil,nil` non-SQLite | **Confirmed** — `return nil, nil` at line 296; the comment explicitly documents the Postgres-swap case |
| `audit/sqlite/sink.go:48-78` + ns `audit` | **Confirmed** — migrations v1–v3 at 49–51, `migrationNamespace = "audit"` at 78 |
| `auditgovernance` managed_relay.go/relay.go | **Confirmed** — files exist; `rg auditgovernance cmd/` → zero references (B4-5 unwired, [PROPOSED] in the proposal doc) |
| `sso-ctl/main.go:55` registration | **Confirmed** at line 53 (2-line drift); banner at 99 |
| `defaultimpl/sqlite` namespace inventory | **Confirmed** — 9 namespaces: auth_codes, rebac_tuples, providers, devices, ssf_streams, ciba_requests, clients, consent, audit |
| `migrate.CurrentVersion` (379–396) | **Confirmed** — exported, returns 0 for absent table, read-only, needs no migration definitions — the whole implementation rides on existing `platform/migrate` symbols |

## Spec decisions (scoped strictly to the direction)

- **CLI**: `verify` subcommand with repeatable `--expect ns=min-version` flags (exactly the T-2 invocation form); strict grammar mirroring `migrate.versionTable`'s charset; ≥1 flag required; duplicates → exit 2 (usage), mismatch → exit 1, pass → exit 0.
- **Distinct non-SQLite diagnosis** (R3): a `sqlite_master` probe executed by migratecmd — `Status` swallows that exact error into the silent green; `verify` turns it into `not a SQLite database: <driver error>`. A Postgres-shaped DSN fails at `Ping` with the existing generic error (still exit 1, and stated as such in A2 rather than overclaiming the distinct message).
- **Floor semantics**: `CurrentVersion >= min` passes — v4 with `--expect audit=3` is green, matching "at minimum versions"; absent/missing namespace = 0 → fail, which is exactly the pre-B4-5 predicate T-9 needs.
- **T-9 made testable today**: A1 case 3 (audit-only DB vs `--expect governance_outbox=1` → exit 1) ships the predicate the deploy-tree sweep will use when B4-5 lands; the bump rule is procedural (R6).
- **Rejected directions 2 and 3 excluded**: no read-only enforcement, no DB-ahead-of-binary detection, no embedded manifest (would break the package's "no migration definitions" design) — each explicitly listed as a non-goal.
- **Testability**: acceptance A1–A6 map to concrete tests in a new `verify_test.go`, seeded via `migrate.Run` mirroring `seedDB`; A5 pins `status` byte-compat by requiring zero edits to existing tests; no new package (cmd/sso-ctl is at its 16-subdir ceiling).
