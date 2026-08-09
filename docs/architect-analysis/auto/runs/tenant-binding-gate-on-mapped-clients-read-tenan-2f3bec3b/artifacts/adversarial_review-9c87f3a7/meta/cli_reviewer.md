All verification complete. Here is the final report.

# Verification: legacy-sync CLI surface vs sibling sso-ctl conventions

## 1. Exit-code semantics — precedent for "exit 1 on pre-write validation in dry-run" EXISTS

**Strongest precedent is legacy-sync itself.** The pre-existing existence gate (`mapped target client %q does not exist or is inactive`, `target.go` `buildReport`) already exits 1 in dry-run today: `buildReport` is called unconditionally at `legacysync/main.go:52` — before the `if cfg.Apply` write branch (56-60) — and mode only feeds `report.Mode` (48-50). Dry-run already performs full plan/target validation and exits 1 on any fatal plan defect. The new unbound gate adds one defect class to the *same* gate; dry-run semantics are not altered.

Sibling precedents for "validation failure in a non-writing mode → exit 1, stderr-only":

| Command | Behavior | Verdict |
|---|---|---|
| `importcmd --dry-run` | `parseInput` runs **before** the dry-run branch (`main.go:110`); parse failure → `fatalf` → exit 1, no stdout | ✅ Pre-write input validation in dry-run exits 1 |
| `auditverify` / `snapshot verify` / `audit-export --verify` | Read-only state validation; failure → stderr + exit 1, no stdout success line | ✅ Same shape |
| `configcmd validate` | Invalid config → `sso-ctl config: invalid config: ...` + exit 1 | ✅ Same shape |

Counter-example noted: `importcmd --dry-run` never opens the DB, so it exits 0 on a broken target — but that's a *shallow* dry-run by design; legacy-sync's dry-run inspects the target by design (the report contains target counts). Within its own established semantics, "dry-run detects fatal precondition ⇒ exit 1, no report" is the correct and consistent behavior.

## 2. `sso-ctl legacy-sync: %v` format — uniform with siblings; one phrasing drift in the prompt

- `reportError` lives in **`cmd/sso-ctl/legacysync/main.go:65-67`**, not top-level `cmd/sso-ctl/main.go` (which has no `reportError`; it only dispatches). The design doc cites the correct location (`main.go:65-67`).
- The prefix matches every sibling byte-for-byte: `importcmd` → `sso-ctl import: ...` (`progName+": "`), `configcmd` → `sso-ctl config: ...`, `migratecmd` → `sso-ctl migrate: ...`, `snapshotcmd` → `sso-ctl snapshot: ...`. All runtime failures use `sso-ctl <name>: ` + message + exit 1.
- **`errors.Join` rendering verified live** (Go 1.26): multiple unbound clients produce exactly one line each, `sso-ctl legacy-sync: ` prefix on the first line only — matching the design's M-table claim (`mapped target client "web" has no tenant binding (tenant_id empty)`, `%q` quotes verified).
- Cosmetic nit (pre-existing, not part of this change): siblings derive the prefix from a `progName` const; legacy-sync hardcodes the literal at `main.go:21, 26, 66`. Bytes are identical; AGENTS.md's consts preference would favor a const, but the design correctly leaves `main.go` untouched.

## 3. Help text / user-facing docs — NO updates required; new surface is documented where it exists

Exhaustive grep of the repo (outside `docs/architect-analysis/`): legacy-sync appears in exactly **three** user-visible places:

1. `cmd/sso-ctl/main.go:98` usage one-liner ("Reconcile sv_sso users and sv_auth roles into a SQLite deployment") — no sibling usage line enumerates runtime failure modes; the change adds no flag or subcommand. **No change.**
2. `legacysync/config.go` FlagSet name + flags — untouched by the design. **No change.**
3. `legacysync/main.go` package doc — describes function, not failure modes. **No change.**

`docs/` (config-reference.md, feature-matrix.md, error-codes.md, openapi.yaml, everything else): **zero** legacy-sync mentions — verified. AGENTS.md §5.6 imposes no contract edit (no new `Err*`, endpoint, or config knob); both the design (§4 "No doc-contract updates") and requirements (§7) state this correctly. The new failure is documented in the design's §5 failure-mode table and the requirements doc — the only documents that describe legacy-sync behavior at all. The pre-existing existence-gate failure is equally undocumented elsewhere, so the new gate creates no documentation asymmetry.

## 4. "Both modes exit 1, no stdout report" — verified consistent

- **Code-verified**: `buildReport` error → `reportError` → stderr + return 1 (main.go:52-54), before `printReport` (61) and the `return 0` (62). Dry-run opens the target `mode=ro` (`readOnlyDSN`, `target.go:32-45`); the gate is SELECT-only. No mode branch exists in the gate.
- **Sibling-consistent**: the uniform split is "success → stdout report + exit 0; failure → stderr + exit 1, no stdout" — same as `importcmd` (no sample on failure), `auditverify` (no "chain verified" line on broken chain), `configcmd` (no "config OK" on invalid).

## Drifts found (all cosmetic, none substance)

| Claim | Actual |
|---|---|
| Prompt: "reportError pattern in `cmd/sso-ctl/main.go`" | `reportError` is in `cmd/sso-ctl/legacysync/main.go:65-67` |
| Design: write branch at 56-59 | 56-60 (already noted by security reviewer) |
| Design: "`return 0` at 67" | 62 — the design's own line refs drift by a few lines, behavior claim unaffected |

**Verdict**: The design's CLI-surface claims hold. The new gate reuses the existing, sibling-conformant `reportError` path (uniform prefix, exit 1, stderr-only), its dry-run semantics match legacy-sync's own pre-existing existence gate and the `importcmd` dry-run parse-failure precedent, and no help text or contract docs need updating — the new failure mode is documented in the only user-visible documents that describe legacy-sync failure behavior. No `.go` files touched; no gates run (documentation-only verification).
