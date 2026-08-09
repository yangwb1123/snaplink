All claims verified against HEAD. Here is the review.

---

# Review: operator-facing contract for the scope-registry pre-flight

**Baseline**: `go build ./cmd/sso-ctl/...` green; legacysync has 6 non-test files (D1 confirmed: 6 → 7, ≤ 10); no `parseFlags` test exists today (`TestParseFlags*` in the design's targeted gate command must be created, not matched).

## 1. Exit-2 fail-closed convention — CONSISTENT, one spec nit

Verified against code:
- `run()` (main.go:30-34) returns 2 for every `parseFlags` error; 2 for missing env (main.go:36-40); 1 via `reportError` (main.go:65-68) for every operational failure; 0 only after `printReport`. The existing `--role-map %q references an unmapped app` (config.go:68-73) is already an exit-2 path, so the new `parseScopeRegistryFlags` errors flow through an established channel.
- The 2/1 split is toolbelt-wide: `configcmd` and `snapshotcmd` use 2 for usage/parse and 1 for validation failures; the audit-provisioner README documents the same automation convention ("0 success, 1 control/OAuth failure, 2 invalid configuration"). The design preserves the operator-meaningful split: **2 = fix the command line, 1 = fix the data** — scripts can distinguish a typo from a dirty deployment.
- Fail-fast ordering is correct: grammar errors fire in `parseFlags`, before the password check, MySQL connection, and target open — an operator with a typo never touches a DB.
- Gate violations correctly stay exit 1 (they are data/pre-flight failures, not invocation errors), identical in dry-run and `--apply`, and `buildReport` precedes the `cfg.Apply` write branch (main.go:52-60), so a failing plan never writes. Consistent with the tenant gate's discharge.

**R1 (minor, spec inconsistency)**: F3 lists "empty" as a grammar-violation → exit 2, but §3.1 step 2 drops empty segments *before* construction, so `ValidatePattern` never sees an empty string and `--scope-registry-extra ","` is a no-op (when wired). Either drop "empty" from F3 or state the drop-first semantics explicitly. Not a code defect; the failure table must not promise an unreachable error.

**R2 (contract tension — must be resolved before implementation)**: Rule 1 ("`--scope-registry-extra` present (non-empty after trim) without `--scope-registry` → error") makes `--scope-registry-extra ""` (or whitespace-only) without `--scope-registry` a **silent no-op** — which contradicts the design's own doctrine ("a per-invocation flag must never silently no-op") that justifies F2. Two defensible resolutions, pick one and pin it with a test:
- **A (strict doctrine)**: detect explicit presence via `fs.Visit`; any explicitly-set extra flag (even empty) without `--scope-registry` → exit 2.
- **B (script-friendly)**: empty/whitespace values are inert (the shell idiom `--scope-registry-extra "${EXTRAS}"` with an empty computed list), documented in the flag help text.

## 2. `--scope-registry-extra` parsing edge cases — SOUND CORE, three gaps

Verified grammar facts: `ValidatePattern` (registry.go:136-145) rejects `""`, bare `"*"`, and any non-`:*` star placement (internal whitespace like `legacy : *` also fails — fail-closed, correct); `NewMemory` uses set semantics — **duplicates are an idempotent no-op, never an error**, consistent with config `extra_scopes` (config_oauth2.go validates extras for grammar only; only *matrix* duplicates are boot errors); `Registered` (registry.go:115-131) is exact-or-`domain:*` and **case-sensitive** — correct, since RFC 6749 §3.3 scopes are case-sensitive, and preserving case is fail-closed (a `Legacy:*` extra registers nothing the plan contains).

| Input | Per design | Verdict |
|---|---|---|
| `" legacy:* , content:read "` | per-segment trim | OK |
| `"a,,b"`, `"legacy:*,"` | empty segments dropped | OK, but **untested** (§7.2 silent) |
| `""` / `" "` + `--scope-registry` | no extras (narrower, safe) | OK |
| `""` / `" "` alone | no error per rule 1 | **R2** |
| `"*"`, `"admin*"`, `"legacy : *"` | exit 2 via `ValidatePattern` | OK; err text is operator-readable |
| `"legacy:*,legacy:*"` | silent dedup | Consistent with `extra_scopes`; **must be pinned by a test** (absent) |
| `"LEGACY:*"` | registers only uppercase | Correct fail-closed; **needs help-text note + one fail-closed test** so a future "fix" never lowercases |
| Repeated flag `-extra A -extra B` | Go `flag` silently keeps **last** | **GAP — the first value is silently dropped**, exactly the silent-no-op the design condemns; the tool's own list flags (`--app-map` etc.) accumulate via `stringMapFlag` |

**G1 (real)**: repeated flag occurrences. Recommend an accumulating `fs.Var` (append segments, mirroring the tool's own `stringMapFlag` precedent and YAML-list semantics) or an explicit last-wins/error decision — plus a test.
**G2 (real)**: the R2 resolution.
**G3 (minor)**: extend §7.2's flag-validation tests to cover whitespace trim, `"a,,b"` drop, duplicates-no-op, `","` alone (no-op wired / exit 2 unwired — surprising, worth pinning), and case preservation. Also pin the F3 error text: wrap with flag + value (e.g. `--scope-registry-extra "admin*": scoperegistry: wildcard must be a "domain:*" suffix…`) — `errBadWildcard`'s text is good but names neither the flag nor the value, while the existing parse-error precedent names the flag (`--role-map %q references an unmapped app`).

## 3. Error-message clarity — GOOD SHAPE, two precision items

Verified: `reportError` prefixes `sso-ctl legacy-sync: `; the proposed line keeps the config-side parenthetical verbatim (`config_oauth2.go:60`'s `(matrix + protocol scopes + extra_scopes)`), so operators who ran `sso-ctl config validate` recognize the doctrine; client id + scope both named (T-8d); dedup + sorted one-line-per-violation mirrors the tenant gate (U3).

**C1 (recommend)**: the F6 malformed-JSON message must carry the underlying parse error, not just the client name — the operator's fix is a DB row edit, and "client X" alone doesn't say why the row is broken. E.g. `mapped target client "web" allowed_scopes is not valid JSON: <err>`.
**C2 (decision)**: S1/S2/S3 share one shape; the *source* (client `allowed_scopes` entry vs role permission vs role code) is indistinguishable, and the fixes differ (fix the client row / fix the source role / add an extra). Keeping one shape is defensible (config precedent, recognition) — the parenthetical already points at the fix direction, and Phase-1 dry-run enumerates everything. Decide explicitly rather than by accident; a two-shape variant (e.g. distinguishing "role code") buys precision at the cost of doctrine recognition.
**C3 (optional)**: with case-sensitive matching, a `Legacy:*` typo is discoverable only by comparing the printed scope against the registry contents. The help text should state "patterns are case-sensitive" (cheap, high value); no per-line change needed.

## 4. Docs updates per AGENTS.md §5.6 — DESIGN'S "NO CONTRACT-DOC CHANGE" IS VERIFIED; one implementation duty

Verified absence (grep, HEAD): `legacy-sync` appears in **no** row of `docs/config-reference.md` (only unrelated "legacy" substrings: trusted-proxies "first-hop trust", OAuth "legacy plaintext", etc.), `docs/feature-matrix.md`, `docs/error-codes.md`, or `docs/openapi.yaml`; `docs/deployment.md:50` enumerates the toolbelt but no flags. AGENTS.md §5.6 triggers therefore do not fire:
- **No new `Err*`** — `docs/error-codes.md` is the HTTP REST catalog; the gate reuses the tool's existing exit codes 1/2 (no new exit code either — 2 is already the toolbelt parse-error convention, verified in configcmd/snapshotcmd).
- **No endpoint** — no openapi.yaml change (T-2 holds; no file under `interfaces/`, `protocols/`, `infrastructure/`, `config/`, `cmd/sso-server` is modified).
- **No config.yaml knob** — the flags are per-invocation CLI flags, not `oauth.scope_registry.*`; the existing row at config-reference.md:20 documents the YAML side and needs no edit.

This matches the accepted tenant-binding-gate precedent, which made and verified the same claim.

**Duty instead of doc edits**: the design makes the **flag help text the operator contract** (`sso-ctl legacy-sync -h` is the only discoverable surface — the tool has no README). §3.1 currently describes meaning but pins no literal help strings; the design must specify exact help text carrying: the grammar (exact or `domain:*` only), case-sensitivity (C3), dedup/empty-token semantics (per R2/G3), the extra-without-`--scope-registry` exit-2 error, and the reconciliation doctrine (one `--scope-registry-extra legacy:*` entry covers the fabricated family; verbatim source permissions like `content:read` need their own extras). If the campaign wants the contract beyond `-h`, the natural home is a README in `cmd/sso-ctl/legacysync/` (none exists) — but repo discipline ("no Markdown unless requested") and precedent argue for help-text-only; that is a campaign decision, not a §5.6 obligation.

## Priority change list for the design

1. **R2**: resolve the empty-value-without-`--scope-registry` tension (fs.Visit strictness vs script-friendly inertness) and pin.
2. **G1**: decide repeated-flag semantics (recommend accumulate) and pin.
3. **C1**: F6 message includes the JSON parse error.
4. **G3/C3**: extend §7.2 test matrix (whitespace, `"a,,b"`, duplicates-no-op, `","`, case fail-closed) and add the case-sensitivity note to help text.
5. **R1**: fix F3's unreachable "empty" row.
6. **Duty**: pin literal help strings in §3.1; name the new `TestParseFlags*` tests so the §7.4 targeted command is real (no such test exists today).
7. **C2**: state the one-shape decision explicitly.

No blocking defects: the exit-code architecture, fail-closed grammar reuse, byte-compat story (T-9), and the no-contract-doc-change conclusion all check out against the code.
