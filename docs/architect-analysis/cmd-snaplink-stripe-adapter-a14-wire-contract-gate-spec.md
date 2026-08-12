# Spec: A14 wire-contract gate — nested OpenAPI validation + exported-code/docs-row pairing in `checks/adapters_check.py`

- Parent: wire_compat review of `docs/architect-analysis/cmd-snaplink-stripe-adapter-tenant-claim-design.md` (finding "A14 pairing is not enforced")
- Requirements anchor: `cmd-snaplink-stripe-adapter-tenant-claim-requirements.md` R6.2 / A14 — "the contract gate (`make ci`, OpenAPI validation) passes with the updated yaml; `docs/error-codes.md` documents every wire code the adapter emits, including `tenant_mismatch`"
- Supersedes: the second sentence of the parent design's §8 "Contract note" ("No new gate is introduced by this direction"). With this spec built, A14's pairing claim ("the adapter's exported `ErrTenantMismatch` constant backs the new docs row") is machine-enforced, not review-only. The parent design's `model.go` comment ("exported so the repository contract gate can prove every documented adapter response remains backed by executable code") likewise becomes true; no comment change is needed.
- Status: spec (every claim re-verified against HEAD on 2026-08-08; verification commands in §8)

## 1. Goal and user outcome

`make ci` must fail when the stripe adapter's wire contract loses executable
evidence, exactly as A14 promises:

1. **Nested OpenAPI validity**: every `cmd/*/openapi.yaml` (today: exactly one,
   `cmd/snaplink-stripe-adapter/openapi.yaml`) is validated by kin-openapi —
   the same validator `make docs-validate` applies to `docs/openapi.yaml` —
   so the adapter's separate contract can no longer rot unnoticed.
2. **Exported wire-code ↔ docs-row pairing**: every exported wire-code const
   in `cmd/snaplink-stripe-adapter/model.go`'s anchored const block appears as
   a `| code |` table row in the `## Stripe payment adapter` section of
   `docs/error-codes.md`. Adding a wire code to `model.go` without its docs
   row (or deleting the row while the const lives) fails `make ci`.

Outcome: a reviewer reading "the exported constant backs the new docs row"
(A14) is reading a gate, not an aspiration; the contract note in the parent
design's §8 stops being a known gap.

## 2. Product boundary and non-goals

- Surface: repository tooling only (`checks/adapters_check.py` + tests +
  registry docs). No Go code, no `.go` edits, no `go.mod`/`go.sum` change.
- Default: always-on — the scan lives in `adapters-check`, which is already a
  `make ci` prerequisite; no new Makefile target, no opt-in flag.
- Non-goals:
  - Validating `docs/openapi.yaml` (already covered by `make docs-validate`).
  - Enforcing the reverse direction (every docs row has a const):
    `invalid_request` is a shared-surface code emitted as a literal from
    `http.go:88/93/141` with no local const; a row↔const bijection would
    false-fail on pre-existing state.
  - Adding kin-openapi to `go.mod` (explicitly excluded; see §4.2).
  - Changing `run_behavioral()` — the Go conformance-suite/matrix invocation
    is untouched. `cmd_adapters` (cli.py:175-181) already runs `run()` then
    `run_behavioral()`; both new scans are static and belong in `run()`.
  - Adding `check-test` (pytest) to `make ci` — out of scope; the pytest
    suite stays supplementary, as today.

## 3. Current-state evidence (verified, all green today)

| Claim | Verified reality |
|---|---|
| Exactly one nested OpenAPI file | `ls cmd/*/openapi.yaml` → `cmd/snaplink-stripe-adapter/openapi.yaml` only (246 lines) |
| kin-openapi validates it today | `go run github.com/getkin/kin-openapi/cmd/validate@latest cmd/snaplink-stripe-adapter/openapi.yaml` → exit 0; pinned form `@v0.146.0` also exit 0 (v0.146.0 is what `@latest` resolves to in the module cache today) |
| kin-openapi is not a module dependency | `grep kin-openapi go.mod go.sum` → zero hits; invocation is `go run pkg@version`, which resolves in the module cache without touching the main module |
| Validator failure shape | Bad yaml → stderr `Validation error: <detail>`, exit 1 (go run wraps as `exit status 1`); subprocess must capture and echo stderr |
| Wire-code block is anchored and parseable | `model.go` has two `const (` blocks; the wire block follows the comment `// Wire error codes are exported so the repository contract gate can prove` and holds exactly 8 exported `Err* = "…"` consts (`billing_unavailable`, `provider_unavailable`, `order_not_pending`, `checkout_conflict`, `invalid_signature`, `invalid_event`, `event_conflict`, `unavailable`) |
| Every exported const has a Stripe-section row | `docs/error-codes.md:1034-1062` — the Stripe section table has **10 rows** today: the 8 consts + `invalid_request` + `tenant_mismatch` (:1051); `grep -cF '| `code` |'` = 1 file-wide for each of the 8; all rows sit inside the section bounded by `## Stripe payment adapter (` and `## Machine usage and entitlement SDK` |
| One-directional assertion is mandatory — **proven live** | The worktree is mid-implementation of the tenant-claim direction: R6.1/R6.2 (openapi `Forbidden` description, error-codes prose :1038-1046 + `tenant_mismatch` row :1051) have landed, while `ErrTenantMismatch` and the http.go gates have not. So the Stripe section currently holds two rows without a local const: `tenant_mismatch` (the direction adds it via R4.3) and `invalid_request` (a shared-surface literal, `http.go:88,93,141`). A row↔const bijection false-fails on the pre-existing worktree; the subset direction passes at both the interim state (8 consts ⊆ 10 rows) and the post-R4.3 state (9 consts ⊆ 10 rows) — verified by executing the spec's functions (§8) |
| `adapters-check` is wired into `make ci` | `Makefile:265` ci line ends with `… profiles-evidence adapters-check`; target at Makefile:194-195 runs `$(CLI) adapters`; `cmd_adapters` (cli.py:175-181) runs static `run()` then `run_behavioral()` — zero Makefile/cli.py changes needed |
| Check conventions | CHECKS_REGISTRY.md "Adding a check": Python module for orchestration + unit test + cli.py exposure + document blocking; `checks/test_adapters.py` is pytest-style with a live-source pin (`test_pinned_inventory_matches_the_live_suite`); `python cli.py check-test` runs pytest over `checks/`; baseline 14 tests green; `python cli.py adapters` green |
| Registry docs must be updated in the same change | CHECKS_REGISTRY.md adapters_check.py purpose row and the "Scope and limitations" bullet ("static scans are existence-level") both become stale; cli.py:25 `adapters` description also becomes stale |

## 4. Design

### 4.1 Constants (top of `checks/adapters_check.py`, beside the existing path constants)

```python
ERROR_CODES_DOC = ROOT / "docs/error-codes.md"
STRIPE_ERROR_SECTION_HEADING = "## Stripe payment adapter"
WIRE_CODE_ANCHOR = "// Wire error codes are exported"
WIRE_CODE_MODEL = ROOT / "cmd/snaplink-stripe-adapter/model.go"
WIRE_CODE_FLOOR = 8  # frozen floor: today's exported block size; shrink-only never
KIN_OPENAPI_VALIDATE = "github.com/getkin/kin-openapi/cmd/validate@v0.146.0"
```

- `WIRE_CODE_FLOOR = 8` is a derived floor, not a name pin: the gate must keep
  passing when the tenant-claim direction adds `ErrTenantMismatch`
  (model.go +1 const, error-codes.md +1 row — both sides grow together). It
  exists only so an extraction regression that empties the block fails loudly
  instead of passing a vacuous `⊆`.
- The validator is **pinned** (`@v0.146.0`, the exact version verified today),
  not `@latest`. `make docs-validate` (Makefile:189) may float `@latest`
  because it is not a `make ci` prerequisite; a ci-blocking gate must not
  silently change behavior when kin-openapi ships a stricter release. Bumping
  the pin is a deliberate, one-line, same-change edit (see §6 F7).

### 4.2 New pure functions (unit-testable, no subprocess)

```python
WIRE_CONST_RE = re.compile(r"\bErr([A-Za-z0-9_]+)\s*=\s*\"([^\"]+)\"")

def wire_code_consts(source: str) -> list[tuple[str, str]] | None:
    """Extract (constName, wireCode) from the anchored wire-code const block.

    Fail-closed: returns None when the anchor comment or its const block is
    missing, so a refactor that renames/removes the registry fails the gate
    instead of passing on an empty extraction.
    """
    anchor = source.find(WIRE_CODE_ANCHOR)
    if anchor < 0:
        return None
    block_start = source.find("const (", anchor)
    if block_start < 0:
        return None
    block_end = source.find(")", block_start)
    if block_end < 0:
        return None
    return WIRE_CONST_RE.findall(source[block_start:block_end])
```

```python
def stripe_error_rows(doc: str) -> set[str]:
    """Backticked codes from | code | rows inside the Stripe section only.

    Section = lines from the Stripe heading up to the next '## ' heading.
    A code mentioned in prose, or as a row in any other section, does not
    count — the row must live in the Stripe table.
    """
    lines = doc.splitlines()
    start = next(
        (i for i, line in enumerate(lines)
         if line.startswith(STRIPE_ERROR_SECTION_HEADING)),
        None,
    )
    if start is None:
        return set()
    rows: set[str] = set()
    for line in lines[start + 1:]:
        if line.startswith("## "):
            break
        match = re.match(r"\| `([^`]+)` \|", line)
        if match:
            rows.add(match.group(1))
    return rows
```

```python
def missing_code_rows(codes: list[tuple[str, str]], rows: set[str]) -> list[str]:
    """Exported wire codes without a Stripe-section row. One-directional."""
    return [f"{name} ({code})" for name, code in codes if code not in rows]
```

### 4.3 Extend `run()` — scans (g) and (h), appended to the existing failures list

```python
# (g) every cmd/*/openapi.yaml must pass the same kin-openapi validation
# that make docs-validate applies to docs/openapi.yaml.
nested_openapi = sorted(ROOT.glob("cmd/*/openapi.yaml"))
if not nested_openapi:
    failures.append("no cmd/*/openapi.yaml found (adapter OpenAPI contract missing)")
for path in nested_openapi:
    result = subprocess.run(
        ["go", "run", KIN_OPENAPI_VALIDATE, str(path)],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        failures.append(
            f"{path.relative_to(ROOT)} fails kin-openapi validation:\n"
            + result.stderr.strip()
        )

# (h) every exported wire-code const in the adapter's anchored block must
# appear as a | code | row in the error-codes.md Stripe section.
model = WIRE_CODE_MODEL.read_text() if WIRE_CODE_MODEL.is_file() else ""
codes = wire_code_consts(model) if model else None
if codes is None:
    failures.append("stripe adapter wire-code const block missing or unanchored")
else:
    if len(codes) < WIRE_CODE_FLOOR:
        failures.append(
            f"wire-code const block shrank below {WIRE_CODE_FLOOR} entries"
        )
    doc = ERROR_CODES_DOC.read_text() if ERROR_CODES_DOC.is_file() else ""
    missing = missing_code_rows(codes, stripe_error_rows(doc))
    for entry in missing:
        failures.append(
            f"exported wire code {entry} has no | code | row in the "
            f"error-codes.md Stripe section"
        )
```

Notes on placement and shape, matching `adapters_check.py` conventions:

- Both scans live in `run()` (static phase). `cmd_adapters` already sequences
  static → behavioral, so `make ci` picks them up with no plumbing change.
  Subprocess precedent inside a static run exists (`route_contract.py`
  compiles and runs a Go helper inside `run()`).
- Failure strings follow the existing `adapters-check: FAIL: <detail>`
  convention; `run()` keeps printing one line per failure and returns 1.
- `run_behavioral()` is untouched; CHECKS_REGISTRY's claim that behavior is
  covered by the Go tests it invokes stays true.
- No `go.mod` change: `go run pkg@version` resolves kin-openapi in the module
  cache outside the main module (verified — zero kin-openapi entries in
  `go.mod`/`go.sum` after repeated invocation). First run in a fresh checkout
  downloads the tool (~seconds, same cost `make docs-validate` already has);
  subsequent runs are cache hits. Hosted CI runners have network; a fully
  air-gapped environment would need vendoring, which is out of scope.

## 5. Wiring (already in place — verification only)

| Layer | Action |
|---|---|
| `Makefile` | **None.** `adapters-check` (194-195) and the `ci` prerequisite list (265) already include it |
| `cli.py` | **None.** `cmd_adapters` (175-181) already runs `run()` → `run_behavioral()`; both new scans are inside `run()` |
| `go.mod`/`go.sum` | **None** (kin-openapi fetched via `go run pkg@version`) |
| `checks/test_adapters.py` | **Add** the unit tests of §7 (required by CHECKS_REGISTRY "Adding a check") |
| `docs/agent-os/CHECKS_REGISTRY.md` | **Update in the same change** — adapters_check.py purpose row: append "and validates nested `cmd/*/openapi.yaml` via kin-openapi plus the exported wire-code ↔ error-codes.md Stripe-row pairing"; "Scope and limitations" bullet: replace "static scans are existence-level" with the two new static assertions |
| `cli.py:25` | **Update** the `adapters` command description: "Adapters delivery contract check (conformance + matrix + examples + nested OpenAPI + error-codes pairing)" |

## 6. Failure modes and false-fail analysis

### 6.1 Cannot false-fail on pre-existing state (verified today)

| Hazard | Mitigation | Today |
|---|---|---|
| Nested openapi invalid | — | Not a hazard: exit 0 verified (§3) |
| Exported const without row | — | Not a hazard: all 8 consts have Stripe rows, each exactly once file-wide |
| Docs row without const (`invalid_request`, and currently `tenant_mismatch` mid-implementation) | One-directional assertion (consts ⊆ rows) | Passes by construction — verified live at the interim state |
| Same code as a row in another section | `stripe_error_rows` is section-bounded (next `## ` heading) | Passes (all 8 rows are in the Stripe section; e.g. `unavailable` also exists as a platform concept but not as a competing row) |
| Code mentioned in prose but not as a row | Row regex requires the `| \`code\` |` table-cell shape | Passes (prose occurrences don't match) |
| Go formatting churn in the const block | `WIRE_CONST_RE` tolerates any whitespace around `=` (gofmt alignment) | Passes |
| A future stricter kin-openapi release | Pin `@v0.146.0` instead of `@latest` | Passes; bump is deliberate (F7) |
| Empty extraction vacuously passing | Anchor + `WIRE_CODE_FLOOR = 8` | Passes (block intact, 8 entries) |
| Two `const (` blocks confused | Extraction anchored on the `// Wire error codes are exported` comment | Passes (block located by comment, not by position) |
| First run offline / no module cache | Subprocess failure surfaces as gate failure with the go error text | Local cache verified; network documented in §4.3 |

### 6.2 Deliberate failures (the gate working as designed)

| # | Condition | Result |
|---|---|---|
| F1 | New wire code added to `model.go` block without an error-codes.md Stripe row | `make ci` fails with `exported wire code ErrX (code) has no | code | row …` |
| F2 | Stripe docs row deleted while the const lives | Same failure (F1 shape) |
| F3 | Nested openapi.yaml edited into invalidity | `make ci` fails, validator stderr echoed |
| F4 | Wire-code block renamed/removed (anchor lost) | `make ci` fails with `wire-code const block missing or unanchored` |
| F5 | Block collapses below 8 entries (extraction regression or mass deletion) | `make ci` fails with the floor message |
| F6 | New `cmd/*/openapi.yaml` added with an invalid spec | Fails by design — every adapter's contract is validated; the glob is intentionally forward-looking |
| F7 | kin-openapi ships a breaking release | No effect (pin); bumping `KIN_OPENAPI_VALIDATE` is a deliberate same-change edit |

### 6.3 Explicitly out of scope

- Row exists but const was removed from the block: **not** a failure
  (one-directional). The docs row for a code that stopped being emitted is a
  documentation cleanup, not a contract break — the same-change discipline
  (R4.3/R6) governs it.
- `invalid_request` (shared-surface literal): never required to have a const.
- Row without const in the interim state: `tenant_mismatch` (error-codes.md:1051) currently has no `ErrTenantMismatch` const in `model.go` — the tenant-claim direction adds it via R4.3 in its own change. The gate stays green in the interim by design (one-directional), so it cannot block mid-implementation worktrees; the same-change discipline (R4.3/R6) guarantees the pair completes before the direction's handoff.

## 7. Unit tests to add (`checks/test_adapters.py`)

| Test | Case |
|---|---|
| `test_wire_code_consts_extracts_only_the_anchored_block` | Synthetic source with the two-const-block shape (paths/scope block first, anchored wire block second); only the anchored block's 8 pairs are returned |
| `test_wire_code_consts_fail_closed_when_anchor_missing` | Source without the anchor comment → `None`; source with anchor but no following `const (` → `None` |
| `test_wire_code_consts_tolerates_gofmt_alignment` | `ErrA  = "a"` / `ErrB = "b"` spacing variants both parse |
| `test_stripe_error_rows_bounded_by_next_heading` | Synthetic doc: Stripe section rows captured; a row with the same code in a later section not captured; prose mention not captured |
| `test_stripe_error_rows_empty_without_heading` | Doc with no Stripe heading → empty set (gate then reports every const — fail-closed) |
| `test_missing_code_rows_reports_only_absent_codes` | `[("ErrA","a"),("ErrB","b")]` vs rows `{"a"}` → `["ErrB (b)"]` |
| `test_live_wire_codes_have_stripe_rows` | Live-source pin, mirroring `test_pinned_inventory_matches_the_live_suite`: `wire_code_consts(model.go)` is not None, `>= 8` entries, and `missing_code_rows(...) == []` against the live error-codes.md |
| `test_live_nested_openapi_glob_nonempty` | `sorted(ROOT.glob("cmd/*/openapi.yaml"))` is non-empty and includes the stripe adapter file (tolerant of a future second adapter) |

The live-source tests duplicate the gate's assertions in pytest and would
catch a pairing regression even when `adapters-check` isn't the invoked
target. The validator subprocess itself is **not** exercised by pytest
(no network in unit tests); it is covered by the §8 runbook.

## 8. Acceptance mapping and verification runbook

A14 ("contract gate passes; every wire code the adapter emits is documented")
now has a mechanical body:

| A14 clause | Enforcement |
|---|---|
| `make ci` passes with the updated nested yaml | scan (g) — kin-openapi over `cmd/*/openapi.yaml` |
| every wire code the adapter emits is documented | scan (h) — exported wire-code block ⊆ Stripe-section rows; R4.3's "put the `tenant_mismatch` string next to the other wire codes" makes the block the registry of emitted codes |
| "the exported `ErrTenantMismatch` constant backs the new docs row" | scan (h) once the tenant-claim direction lands R4.3: `ErrTenantMismatch = "tenant_mismatch"` joins the block ⇒ the already-present row (error-codes.md:1051, landed by R6.2) is what the const backs. Verified: the spec's functions return green for both the current interim state (8 consts, 10 rows) and the post-R4.3 state (9 consts, 10 rows) |

Runbook (in order; all green at HEAD today):

```bash
python -m pytest checks/test_adapters.py -v                 # new unit tests
python cli.py adapters                                      # static + behavioral, exit 0
make adapters-check                                         # same via Make target
python cli.py check-test                                    # full pytest suite over checks/
make ci                                                     # full handoff gate
```

Negative proof — **executed** against HEAD with the spec's exact functions (each failure surfaced, then reverted to green):

| Injection | Result |
|---|---|
| F1: `ErrProbe = "probe_code"` inserted inside the block, no docs row | `['Probe (probe_code)']` missing → gate FAILs; adding the row clears it |
| F2: delete the `unavailable` docs row while the const lives | `['Unavailable (unavailable)']` missing → gate FAILs |
| F3: `echo 'openapi: 3.1.0' > cmd/snaplink-stripe-adapter/openapi.yaml` | validator exits 1 with `Validation error: invalid info…` → gate FAILs (subprocess stderr echoed); restoring the file → green |
| F4: rename the anchor comment | `wire_code_consts` → `None` → gate FAILs with the unanchored message |
| F5: empty the anchored block | `[]` → floor check FAILs |
| Interim/final tenant-claim states | both green (8/10 and 9/10) — no false-fail mid-implementation |

```bash
# F3 shape, runnable verbatim:
echo 'openapi: 3.1.0' > cmd/snaplink-stripe-adapter/openapi.yaml && python cli.py adapters; git checkout -- cmd/snaplink-stripe-adapter/openapi.yaml
```

No `.go` edits are made by this change, so the AGENTS.md per-edit Go gates are
not re-triggered; the runbook above is the change's own gate. The parent
design's §8 contract note is superseded per the header of this spec.

## 9. Decisions (resolved)

| # | Decision | Rationale |
|---|---|---|
| D1 | Extend `checks/adapters_check.py` rather than a new module or Go gate | The check already owns "the adapters delivery contract keeps its executable evidence" (module docstring), is already in `make ci`, and has the pytest + registry infrastructure. CHECKS_REGISTRY prefers a committed root Go test for structural rules, but this is orchestration across Go, YAML, and Markdown artifacts — the documented Python-module case |
| D2 | Pin `@v0.146.0`, not `@latest` | ci-blocking gates must be deterministic; `docs-validate` may float because it is not in `make ci`. Bump = deliberate edit (F7) |
| D3 | One-directional pairing (consts ⊆ rows) | `invalid_request` is a literal with a row and no const; bijection false-fails on pre-existing state (§2) |
| D4 | Section-bounded row matching, anchored on `## Stripe payment adapter` | Matches the requirement's "Stripe section" wording; immune to same-code rows/prose elsewhere (matches `CONTRACT_SECTIONS` heading-pinning precedent in this file) |
| D5 | Anchor comment + `WIRE_CODE_FLOOR = 8` | Fail-closed extraction; floor is a regression guard, not a name pin, so the tenant-claim direction's `ErrTenantMismatch` needs no check edit |
| D6 | Both scans in `run()`; `run_behavioral()` untouched | Both are static validations; `cmd_adapters` already sequences static → behavioral; zero cli.py/Makefile changes |
| D7 | Update CHECKS_REGISTRY.md + cli.py:25 in the same change | "Adding a check" requires documenting blocking behavior; both texts become factually stale otherwise |
