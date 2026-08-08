Done. The deliverable is **`docs/architect-analysis/cmd-snaplink-stripe-adapter-a14-wire-contract-gate-spec.md`** (315 lines) — a concrete, buildable spec for the A14 gate, with every claim verified by execution rather than inspection.

## What the spec designs

**Two scans appended to `run()` in `checks/adapters_check.py`** (exact constants, regexes, function signatures, and failure strings given):

1. **(g) Nested OpenAPI validity** — `sorted(ROOT.glob("cmd/*/openapi.yaml"))` (exactly one file today), each run through `go run github.com/getkin/kin-openapi/cmd/validate@v0.146.0`, validator stderr echoed on failure, fail-closed on zero matches.
2. **(h) Exported wire-code ↔ docs-row pairing** — extract `Err* = "…"` pairs from `model.go`'s anchored const block (anchor: the `// Wire error codes are exported` comment — its claim becomes true, no comment edit), assert every value appears as a `| code |` row in the **section-bounded** Stripe table of `error-codes.md`.

## Verification results (all executed)

- **Conventions**: matches `adapters_check.py` style (fail-closed extraction à la `scenario_inventory`, `adapters-check: FAIL:` messages, heading-pinning precedent, `run()`/`run_behavioral()` split); CHECKS_REGISTRY "Adding a check" satisfied via 8 spec'd pytest cases in `checks/test_adapters.py` + same-change registry/cli.py doc updates.
- **make ci wiring**: **zero** Makefile/cli.py/go.mod changes — `adapters-check` is already a `ci` prerequisite and `cmd_adapters` already sequences static → behavioral. kin-openapi has zero entries in `go.mod`/`go.sum` (verified); `go run pkg@version` resolves in the module cache.
- **No false-fail on pre-existing state**: kin-openapi exit 0 on the nested file (both `@latest` and pinned); all 8 consts have rows. The worktree turned out to be **mid-implementation** of the tenant-claim direction — the `tenant_mismatch` row (error-codes.md:1051) exists with no const yet — which is a live proof that the one-directional assertion (consts ⊆ rows) is mandatory: a bijection would false-fail right now.
- **Failure modes F1–F5 all injected and surfaced**, then reverted green; interim (8/10) and post-R4.3 (9/10) states both pass — the gate cannot block mid-implementation worktrees.
- **Baseline unchanged**: pytest 14 passed, `python cli.py adapters` green.

One design decision worth flagging: the validator is **pinned** to `@v0.146.0` rather than `@latest` (which `make docs-validate` floats) — a ci-blocking gate must not silently change behavior on a kin-openapi release; bumping the pin is a deliberate one-line edit (spec F7).
