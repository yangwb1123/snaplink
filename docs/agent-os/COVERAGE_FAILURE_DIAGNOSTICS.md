# Coverage failure diagnostics

## Goal and owner

Operators must see why supplementary acceptance rejected coverage rather than
receiving only a red summary. Owner: Python engineering tooling
`checks/acceptance.py`, consuming the existing `checks/coverage.py` gate.
No SDK, server, store, schema, configuration, permission or dependency change.

## Contract

- `run_py` retains child stdout followed by stderr and preserves the exact exit
  code. This concatenation is not chronological/interleaved stream evidence.
- Failed coverage prints the captured child diagnostic body as well as the
  failed check/acceptance summary. Successful coverage remains summary-only.
- Actual coverage commands, target packages/thresholds, failure conditions and
  caller exit semantics are unchanged. Missing percentages never become zero
  or PASS; failed tests, coverage tools and missing rows remain blocking.
- This improves future observability. Missing original child output/profile
  cannot be reconstructed from source, a later run, or a later successful CI.
  Keep previous failed acceptance results and unknown causes unchanged.

## Verification

`checks/test_acceptance_reporting.py` exercises both real Python owners with
synthetic process seams: stdout/stderr and signed exits, full-root test failure,
coverage-tool failure, missing total row, below-target total, target-package
failure, missing target percentage and unchanged successful summary. These are
reporting tests, not native backend or durable runtime acceptance.

```sh
python -m pytest checks/test_acceptance_reporting.py checks/test_coverage.py -q
make ci
python cli.py accept
```

Use a fresh explicitly owned PostgreSQL fixture when required by the existing
security/catalog coverage workload. No historical import or stock start is
needed for this engineering slice. Whole execution/output/evidence limits still
apply; a timeout, missing profile, partial output or missing normal exit is not
success. Diagnostic archives must be private, bounded, credential-checked and
correlated with the actual commands/exits before original temporary profiles
are removed. Do not silently change workloads, flags, targets or timeouts to
obtain a green run. Diagnostic instrumentation is not independent acceptance.

## Scope of completion

Applicable universal criteria are in [EVALUATION](EVALUATION.md); committed Go
gates and full CI remain authoritative. No new command, option, skip, exemption,
threshold or authorization is introduced. Full startup/worker/shutdown admission,
historical runtime/business parity, browser/external validators, independent
security/integration review, deployed-engine recovery and production cutover
remain separate. A passing new observation does not explain Step44's original
coverage failure, whose nested child exit/output was not retained.
