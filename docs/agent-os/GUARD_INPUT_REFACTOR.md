# Migration input-contract refactoring

## Goal and boundary

Reduce review complexity for maintainers of the migration evidence tooling:
`cli.mode_inputs`, `compare.compare`, `conversion_policy.validate_document`, and
`conversion_policy.audit_plan`. Separate input admission, native mapping shape,
and evidence projection within their existing owners. This is **refactoring
only**, with no new command, engine, configuration, dependency, schema or runtime
policy. Other inherited Python complexity debt remains separately reported.

The baseline is the immutable direct-login-refresh candidate on primary
`b3812299daeab6e8147b402418d6488a3faeb775`. Preserve that candidate and its evidence;
work only in a new isolated tree. No commit, merge, deployment, historical data
transfer, production setting change or cutover is included.

## Invariants

- Validate mode/policy/contract dependencies **before loading any file**. Preserve
  existing rejection reasons and precedence, including sequence/schema/content/
  row policy requirements. Absent is `None`, not arbitrary falsy input.
- The parser still accepts at most one observation mode. Reader flags cannot
  authorize the importer; importer intents cannot authorize an observer.
- Default preflight still requires empty business tables. Explicit populated
  observers require a policy and remain observation, not writer admission.
- Policies remain duplicate-free, private, bounded and source/target-shape-pinned;
  only the two existing scalar mappings are supported. Unknown, malformed,
  stale or mismatched inputs never fall back to ordinary preflight.
- Preserve audit target/source shape checks before rowid proof checks. Exact
  positive int64 rowid gaps, ordering hashes, empty-source floor 1 and overflow
  rejection remain unchanged. No sequence allocation/reset or hash rebuilding.
- Preserve every report field, blocker order, metadata order, error and false
  authority flag. Shape PASS is not content/schema/runtime/relationship PASS.
- Do not edit importer, streaming, deadlines, transaction endings, uncertain-write
  reconciliation, report durability, read locks, or sequence observers. Existing
  directory-fsync failure may leave a report; it never proves rollback.
- ACCESS SHARE does not fence writers; sequence observations are non-MVCC. An
  unchanged disposable fixture does not prove production atomicity or fencing.

## Files and acceptance

Modify only the three owning Python modules and the checks registry; add this
bounded specification and `checks/test_migration_input_contract.py`. No new
production Go file, package/import edge, SPI, SDK or protocol field is added.

1. Supplementary conservative AST measurement reproduces the four inherited
   values above 15 before refactoring. Changed functions and helpers must stay
   within 50 lines/15 using the **same** method; no exemption or threshold change.
2. Mode dependency/load-order, strict-policy, audit-proof, report/ordering and
   empty-vs-populated regressions pass before and after refactoring. Differential
   comparison against frozen predecessor bytes reports complete equal results
   or equal rejection reasons, not just successful exits.
3. All engineering checks, build/vet, committed Go gates, full `make ci`, product
   E2E and supplementary acceptance pass on frozen final source.
4. Fresh explicitly owned loopback PostgreSQL exercises read-only CLI modes with
   new synthetic SQLite facts. Fixture setup writes are separately disclosed;
   the refactor/observers do not import, allocate/reset sequences or mutate it.
   Historical runtime, production recovery and other engines are not recertified.
5. Exact private source/patch delivery, independent reconstruction, owned-fixture
   cleanup and unchanged protected worktrees are verified. Keep the existing
   1MiB whole-source archive cap; use bounded patches/tree when exceeded.

Universal criteria from [EVALUATION.md](EVALUATION.md) and committed gates from
[HARNESS.md](HARNESS.md) apply. Remaining Python functions above 15 stay **Partial**;
this slice does not claim whole-tool maintainability or release authorization.

```sh
python3 -m pytest checks/test_migration_input_contract.py -q
python3 -m pytest checks/ -q
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
make ci
go test ./test/ -run TestE2E -v
python3 cli.py accept
git diff --check
```
