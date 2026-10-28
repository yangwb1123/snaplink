# CHECKS_REGISTRY.md — Agent engineering checks

Catalog of the Python engineering helpers. Committed Go gates are specified in
[`HARNESS.md`](HARNESS.md); broader repository automation is listed by
`make help` and `.github/workflows/`.

## Python modules

| Module | Purpose | Command |
|---|---|---|
| `acceptance.py` | Supplementary U1–U9 report | `accept` |
| `adapters_check.py` | Adapters delivery contract enforcement: conformance-suite inventory, router-backend matrix, embed examples, line budgets, kin-openapi validation of nested `cmd/*/openapi.yaml`, exported wire-code ↔ error-codes.md Stripe-row pairing; behaviorally runs suite + matrix | `adapters`, `make adapters-check` |
| `adr_compliance.py` | Project ADR checks | `adr-compliance` |
| `architecture.py` | Python dependency-direction check | `architecture` |
| `build.py` | Configured binary build | `build` |
| `complexity.py` | Optional cyclomatic/cognitive diagnostics | `complexity` |
| `coverage.py` | Package coverage regression gate | `coverage`, `evaluate` |
| `directory_fanout.py` | Configured subdirectory fan-out | via `adr-compliance` |
| `exemptions.py` | Declarative exemption synchronization | `check-exemptions` |
| `filesize.py` | Configured file-size check | `check-filesize` |
| `health_report.py` | Aggregate engineering health | `health-report` |
| `invariants.py` | Presence-only security marker scan | `check-invariants` |
| `route_contract.py` | Compiles registered route constants and requires matching OpenAPI operations + unique operation IDs | `check-routes`, `make route-contract` |
| `proto_openapi_parity.py` | Proto message field ↔ OpenAPI schema property parity (admin `Client` ↔ `AdminClient`); symmetric drift detection, rejects oneof/nested/reserved blocks it cannot represent | `check-proto-openapi-parity`, `make proto-openapi-parity` |
| `review_feature.py` | Feature-spec/checklist runner | `review [spec]` |
| `root_business_code.py` | Root business-file policy | via `accept`, `check-root` |
| `root_files.py` | Root file-count diagnostic | via `accept` |
| `self_test.py` | Deliberately bad harness probes | `self-test` |
| `sdk_drift.py` | Regenerates canonical TypeScript/Python SDKs in a temporary tree and sweeps optional deploy copies for byte drift | `sdk-drift check`, `make sdk-drift-check` |
| `ops/scripts/module_catalog.py` | Strict module/profile validation and capability planning | `modules check`, `modules list`, `modules plan`, `modules graph`, `modules why` |
| `ops/scripts/capability_registry.py` | Validates product availability against runtime gates/module capabilities and detects generated feature-matrix drift | `capabilities check`, `capabilities generate`, `capabilities list` |
| `ops/scripts/sdk_surface.py` | Orchestrates generated-SDK registry/coverage validation, explicit-baseline operation/schema diffing, and regeneration | `sdk-surface check`, `sdk-surface coverage`, `sdk-surface diff --baseline-ref <ref>`, `sdk-surface generate`, `sdk-surface list` |
| `ops/scripts/sdk_surface_coverage.py` | Strict local decision sidecar, duplicate-safe HTTP inventory and deterministic declaration/boundary report; not a second generation allowlist | Called by `sdk-surface check` and `sdk-surface coverage` |
| `ops/scripts/sdk_versions.py` | Audits seven fixed SDK identities, validates manifest SemVer where present, and checks the TypeScript lock root; Go/Swift versions derive from their own tags | `sdk-surface versions`; also runs inside `sdk-surface check` |
| `ops/scripts/sdk_toml.py` | Stdlib TOML loader with a fixed-format fallback for older repository tooling | Called by `sdk_versions.py` |
| `ops/scripts/sdk_schema.py` | Bounded `components.schemas` structural compatibility comparison using PyYAML; conservative for composition/unsupported keyword changes | Called by `sdk-surface diff` |
| `ops/scripts/sdk_baseline.py` | Reads registry + OpenAPI from one local git ref without fetch/shell, or reports a closed baseline error | Called by `sdk-surface diff` |
| `ops/scripts/sdk_report.py` | Stable operation-surface and schema breaking/additive report formatting | Called by `sdk-surface diff` |
| `ops/scripts/sdk_paradigm.py` | Validates the hand-written SDK-layer capability registry, resolves every declared present symbol against the real tree, and enforces the cross-language conformance fixtures | `sdk-paradigm check`, `make sdk-paradigm-check`; also `sdk-paradigm list` / `make sdk-paradigm-list` |
| `ops/scripts/profile_evidence.py` | Builds profile binaries and asserts the declared package-isolation boundaries (durable/admin graph must stay out of the small editions), archiving per-binary package/module/symbol/size evidence | `profiles evidence [--skip-build]` |
| `ops/scripts/migration_guard/` | Bounded shared evidence and separate candidate-import internals; read-only preflight/content/schema/sequence/recovery readers never transfer; writer requires explicit pinned candidate intent | `python ops/scripts/migrate_snapshot.py --help` |
| `ops/scripts/postgres_recovery_check.py` | Read-only distinct-owned-target comparison to pinned prior native PG public-table observations, including migration histories; never executes archive SQL or restores | `python ops/scripts/postgres_recovery_check.py --help` |
| `ops/scripts/import_snapshot.py` | Explicit one-shot import into an owned disposable candidate only; complete mapped content verification before commit, transactional audit sequence restart, private attempt journal; no production/cutover/retry/overwrite mode | `python ops/scripts/import_snapshot.py --help` |
| `ops/scripts/configure_modules.py` | Atomic alternate modfile/overlay/lock materialization and profile builds | `configure --profile <id> [--version vX.Y.Z] [--build]` |

`config.py` loads `engineering.yaml`; `make_help.py` formats Make target help.
Run `python cli.py check-test` for check-module tests and
`python cli.py skill-test` for skill tests.

## Command groups

| Group | Commands |
|---|---|
| Fast loop | `check`, `check-filesize` |
| Composite reports | `harness`, `accept`, `evaluate` |
| Specific checks | `complexity`, `architecture`, `coverage`, `check-invariants`, `check-routes`, `check-proto-openapi-parity`, `adapters`, `capabilities check`, `sdk-surface versions`, `sdk-surface check`, `sdk-surface coverage`, `sdk-surface diff --baseline-ref <ref>`, `sdk-drift check`, `sdk-paradigm check`, `profiles evidence`, `check-root`, `check-exemptions`, `adr-compliance` |
| Scaffolding | `generate` |
| Diagnostics | `diagnose`, `trend`, `health-report`, `self-test` |
| Test execution | `test`, `race`, `bench`, `check-test`, `skill-test` |
| Review | `review [spec]` |
| Module builds | `modules <action>`, `capabilities <action>`, `sdk-surface <action>`, `sdk-paradigm <action>`, `profiles evidence`, `configure --profile <id> [--version vX.Y.Z] [--build]`; `modules smoke` builds every supported profile plus each currently buildable preview |

`python cli.py --help` is the executable command index.

## Scope and limitations

- [Post-build exit lifecycle](STOCK_STARTUP_LIFECYCLE.md) records partial-build,
  worker, listener and flush effects. `TestStartupExitCleanup_` pins one late-bound
  deferred runtime teardown before backing-store close on every post-build exit,
  partial listeners, ownership of the gRPC health poller after a failed bind with
  no retained server handle, normal-only clean logging, the run-error branch
  flushing tracing/config sources before `os.Exit`, and the failed-build owner
  installed before shared-pool allocation releasing both pools via
  `closeBuildFailure` (direct `fail()` exits after the
  source defer is installed remain outside this bound). Synthetic source/lifecycle
  tests do not prove full reachability, rollback or historical startup admission.
- [Coverage failure diagnostics](COVERAGE_FAILURE_DIAGNOSTICS.md) retains Python
  child stdout then stderr and prints rejected coverage details without changing
  commands, thresholds, failure or exit semantics. Reporting regressions live in
  `checks/test_acceptance_reporting.py`. Future diagnostics and later success do
  not recover missing original child output or reinterpret prior failed gates.
- [Finite stock launch/configuration binding](STOCK_STARTUP_LAUNCH.md) distinguishes
  file-only inspection from stock file/environment/optional-etcd/flag resolution.
  `migration_guard/startup_launch.py` rejects any unreviewed argv/environment in
  its finite owned-rehearsal context; `checks/test_migration_startup_launch.py`
  pins strict/nonmutating boundaries. `TestStartupLaunch_ConfigSourceChain` uses
  the actual stock parser/source builder, including environment reaper activation
  and CLI precedence. Neither supplied-context hashing nor configuration loading
  proves complete startup effects or authorizes historical stock execution.
- [Stock startup preservation prerequisites](STOCK_STARTUP_PRESERVATION.md)
  enumerate constructor Load/Prune, builtin bootstrap and immediate client-secret
  scan effects. `migration_guard/startup_preservation.py` rejects malformed facts,
  populated revocations and pending builtin seed/row rewrites; tests are in
  `checks/test_migration_startup_preservation.py`. This finite pure prerequisite
  checker neither proves its inputs nor completes startup inventory/authorizes
  stock execution; complete source/config/own-history admission remains separate.
- [Code-exchange refresh grants](AUTHCODE_REFRESH_GRANTS.md) require effective
  exact offline scope plus exact `refresh_token` in nonempty client grant lists;
  nil/empty lists remain compatible. `TestAuthCodeRefreshGrant` pins pre-store
  denial/context; `TestE2E_AuthCodeRefreshGrant` covers real memory/SQLite HTTP,
  persistence/audits/replay/rotation. Fresh owned-PG stock acceptance is separate;
  prior failed runtime results and all unexecuted dimensions remain visible.
- [Historical stock-runtime rehearsal](HISTORICAL_STOCK_RUNTIME.md) requires
  fresh control/browser-off/browser-on imports, a pre-traffic cleanup inventory,
  complete original-row preservation and actual stock synthetic wire evidence.
  Default-zero cleanup, short refresh-family expiry and synthetic credentials do
  not certify enabled reapers, natural 30-day session expiry, historical passwords
  or full HTTP/business equivalence; preserve prior failed runtime outcomes.
- [Converted historical runtime acceptance](CONVERTED_RUNTIME_ACCEPTANCE.md)
  defines fresh owned-candidate import, typed historical API parity, explicit
  browser/offline profiles and complete original-row preservation after stock
  activity. Synthetic credentials, expiry injection and finite PostgreSQL 16
  evidence do not certify historical logins, production recovery or cutover.
- [CIBA request admission](CIBA_ADMISSION_GRANTS.md) requires exact CIBA in
  nonempty client grant lists before hint/verifier/pending/challenge side effects.
  `protocols/oauth/handle_ciba_grant_admission_test.go` pins authorization and
  existing error ordering; `test/backchannel_grant_admission_test.go` covers real
  memory/owned SQLite requests and authorized poll, ping collection, local TLS
  push, replay and rotation. Existing pending requests and approval-time policy
  revalidation remain outside this gate; no new offline-scope requirement.
- [CIBA refresh grant restrictions](CIBA_REFRESH_GRANTS.md) enforce exact
  `refresh_token` in nonempty client grant lists before refresh-store access.
  `internal/handler/tokengrant/token_ciba_refresh_grant_test.go` pins boundary
  calls, forwarded context and the shared poll/push builder. Real-memory and
  owned disposable SQLite HTTP tests in `test/ciba_refresh_grant_test.go` cover
  poll, ping collection, local TLS push, omission, issuer non-fallback, replay
  and existing no-offline family rotation. CIBA offline-scope semantics remain
  unchanged; no Redis/PostgreSQL CIBA, HA or historical-runtime certification.
- [Device refresh authorization](DEVICE_REFRESH.md) requires exact offline scope
  in the approved stored device grant plus the existing store/grant-type checks.
  `internal/handler/tokengrant/token_device_refresh_scope_test.go` pins the
  no-contact/issue/event boundary and forwarded context; real-memory HTTP tests
  in `test/device_offline_access_test.go` cover scopes, defaults, poll non-expansion,
  ID/access independence, store failure, issuer non-fallback, replay and rotation.
  Committed Go gates/full CI remain authoritative; these synthetic fixtures do
  not certify historical credentials, other grant policies or production cutover.
- The [current-base storage combination](STORAGE_COMBINATION.md) retains distinct
  read-only and candidate-writer admission; broader inventory support does not
  expand import/recovery scope or certify converted-runtime/cutover acceptance.
  `checks/test_migration_storage_combination.py` covers the shared boundaries.
- The [migration input-contract refactor](GUARD_INPUT_REFACTOR.md) keeps policy/
  contract dependency rejection before file loading, strict scalar mappings,
  audit shape/proof ordering, empty-target admission and shape-only report fields.
  `checks/test_migration_input_contract.py` covers these owners and applies the
  unchanged supplementary AST budget locally; other inherited Python debt is
  still partial, not waived or converted into a whole-tool maintainability PASS.
- `make ci` is the core local gate; hosted CI additionally runs lint,
  security, contract, container, and infrastructure validation.
- `make proto-lint`, `proto-gen`, and `proto-breaking` share the pinned Buf
  v1.73.0 invocation in `Makefile`; none resolves `@latest` or silently uses a
  different PATH binary. Its subprocess alone selects Go 1.26.9 explicitly
  (Buf requires >=1.26.7); the root product remains Go 1.26.1. Offline use
  requires a reviewed local file module proxy, cached Buf/transitive modules,
  the compatible toolchain, and cached checksum verification. `GOPROXY=off`
  alone cannot satisfy Go's deprecation/toolchain metadata lookups. Missing
  caches fail rather than skipping validation; no global toolchain change. `proto-gen` may still
  need network access for its declared remote plugins. Default CI runs lint,
  not generation or the opt-in wire-breaking comparison.
- `migrate_snapshot.py` remains read-only and has no apply/cutover mode. Its
  optional `--conversion-policy-file` is private bounded JSON with exactly
  `version`, `source_sha256`, `target_shape_sha256`, and a nonempty `mappings`
  list. Each mapping has exactly `table`, `column`, `mode`. Version 1 retains its
  two-entry limit and supports only these pairs:
  `audit_events.seq` / `sqlite_rowid_int8_v1`, and
  `permissions_resources.dispatch_key` / `text_utf8_bytea_v1`. Audit rowids
  remain exact positive int64 values, including gaps; never derive sequence
  from IDs/timestamps or regenerate hashes. Dispatch text becomes strict UTF-8
  bytes, including NUL, without trimming, normalization, JSON rendering or key
  regeneration; NULL stays NULL. Invalid/duplicate/unknown/stale policy fails
  rather than falling back. Other missing/extra columns, type/storage/NULL/PK
  errors and nonempty targets still block import preflight. The target fingerprint covers only
  column name/type/nullability/PK, not complete DDL. Sequence calibration,
  defaults/indexes/FKs/collations, full content/relationship verification, audit
  chain evidence and operator approval remain separate gates. A mapping-plan
  PASS is neither copied-data acceptance nor authority to use the old mover.
- Opt-in conversion policy version 2 additionally permits exactly the three
  absent client policy columns via `client_policy_zero_v1`; it requires at least
  one such entry and allows at most five total distinct mappings. Exact native
  int4/int8, NOT NULL, non-PK and canonical constant DEFAULT 0 evidence is mandatory.
  The catalog adds optional Boolean `canonical_zero_default`, not raw expressions;
  legacy frames remain supported but cannot authorize new defaults. Typed
  projection/COPY and locked pre-COPY checks bind explicit integer zero, never
  editable attributes or historical-policy inference. Version 1 rejection/order
  remains unchanged. See [client policy projection](CLIENT_POLICY_ZERO_PROJECTION.md);
  no historical runtime/password/key/cutover certification follows from it.
- [Historical API read-only projection](HISTORICAL_API_READONLY.md) uses an
  explicit version-2-bound TEMP client view, never a source schema upgrade.
  `NewClientStoreWithoutMigrations` only wraps an initialized database; existing
  constructors retain their semantics. Query-only API comparison and complete
  before/after storage evidence remain separate from stock login/session runtime,
  historical passwords/keys, independent review and production cutover authority.
- Optional `--row-evidence` requires the explicit policy and audit rowid mapping;
  it preserves default CLI behavior when absent. Every business table gets a
  `pk_sorted_typed_projection_v1` expected-content digest: target columns are
  sorted by name, PK components by PK position, and rows by encoded typed PK
  bytes (not database collation). Exact typed JSON is UTF-8 encoded; each
  aggregate member is prefixed with its eight-byte big-endian length. The
  content header binds algorithm/table/column shape; each row binds the full
  encoded PK and SHA-256 of all projected fields. The PK-set digest separately
  binds PK column names and all encoded keys. NULL, empty text/bytes, int64,
  Unicode/trailing spaces, and stored historical fields remain distinct.
  Only explicitly version-approved scalar projections run; metadata history is not
  projected. Scans are SHA-rechecked, read-only, time/row/byte bounded, and
  reports contain digests, not raw row values. These are expected source
  projections, **not compared target contents** or relationship proofs.
- Extended sequence checks require the observed audit BIGSERIAL to be owned by
  `public.audit_events.seq`, have its canonical nextval default and one default
  dependent, and use int8/start1/min1/max-int8/increment1/cache1/no-cycle. Identity
  columns, alternate configurations, missing/unreadable/changed/exhausted state
  fail rather than guessing. Only `last_value`/`is_called` are read; nextval and
  setval are never called. The candidate next value must reach the source rowid
  maximum plus one, otherwise `audit_sequence_below_required_floor` blocks the
  extended report. A new empty target can therefore pass Step16's mapping plan
  but fail extended readiness until separately authorized calibration. Repeat
  observations detect drift, not writer fencing or an atomic cross-query
  snapshot; sequence state is non-MVCC. Row-evidence mode supplies no reset,
  import, grant, target-content comparison, complete DDL certification, recovery
  proof or cutover permission. Other stores/sequences and full FK/index/collation
  acceptance still need independent checks.
- `--verify-target-content` is a separate, mutually exclusive read-only mode
  requiring the explicit policy and audit mapping. Explicit content/schema/sequence
  verification purposes accept populated targets; default preflight and `--row-evidence`
  continue to require empty business tables. Shape checks remain mandatory, and
  a shape PASS alone is never content verification. Source and target use the
  same unchanged `pk_sorted_typed_projection_v1` digest contract. The verifier
  compares every business table's row count, complete encoded PK set and all
  mapped fields. Missing/extra rows, changed keys/tenants/content, NULL/empty
  substitution, nonfinite floats and incomplete/malformed/truncated streams fail.
- Target content is read in **one REPEATABLE READ READ ONLY transaction**.
  Explicit `public` ACCESS SHARE locks prevent DDL drift during the read; they
  do not fence ordinary writers. Ownership/database/role, isolation, and the
  policy-bound catalog are validated before any data script is sent. Ordinary
  native tables without RLS and native `pg_catalog` text/int2/int4/int8/float8/
  bytea columns are supported; RLS, partitions, type-namespace spoofing and other
  unsupported shapes reject instead of certifying filtered/partial contents.
  User-schema shadows cannot replace public tables. Integers travel as exact
  decimal strings, float8 as network-order IEEE bytes, bytea as hex, and text as
  unchanged strings; JSON numbers never round int64. Only outer wire envelopes
  become compact JSONB for one-frame-per-line output; stored JSON text is not
  parsed or re-rendered. SQL generation omits redundant NULL branches solely
  for locked, validated native NOT NULL columns, preserving nullable distinctions.
- Scalar and catalog validation remain in `target_codec.py` / `target_content.py`;
  `checks/test_migration_reader_contract.py` pins exact rejection ordering, integer
  endpoints, binary64 bits, unchanged text, NULL/empty and metadata seams. See
  [READER_CONTRACT_REFACTOR.md](READER_CONTRACT_REFACTOR.md). Its conservative
  AST budget is supplementary; it does not replace committed Go gates or certify
  all remaining migration-tool Python debt.
- Content transport has bounded full-duplex pipes and owned-process cleanup:
  each generated statement <=4 KiB, total scripts <=64 KiB, each JSON frame
  <=2 MiB, stderr <=8 KiB, total wire <=128 MiB, and each source/target canonical
  scan <=128 MiB. Existing
  row/table/column/window limits remain; budgets/queries/validator errors never
  become an empty PASS. Full completion and normal subprocess exit are both
  mandatory. Credential/SQL/row-value diagnostics are withheld; reports carry
  digests, not raw keys/rows. Business counts in the snapshot are observed;
  native migration-history counts are explicitly untracked, never fabricated zero.
- Exact content PASS means only that the declared snapshot's supported mapped
  content/PK matched. The CLI separately retains the audit sequence gate;
  matching data can still FAIL for an uncalibrated sequence. Content is MVCC,
  but sequence state is not; concurrent commits after the snapshot are not
  covered. No writer fencing, business/runtime equivalence, full DDL/FK/collation,
  historical audit-chain proof, calibration, recovery, import or cutover authority
  follows. An empty actual target against a nonempty retained source still fails.
- Optional `--verify-target-schema` is a third mutually exclusive read-only
  mode. It requires the conversion policy, audit mapping, private
  `--schema-contract-file` and a separately pinned `--schema-contract-sha256`.
  Invalid/stale/duplicate/unknown/unpinned contracts reject before target contact.
  No implicit baseline learning, schema export, DDL execution, import, sequence
  calibration or approval mode is provided. Default empty-target preflight,
  source projection and content verification retain their previous semantics.
- `pg_native_schema_facets_v1` compares every business table against explicit
  expected hashes: native column positions/type namespace/typmod/defaults/
  identity/generated/collation, constraint definitions and FK actions/match/
  deferral/validation, full index definitions (including unique, NULL-distinct,
  include/expression/predicate/operator-class facts and readiness), collation
  provider/locale/version, owned sequence **descriptors** and relation hazards.
  Exact environment/version/encoding/collation facts are pinned separately.
  Fingerprints exclude unstable catalog OIDs; record order is canonicalized
  without database collation. All facets and tables must arrive completely.
  Raw defaults/DDL and row keys are not emitted; reports retain hashes/counts.
- `checks/test_migration_schema_validation_contract.py` pins schema contract,
  facet-record and declared-FK validation grammar, budgets, aliases and exact
  first-failure order. [SCHEMA_VALIDATION_REFACTOR.md](SCHEMA_VALIDATION_REFACTOR.md)
  documents the refactor-only boundary. Its conservative AST metric is
  supplementary; remaining Python debt and production approval stay separate.
- `checks/test_migration_schema_reader_contract.py` pins ordered schema frame
  dispatch, identity/environment advancement, FK completion and child-failure
  boundaries, including Recovery inheritance. [SCHEMA_READER_COMPLETION.md](SCHEMA_READER_COMPLETION.md)
  defines the refactor-only scope; conservative AST diagnostics do not replace
  committed Go gates or production approval.
- `checks/test_migration_checkpoint_validation_contract.py` pins checkpoint
  envelope/archive/source-identity grammar, exact budgets, aliases, validation
  order and pinned JSON load behavior. [RECOVERY_CHECKPOINT_CONTRACT.md](RECOVERY_CHECKPOINT_CONTRACT.md)
  defines the refactor-only boundary; archive fingerprints never grant restore
  authority, and supplementary AST diagnostics do not replace committed gates.
- Native schema/FK inspection reuses the owned loopback identity, shape policy,
  and bounded full-duplex transport in one REPEATABLE READ READ ONLY transaction.
  ACCESS SHARE locks protect relation/column DDL requiring conflicting locks;
  this is not exclusive writer/DDL fencing or current-state/production proof.
  User triggers/rules/inheritance/RLS, generated/identity columns, type namespace
  spoofing, invalid indexes and observed collation-version drift reject. Existing
  statement/script/frame/output/time budgets remain; each facet <=256 records,
  total declared FKs <=100 and total FK child-row scans <=200,000. PG15/16 catalog
  grammar is supported, but real-engine evidence is explicitly PG16.14 only.
- Declared FK checks resolve ordered composite components, require scoped public
  parents and native equality operators, and distinguish MATCH SIMPLE (any NULL
  exempts) from MATCH FULL (all NULL exempts; partial NULL violates). Orphan or
  NOT VALID declarations block. Only declared native relationships are checked;
  missing declarations return `not_executed/no_declared_foreign_keys`, never an
  empty success or inferred relation. SQLite declarations are SHA-pinned and
  inspected independently; absent FKs do not establish business relationships.
  Snapshot row counts are explicitly untracked in schema-only mode. The audit
  sequence readiness gate remains separate and can still block a schema match.
- A contract match proves only supported facets equal the **declared** baseline.
  Baseline file/hash/provenance claims are untrusted inputs, not operator approval
  or proof that product DDL is adequate. A freshly initialized owned canonical
  fixture may supply experimental expected hashes for independent fault tests;
  it does not approve its own schema for production. `full_ddl_certified`,
  `all_business_relationships_verified`, `all_sequence_states_verified`,
  `target_content_verified` and `schema_baseline_provenance_verified` stay false
  in schema-only evidence. Undeclared business/tenant relations, all object kinds,
  privileges/extensions/function bodies, crash/failover/recovery, actual sequence
  state/fencing, historical audit chain and cutover acceptance remain separate.
- `postgres_recovery_check.py` is a separate native-PG evidence entrypoint, not a
  SQLite migration mode or restore executor. It requires private bounded
  `--checkpoint-file` / `--checkpoint-sha256`, `--archive-file` /
  `--archive-sha256`, a `--restored-connection-file` and new private `--report`.
  Invalid, stale, duplicate, unknown or unpinned inputs reject before target
  data queries. The archive is fingerprinted (<=64 MiB, PGDMP prefix); its format,
  origin or actual consumption is **not** certified by the reader. No dump,
  restore, clean, overwrite, TRUNCATE, sequence-reset or approval mode exists.
- `pg_readonly_recovery_checkpoint_v1` pins prior observed native public-table
  content/PK digests, supported schema facets/environment, and canonical audit
  BIGSERIAL descriptor/state. A checkpoint is untrusted explicit evidence, not
  an operator grant or a self-approved production baseline. The experimental
  `capture_checkpoint` API observes an owned fixture; it does not correlate its
  separate reads atomically with a backup. The destination must use a distinct
  dedicated database and ownership nonce, and the declared role. Credential
  hashes in private inputs never expand authorization; reports omit credentials,
  raw rows and raw DDL. Public ordinary native tables with complete primary keys
  and supported scalar columns are required, including **migration histories**.
  PK/content encoding and default SQLite-preflight/content-mode behavior remain
  unchanged; complete history-count coverage is tracked only in this native recovery
  mode. Separate sequence inventory tracks counts of its owner tables, including
  a history table only when it owns a supported sequence; other counts remain unknown.
- Recovery content plus histories use one locked REPEATABLE READ READ ONLY
  snapshot; schema/FK facets use another; sequence state is non-MVCC. Complete
  frames, successful process exits, private input rechecks, and the existing
  row/statement/script/frame/wire/time budgets remain mandatory. Metadata RLS,
  partitions, missing PKs, type spoofing, incomplete replies, malformed counts,
  unsupported sequence configurations, and other public sequences reject. The
  current accepted sequence scope is canonical `audit_events.seq` only. Restored
  history rows/timestamps, keys, zero/NULL/empty, untouched stored JSON text,
  integer/float bytes, schema facets and sequence state must match the checkpoint.
- A recovery observation PASS is **not** proof that this archive was restored,
  that its origin/format is valid, that writers were fenced, or that all reads
  share one point-in-time snapshot. Audit required-floor/chain, all sequences,
  undeclared relationships, full DDL, roles/grants/extensions/external encryption,
  signing/HMAC keys, live authentication and production recovery remain separate.
  `archive_consumption_provenance_verified`, `archive_format_fully_validated`,
  `backup_snapshot_correlation_verified`, `restore_execution_verified`,
  `cross_phase_atomic_snapshot`, `writer_fencing_verified`,
  `production_recovery_certified` and `cutover_authorized` stay false.
  A separately authorized isolated fixture rehearsal may record actual native
  dump/restore exits and integrity/fault witnesses, without promoting these
  reader flags or granting any real-source transfer/cutover authority.
- `import_snapshot.py` is a **separate writable candidate-rehearsal entrypoint**;
  all earlier evidence CLIs remain read-only. It requires the private source SHA,
  explicit conversion policy, pinned native schema contract, a separately SHA-pinned
  private short-lived intent, exact candidate database confirmation, and new private
  journal/report paths. The intent binds source/policy/schema/shape/database/owner
  digests, expires within one hour, declares an exclusive disposable candidate, and
  explicitly denies final-cutover snapshot and audit-chain certification. This caller
  claim/file is neither independently verified exclusivity nor production approval.
  Only loopback `snaplink_mig_*` databases with the exact ownership nonce qualify.
- `checks/test_migration_copy_coverage_contract.py` pins lazy source-SHA/coverage
  admission, caller-order/exact COPY bytes, counter/budget failures, owned SQLite
  closing and no copied marker on cancellation/final-source drift.
  [IMPORT_COPY_COVERAGE.md](IMPORT_COPY_COVERAGE.md) bounds the refactor; COPY
  generation neither grants writer authority nor proves commit/rollback.
- `checks/test_migration_admission_sequence_contract.py` pins declared-FK to
  canonical audit descriptor/public-sequence admission, ordered envelopes/errors,
  aliases and genuine partial state on budget/send failure. See
  [IMPORT_ADMISSION_SEQUENCES.md](IMPORT_ADMISSION_SEQUENCES.md); admission
  completion is not COPY/commit authority, and the separate runner debt remains.
- One REPEATABLE READ write transaction takes ACCESS EXCLUSIVE locks on all existing
  public business/history tables and the ownership marker plus a cooperative advisory
  lock. Ownership, full native scalar/PK catalog, pinned supported schema facets,
  relation hazards, declared FKs and canonical audit sequence are checked inside the
  locks. Empty business contents are rechecked there, not just before connection.
  Supported FK dependencies are parent-first; self/cyclic/unsupported dependencies
  reject. All business columns/rows are copied explicitly via bounded escaped COPY
  text. No common-column intersection, defaults substitution, TRUNCATE, CASCADE,
  historical rewrite or SQLite migration-history copying occurs.
- `checks/test_migration_commit_protocol_contract.py` pins deadline-first runner
  dispatch, post-copy FK/restart/ack ordering, private-input rechecks, journal/send
  failures and genuine partial flags. [IMPORT_COMMIT_PROTOCOL.md](IMPORT_COMMIT_PROTOCOL.md)
  bounds the refactor: in-memory acknowledgement never substitutes for normal
  child exit, final deadline or durable success; uncertain writes are not retried.
- Exact source/target PK/content digests and native history before/after must match
  **before COMMIT**; declared FKs and all pinned private inputs are rechecked. Audit
  rowid mapping sets the next floor using transactional `ALTER SEQUENCE ... RESTART`,
  never nontransactional setval or nextval. Only canonical audit serial is supported;
  other public sequences reject. Source inspection, target inspection, projection,
  pipes and transaction share a 60-second deadline. Existing row/byte/frame/query/
  stderr limits remain; incremental COPY input is bounded to128 MiB and2 MiB/row.
- The exclusive0600 fsynced attempt journal persists `commit_requested` before sending
  COMMIT. Success needs exact acknowledgement **and** normal subprocess completion
  and durable evidence. Lost acknowledgement, cancellation, abnormal exit or missing
  evidence fail without retry; retain/reconcile the candidate before any replay.
  Killing psql is not reported as verified rollback. Table locks/advisory ownership
  do not certify global/admin DDL fencing or same-UID isolation. Post-commit runtime,
  independent read-only verification, native restore, live source freeze/drift,
  external keys/grants, HTTPS and production/operator acceptance remain separate.
- `--verify-target-sequences` is a fourth mutually exclusive SQLite-snapshot
  inspection mode requiring the explicit conversion policy and audit rowid mapping.
  It catalogs **every sequence in every schema of the owned database**, with no
  namespace exclusion (even custom objects placed in system schemas cannot hide);
  unsupported/non-public/unowned/shared/identity/default-expression/extension or
  alternate-configuration sequences reject before state/floor data queries. The
  accepted profile is public canonical positive SMALLSERIAL/SERIAL/BIGSERIAL:
  native int2/int4/int8, start/min/increment/cache1, native type maximum, no cycle,
  an ordinary non-RLS native NOT NULL owner column, one automatic owner, one exact
  nextval default dependent and no other dependencies/dependents. The audit owner
  remains `audit_events.seq` BIGSERIAL. Empty or incomplete inventories fail closed.
- All accepted owner-column counts/min/max share one locked REPEATABLE READ READ
  ONLY table snapshot. Values are exact decimal strings on the wire; nonpositive,
  out-of-range, NULL or malformed counts/bounds reject. Next candidate must exceed
  the observed column maximum, and audit must additionally reach the pinned source
  rowid floor. Source floor1 for other owners is **not** a source-content comparison.
  Exhaustion blocks. Aggregate bounds/sequence scalars are reported, never raw rows,
  keys, defaults or credentials; non-owner table/history counts remain `None`.
  Existing row/script/statement/frame/wire/window budgets and complete frames plus
  normal child exit remain mandatory. Two fresh catalog reads bracket state rereads;
  OID/config/state drift rejects, without claiming atomicity or protection from a
  mutate-and-revert/nextval/setval race. The verifier never calls nextval/setval,
  calibrates or writes target data. `supported_inventory_complete` and
  `supported_sequence_states_observed` describe finite accepted observations only;
  `all_sequence_states_verified`, `sequence_state_in_mvcc_snapshot`,
  `writer_fencing_verified`, `cross_query_atomic_snapshot`, `target_content_verified`,
  `production_recovery_certified` and `cutover_authorized` stay false. Existing
  recovery checkpoints still accept only canonical audit sequence state; this
  separate inventory does not silently change recovery scope or grant import.
- `route_contract.py` covers statically registered stock-server routes plus
  the out-of-router liveness/readiness probes. Embedder-owned dynamic routes
  added through `Server.Handle` require their own OpenAPI contract.
- `adapters_check.py` static scans cover existence-level contract facts AND
  two wire-contract assertions: every `cmd/*/openapi.yaml` passes pinned
  kin-openapi validation, and every exported wire-code const in
  `cmd/snaplink-stripe-adapter/model.go` appears as a `| code |` row in the
  error-codes.md Stripe section (one-directional: consts ⊆ rows); behavior is covered
  by the Go tests it invokes (conformance suite + matrix), which run without
  `-race` — race coverage lives in `make ci`'s `race` target and
  `make test-e2e`.
- `capability_registry.py` describes product-level capability domains, not
  every protocol row or every profile's resolved dependency closure.
- `sdk-surface versions` is a read-only, non-networked gate over seven fixed SDK
  identities: TypeScript (and its lock root), Python, Rust, PHP, Kotlin, Swift
  and the independent `sdks/go` module. Go and Swift derive release versions
  from tags, not manifest version fields; central auditing does not transfer Go
  publication ownership to the root module. It rejects
  missing or malformed manifests, missing/non-string/invalid SemVer versions,
  and a TypeScript lock-root mismatch. Each package version is validated
  independently; cross-package version equality is not required. It reads only
  package-root metadata, never dependency versions, and does not publish or
  change any file. `sdk-surface check` and `make ci` run the same gate;
  versioned package publication remains an external release boundary.
- `sdk-surface check` also requires exact coverage decisions in
  `ops/build/sdk-surface-coverage.json`: every OpenAPI HTTP operation is either
  selected by the sole generator allowlist or explicitly unselected with matching
  operationId/method/path. New unclassified operations, stale/overlapping/duplicate
  exclusions, missing group reasons, duplicate raw YAML keys/operationIds, invalid
  versions/fields/text and escaping/missing file references fail closed. There is
  no automatic catch-all exclusion or network access. `sdk-surface coverage`
  prints stable sorted JSON with decisions, media types and OpenAPI security
  declarations (operation/root/unspecified, preserving explicit empty arrays),
  plus manually maintained exposure/authentication/default/licensing boundaries.
  This is decision completeness, not full API support, runtime exposure/auth
  verification, a license grant or platform acceptance. Selected HTML/SSE methods
  retain their existing generator limitations. Tests live in
  `test_sdk_surface_coverage.py`; no historical diff baseline needs the sidecar.
- `sdk-surface diff` compares the committed registry's group/operation data and,
  when available, a bounded structural subset of OpenAPI `components.schemas`.
  It requires exactly one explicit local baseline (`--baseline-ref` or
  `--baseline-file`); a ref reads both files from that same local commit without
  fetching, while `--baseline-file` is registry-only unless explicitly paired
  with `--baseline-openapi-file`. It never reads generated SDK source, changes
  versions, or exposes a breaking-change bypass. Removed/renamed operationIds,
  group relocations, schema/property removals, required additions, `$ref`/type/
  format changes, `additionalProperties` tightening, enum removals, and nested
  or array breaking changes fail; optional properties, required removals, and
  enum additions are additive. Description/title/examples/default metadata is
  ignored. `oneOf`/`anyOf`/`allOf` and other unsupported schema keyword changes
  use a conservative breaking policy; this is not a complete vendor-level OAS
  diff. The opt-in `make sdk-surface-diff` target requires
  `SDK_SURFACE_BASELINE_REF`; it is intentionally not a `make ci` prerequisite, so
  a shallow or parentless local checkout cannot create a false baseline result.
- `sdk-paradigm` governs what the generator never sees: the hand-written
  transport, session, entitlement, preferences, and runtime behaviour of the five
  hosted-login SDKs plus the registered Kotlin and Swift native SDKs. Kotlin and
  Swift remain in onboarding; `sdk-surface` deliberately covers only generated
  TypeScript and Python clients. The registry is the only source of
  truth; the checker never infers a capability from source. A `present` entry
  must name a real file and a symbol the checker finds in it, so renaming a
  symbol fails until the registry is edited deliberately. This presence check is
  not proof of public access or executed native fixtures. Swift remains onboarding;
  its internal transport/store seams are `missing`, and existing but unaccepted
  clear/entitlement source is explicitly recorded as validation debt. The narrow
  `test_sdk_paradigm_source.py` audit does not execute Swift or change parity. A `missing` entry must
  name the wave that closes it and may not name a file or symbol. A capability
  declared `parity` must be present in every language, so the eight parity
  capabilities cannot erode; downgrading one to `divergent` is a contract change
  requiring a minor bump and a CHANGELOG entry. Every package in
  `sdk_versions.MANIFEST_SPECS` must declare a language, so a newly published SDK
  cannot ship ungoverned. The gate also requires the four cross-language
  conformance fixtures under `ops/build/sdk-conformance/` to exist and carry
  their invariants. It is read-only, non-networked, and is a `make ci`
  prerequisite; `make sdk-paradigm-list` prints the capability matrix.
- `invariants.py` confirms selected markers exist somewhere; it does not prove
  per-endpoint behavior.
- Coverage fails closed when the test subprocess fails, a package target cannot
  be resolved, or a coverage row is missing. Optional complexity remains a
  diagnostic unless invoked through a blocking project gate.
- Python and Go fan-out use the same 15-subdirectory ceiling and skip scope;
  the committed Go exemption maps remain the ratcheted authority.

Exact open debt belongs in [`TODO.md`](TODO.md) and acceptance caveats in
[`EVALUATION.md`](EVALUATION.md).

## Adding a check

Prefer a committed root Go test for a build-blocking structural rule. Use a
Python module for orchestration or cross-cutting diagnostics, add its unit
test, expose it through `cli.py`, and document whether it blocks or only
reports. Project-specific OAuth/ADR scans must not be presented as generic
policy.
