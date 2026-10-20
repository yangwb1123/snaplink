# Wave 5c: stock command / shared PostgreSQL acceptance

## Goal and boundary

Run a freshly built root `cmd/sso-server` executable as two independent OS
processes. Exercise its actual flags, config loader, multi-topology guard,
store/authenticator/Browser-SSO wiring, readiness and shutdown, rather than the
SDK helper test binary. Reuse Wave 5b's HTTP/cryptographic assertions without
weakening them. This is a local single-host stock command configuration, not a
container, external browser/UI, protected release, multi-host HA or production
acceptance. `full` is not HA.

Test entry points remain optional unless both `SSO_TEST_POSTGRES_DSN` and a
trusted absolute `SSO_TEST_STOCK_BINARY` are provisioned. Record the selected
binary's SHA-256, `go version -m` and `modules --json`; a path/hash is not an
authenticated builder identity or clean-tag release. Acceptance executions must
have no skipped stock cases and use the instrumented current-source binary.

## Ownership, files and budgets

Cross-process integration stays in `test/` (`package ssotest`), never imports
`cmd/`, and introduces no production package or directory:

- New `reference_stock_test.go`: private real stock config/key files, trusted
  executable launch, bounded HTTP readiness, SIGTERM normal stop, stock tests.
- Existing `reference_process_driver_test.go`: one test-only launch seam and
  checked stop/lifecycle reuse; retain prior SIGKILL/race/panic/reap/DROP guards.
- Existing `reference_process_test.go`: extract the three existing scenarios
  into shared assertion functions, keeping the SDK test entry points intact.
- Extend `docs/sso/reference-apps.md` and `docs/proposals/release-readiness.md`.

Initially no production change was planned. The bounded startup amendment below
owns the reproduced schema-dialect defect only; no public config/API/SPI/schema
version/module/dependency/profile changes. All frozen thresholds/exemptions stay
unchanged. Existing Browser SSO and other owners' work stays separately owned.

## Configuration and trust decisions

- Declare `server.topology.mode: multi` with `allow_per_pod_state: false`.
  Identity, sessions, tenants, passwords and OAuth use shared PostgreSQL. Parent
  provisions two users/four confidential clients once using real stores; stock
  configs contain no users/client seeds and disable first-boot bootstrap.
- Enable stock stored-password authentication, code/refresh and Browser SSO;
  strict refresh rotation (grace off), unchanged PKCE, token TTLs and policies.
  Pre-provision one private Ed25519 PEM key and a separate lookup-HMAC key.
- The fixture's loopback gateway supplies one canonical issuer/origin. Explicit
  proxy trust is loopback only; no arbitrary forwarded-header trust claim.
  Child `SSO_*` environment overlays are removed so unrelated caller settings
  cannot redirect fixture storage/listeners. Config/key/log files are private.
- Bind HTTP loopback; disable gRPC/admin/network APIs/permissions, unneeded
  modules and schedulers. Do not claim application permission, distributed
  service discovery, audit durability, key rotation or live JWT invalidation.
  No Redis bus or durable access-token deny-set is configured in this slice.
- Stock does not accept an inherited listener: a loopback port is reserved and
  released immediately before launch. This small port-allocation race is a
  trusted-runner fixture limitation, not an authenticated PID-to-socket binding
  or production port allocator. Readiness is bounded HTTP `/readyz` with child
  liveness checks; signed token/JWKS assertions validate later operations.

## Acceptance

Apply U1-U9, relevant O1/O7-O8/O10-O11 and S2-S4:

1. Both actual command processes boot the declared multi config without the
   unsafe override, become ready, and run Wave 5b's two-tenant/four-client
   cross-process grants/session resume/refresh/introspection and signed claim
   assertions. A peer rejects mismatched client/tenant code exchange.
2. Requests pinned directly to distinct stock child URLs compete for one code:
   exactly one successful response and byte-identical no-store
   unknown/consumed/loser `400 invalid_grant` responses.
3. Explicit SIGKILL is verified from OS wait status, then the surviving command
   handles a completed peer's outstanding code/refresh state. A newly launched
   command opens the same key/stores without seeding. Consumed-code rejection,
   family-reuse kill and shared-session logout denying peer refresh survive.
   Independent tenant credentials remain usable. This is not in-flight
   exactly-once, database crash/failover durability or JWT-revocation propagation.
4. A mutated multi config with process-local critical state exits nonzero for
   the expected HA-coherence reason. Do not use `--validate-only` as evidence
   of store wiring or this boot-only guard.
5. Normal SIGTERM exits successfully and all commands are reaped before schema
   deletion. Preserve bounded forced cleanup and fail/retain-isolated-schema on
   unkillable-host failure. Reject child race/panic/test-failure diagnostics.
   POSIX signal assertions do not claim Windows crash acceptance.

## Bounded startup amendment: schema-dialect gate

Actual stock PostgreSQL startup reproduced `schema check sessions: migrate(...):
probe version table: ERROR: syntax error ... (SQLSTATE 42601)`. The SQLite-only
boot helper accepts any `DB()`, unlike the health reporter's existing driver
check. PostgreSQL sessions (and tenants) consequently reach a SQLite query.

- Extend existing `serverbuildsign.CheckSQLiteSchema` to run only for a SQLite
  driver, reusing its existing `isSQLiteDB`. Do not alter SQLite's ahead-schema
  rejection or readiness/health behavior.
- Before permitting PostgreSQL construction to bypass that dialect-specific
  query, enforce native ahead-schema rejection in the existing Postgres
  migration runner: a namespace ahead of its declared migrations returns the
  existing `migrate.ErrSchemaTooNew` before pending migration application.
  This covers every Postgres store constructor without wrong SQLite version
  maxima, duplicate version inventories or a new migration/schema API.
  `MaxVersion` assumes ordered slices: validate positive strictly increasing
  versions before SQL, as the migration type already requires. Reject malformed
  inventories explicitly rather than sort DDL silently. Regression tests cover
  descending/duplicate/zero/negative versions and valid idempotent ordered gaps.
- Production scope: `cmd/sso-server/serverbuildsign/build_readiness.go` (143
  lines before) and `infrastructure/postgres/migrate.go` (234 lines before).
  Correct only the now-stale native-gate comment in `build_app_core.go`; preserve
  its earlier lifecycle handoff changes and 500-line ceiling.
  Adjacent real-PG dialect and ahead-constructor tests go in existing readiness
  tests and new `infrastructure/postgres/schema_gate_test.go`. Record red then
  green; repeat under race10 and the complete root gates.
- Compatibility: forward-migrated PostgreSQL namespaces now fail construction
  explicitly instead of relying on optional later stock checks. This tightens
  rollback safety for clients/users/sessions/tenants/passwords as well as other
  stores using the runner. No version numbers/DDL changes, error-code additions,
  migration edits or reductions in SQLite/PG safeguards. Cockroach wire uses the
  same guard, but no actual Cockroach execution is claimed.

## Verification and remaining acceptance

After every Go edit: build/vet and committed root architecture/maintainability
gates. Build the stock command with `go build -mod=readonly -race`, record binary
metadata, run stock cases and affected SDK/lifecycle cases with race10, E2E and
complete real-PG-backed `make ci`. PostgreSQL16/300 connections and Go package
parallelism8 are local fixture resources, not remote default CI or capacity
acceptance. Obtain independent read-only review and close scoped findings.
Local logs live under ignored `dist/release-readiness/stock-process/`.

No OpenAPI/error/config contract change is planned; this consumes existing
surfaces. Container rebuild/runtime/rescan, external UI/browser callbacks,
real TLS/edge/ARM/Mac, distributed keys/revocation, backup/restore, database
failover, load/P99, revocation SLA, RPO/RTO, protected publication and official
certification remain outstanding. No commit/push/publish is authorized.

## Execution result

- Four actual stock scenarios passed `-race -count=10` with the final rebuilt
  race-enabled command; no stock backend case was skipped. Three SDK-process
  compatibility scenarios and lifecycle guards also passed race10.
- Native constructor ahead-schema, dialect routing, existing SQLite gates and
  migration inventory/gap regressions passed real-PG race10. Red logs preserve
  the actual stock startup error, PostgreSQL sessions/tenant dialect failures,
  five constructors accepting future versions, and malformed-order rejection
  before the respective fixes. No assertions or wire policies were weakened.
- Relevant reference/browser/client/introspection/logout compatibility, E2E and
  complete `make ci` passed on the final merged source tree. The same newly
  built binary was selected throughout the final stock runs; SHA-256, Go build
  metadata and compiled module inventory are recorded, not authenticated.
- Independent final read-only source review found no remaining scoped P0/P1/P2.
  Its sole earlier P2 (MaxVersion requires ordered inventory) was reproduced,
  fixed and reviewed closed. Review did not independently execute gates or
  certify binary provenance, builder identity or product/production security.
- Production semantic edits are limited to the SQLite-driver boot predicate and
  PostgreSQL ordered-inventory/native-max guards. A related stale core comment
  was corrected. Owner file sizes are 143 / 245 lines; core remains 500, without
  exemption growth. There are no schema versions, public API/config/SPI,
  dependency or module-profile changes in this wave.
- Evidence: ignored `dist/release-readiness/stock-process/`. Owned PostgreSQL
  fixtures and child processes were cleaned up; unrelated containers were not
  touched. Local PostgreSQL16/300 and Go parallelism8 are not remote CI-default
  or production sizing acceptance.
- Existing OCI scan/runtime/promotion evidence is still stale for current
  production bytes, including these startup changes. No image rebuild,
  commit/push/publication, browser UI, distributed-key/revocation/HA/database
  failover/load/DR acceptance or official certification was performed.
