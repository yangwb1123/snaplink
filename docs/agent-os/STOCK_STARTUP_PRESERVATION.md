# Stock startup preservation prerequisites

## Goal, scope and non-goals

A converted candidate can preserve every imported row yet still execute startup
writes before the first credential request. Identify those effects before running
stock, and reject preservation conflicts rather than hiding them behind zero
reaper intervals. This document is a source review and bounded feature spec, NOT
an execution receipt, complete startup inventory, or authorization to start stock.

Classification: migration/evidence tooling in `ops/scripts/migration_guard`.
No stock Go, store SPI, YAML/default, schema, cleanup, HTTP, SDK, grant or session
policy changes. Independent compatibility/security/integration review remains
required for the inherited combination. Earlier failed runtime results remain
failed; later source review cannot retrospectively admit their traffic.

The first prerequisite checker deliberately supports ONLY an empty revocation
table and pre-existing default bootstrap principals/clients requiring no row
rewrite. Nonempty revocations, missing authority or a pending bootstrap rewrite
require a separate policy decision; even currently live revocations are outside
this finite rule. Never delete rows, change expiry, fabricate bootstrap history,
edit historical grants or disable bootstrap/cleanup to satisfy it.

## Unconditional and data-dependent startup effects

Follow `cmd/sso-server/main.go::run` through `buildApp`, foundation/domains/edge,
`finalize`, `sso.NewServer`, background workers, then `runBootstrap`, before HTTP.
Source owners and actual function bodies, not comments or configuration names,
determine effects. Required source pins belong in the execution evidence.

| Path / owner | Startup effect | Preservation admission |
|---|---|---|
| `serverbuildstore/build_identity_stores.go`; `infrastructure/postgres/{clients,users,session}.go` | Constructors run clients/users/sessions migrations; sessions PG constructor does not start the memory session reaper | Canonical initialized complete schema and each candidate's own full histories must already match; reject pending migrations or schema drift |
| `serverbuildsign/build_signing.go`, `build_signing_issuers.go`; `defaultimpl/ed25519_validate.go`; `postgres/securitystore/{store,revocations}.go` | Revocation constructor migrates; issuer `SeedRevocations` calls `Load`, which unconditionally calls `Prune`: `DELETE ... WHERE exp < now` before selecting live rows | Intervals do not control this write. v1 requires actual revocation count 0; no inference from timestamps or an initially empty control alone |
| `serverbuildauthn/build_audit_secrets.go`; `postgres/audit_sink.go` | Audit constructor runs migrations; Recorder subsequently appends audit events from startup as well as HTTP | Preserve original rows/hash pairs and canonical sequence; distinguish legitimate new events from original rows. Do not infer final row totals from HTTP counts |
| `serverbuildplatform/build_permissions_risk.go`; `postgres/permissions.go` | Permissions migrations include SoD and resource catalog; catalog `New` merely attaches operations | Preserve all original roles/assignments/menus/conflicts/active roles/resources and full own history |
| `build_app_selfservice.go`; `serverbuildauthn/build_authenticators_helpers.go`, `build_audit_secrets.go`; `postgres/password_credentials.go` | Credential constructor migrates; configured password seeds can persist hashes/users | Empty YAML seed lists do not suppress unrelated builtin bootstrap. Validate both independently |
| `build_app_oauth.go`; `serverbuildstore/build_oauth_stores.go`; `postgres/{auth_code,refresh_token,refresh_token_schema}.go` | OAuth constructors migrate, install lookup keys and call `StartReaper` | Separate constructor migration from reaper activation. Positive intervals can delete expired original rows; zero defaults certify neither enabled nor deployed cleanup |
| `infrastructure/postgres/migrate.go` | `Run` uses a transaction/advisory lock and `CREATE TABLE IF NOT EXISTS` for each version table; pending versions execute SQL/Func and append `applied_at` | A maximum-version check alone is insufficient. Preserve complete native schema and each own complete history; independent initializations have distinct timestamps |
| `interfaces/sso/sso.go::NewServer` | Applies configured sink taps/config-audit/federation/cache/session hub; startup feature-gate reporting may append audit events when gates are off | Classify each active option; default memory bookkeeping is not durable-state equivalence |
| `build_app_security.go::startGovernanceWorkers`; `platform/lifecycle/rotation/client_secret_scan.go` | When a client store exists, scanner starts regardless of rotation.enabled; first sweep is immediate, then every 6h | Read-only to clients is NOT read-only to audit. Eligible clients may append up to three warning events per scan, with local daily dedup; Redis claim-store wiring is separate |
| `main.go::run`; `build_bootstrap.go`; `platform/bootstrap/{bootstrap.go,file/file.go,builtin/builtin.go}` | Bootstrap runs by default (`Disabled` is false). New file tracker starts at version 0; seven builtin steps run/mark applied; subsequent boots skip recorded steps and still audit skips | Separate per-profile owned tracker paths, retained across that profile's restart; no shared off/on tracker, prefilled versions or invented provenance |

### Builtin bootstrap is not YAML seeding

The current seven steps are source-defined and ordered:

1. `seed_admin_role`: attempts to add `sso-admin` under empty client ID;
   an existing role returns `ErrRoleExists` rather than being overwritten.
2. `seed_admin_user`: reads default ID `admin`; if absent it creates a user and
   assigns the role, printing a generated password. Absence is an authority and
   secret-output decision, not permission to synthesize historical admin access.
3. `seed_default_netpolicy`: only when a network store exists and is empty.
4. `seed_admin_client`: creates `sso-admin` if not found.
5. `seed_admin_console_client`: creates public `sso-admin-console` if not found.
6. `clear_seeded_password`: removes an existing `seeded_password` attribute and
   writes the full user. That is a historical-row change even if security-motivated.
7. `enforce_admin_console_pkce`: rewrites an existing console client only when its
   PKCE bit is false and secret is empty. A confidential operator client is left
   alone. This exception does not justify changing a public historical client to
   make a preservation test pass.

The tracker writes temporary files and renames them; the Runner separately
records applied/skipped/failure audit events. Retain tracker bytes, ownership,
normal process exits and all database additions. A tracker is not one of the ten
native SQL migration histories. A file lock/rename is not global fencing or
cross-file/database atomicity. Never replay an uncertain completed seed step.

## Other branches still require complete inventory

[Post-build exit lifecycle](STOCK_STARTUP_LIFECYCLE.md) now gives `run` one
late-bound deferred teardown for partial listeners and existing workers on all
post-build exits. It does not undo startup writes, complete partial-build cleanup,
prove cooperative Close behavior or close the full effect inventory below.

The table above is NOT a claim of complete reachability. Before stock traffic,
resolve the exact config source chain/defaults/flags/environment and every active
constructor, optional store, background loop and shutdown flush, including:

- client/password seeds; tenant/membership/activation/quota reconciliation;
  connection/region/network policies and classifiers;
- OAuth device/PAR/CIBA stores, CIBA pruning/push, refresh-grace store cleanup
  (its own constructor default interval), consent/native SSO and login state;
- account lockout/replay, MFA/TOTP/WebAuthn, pairwise subjects, identity linking,
  self-service signup/reset/email-change/notifications, federation and SCIM;
- key/credential rotation, unconditional client-secret warnings, optional audit
  async/notary/fan-outs/retention, feature-gate/config-audit snapshots/drift/canary;
- token anomaly/usage, trust decay/continuous verification, conditional-access
  convergence, break glass, user lifecycle/auto-deprovision and degradation;
- service/signing-key registries, invalidation bus/reseed, snapshots/releases/DR,
  bootstrap restore and external files/transports. Inventory normal shutdown too.

Record inactive branch predicates and their *effective* values. Omitted options
are not proof that every default is false. A source/config/hash change invalidates
that observation. If any active edge or persistence is unknown, fail closed before
stock startup/traffic. Source review is owner evidence, not independent approval.

## Finite reusable checker

`startup_preservation.check_startup_preservation(facts)` opens no files, databases,
processes or transport. It accepts a plain dict with EXACTLY these fields:

- `version`: integer 1 (not Boolean).
- `revocation_rows`: exact integer within the existing source row cap; only 0 is
  currently admitted. Nonzero means separate retention policy required, not proof
  of corruption or that every row is already expired.
- Actual Boolean observations: `admin_role_present`, `admin_user_present`,
  `admin_seeded_password_present`, `admin_client_present`,
  `console_client_present`, `console_requires_pkce`, `console_has_secret`.

Presence requires the default IDs described above; a similar ID, editable alias
or client attribute is not evidence. The four presence facts must be true, the
seeded-password key absent, and console PKCE or a nonempty secret already present.
Do not log hashes, secrets, attribute bodies or raw historical rows to explain a
failure. Missing/unknown keys, NULL, coercible strings/numbers and malformed facts
reject; no fallback or default-zero success. Validation order is fields, version,
count shape, Boolean shape, revocation policy, missing bootstrap authority, rewrite.

A returned PASS means ONLY these supplied finite prerequisites matched. It says
`complete_startup_inventory_verified=false`, `stock_start_authorized=false`, and
`runtime_certified=false`. This helper cannot prove its input facts, their source
pins or freshness; the caller must obtain a complete bounded read-only native
observation and compare all originals/schema/own histories separately. This is not
a new CLI or implicit hook in `sso-server`; caller wiring and full startup admission
remain separate work. It cannot replace retention policy or engineering gates.

## Acceptance and delivery

`checks/test_migration_startup_preservation.py` covers exact field/type/order
rejection, populated revocations, missing builtin authority, both bootstrap rewrite
hazards, all three already-safe console cases, nonmutation and explicit nonauthority.
Native observation must use a new owned target, one protected import, full typed
content/schema/sequence verification and own complete metadata before/after reads.
Do not run stock merely to discover whether startup changes protected originals.

Run targeted tests, all engineering checks, build/vet/committed Go gates, full
`make ci`, product E2E and explicit owned-PG acceptance. No increased caps,
exemptions, skipped mandatory PG or weakened assertions. Report full inventory,
stock traffic and historical/production acceptance as unexecuted unless actually
established; a finite prerequisite PASS is not the missing full-runtime PASS.

See [historical stock runtime](HISTORICAL_STOCK_RUNTIME.md). Historical credentials,
admin/grants/external keys, real browsers/validators, enabled/deployed cleanup,
PG15/MySQL/Vault/HA/recovery/fencing, independent review and production approval
remain separate. No automatic commit/merge/push/deploy, live restart or SVERP HMR/
backend-watch/30-day-session policy change.
