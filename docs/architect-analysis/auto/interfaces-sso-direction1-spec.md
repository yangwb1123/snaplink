# Requirements Specification: interfaces/sso — Direction 1

SDK option surface vs stock-server configuration surface consistency gap.

Source: `docs/auto/interfaces-sso-analysis.md`, 方向一.
Module: `interfaces/sso` (option surface), `cmd/sso-server` (stock wiring),
`ops/build` + `ops/scripts` + `checks/` (tooling), `docs/config-reference.md`
+ `docs/feature-matrix.md` + `ops/build/capabilities.json` (contract docs).
Out of scope (separate directions): Postgres OAuth hot stores (方向二),
`interfaces/sso` file-budget slimming (方向三), and any change to the
`Option`/`Server` SPI shape.

Background facts established by inspection (all verified in current code):

- `interfaces/sso/options*.go` (7 files: `options.go`, `options_admin.go`,
  `options_grants.go`, `options_httpstack.go`, `options_misc.go`,
  `options_passwd.go`, `options_security.go`) declares **174 unique
  `func With*` option constructors** (`grep -hoE "^func With[A-Za-z0-9_]+" |
  sort -u | wc -l` = 174).
- `cmd/sso-server/` references **159 unique `sso.With*`** across 22 non-test
  files (`grep -rhoE "sso\.With[A-Za-z0-9_]+" | sort -u | wc -l` = 159);
  **48 declared options are never referenced by the stock binary**, including
  `WithIssuer`, `WithDataRetentionSweep`, `WithBackupDir`,
  `WithBackupRetention`, `WithBackupSource`, `WithTokenExchangePolicy`,
  `WithTenantUserStore`, `WithCAEPStreamStore`, `WithRebacStore`,
  `WithRebacEngine`.
- `docs/config-reference.md` has 42 `## ` sections and explicitly admits two
  boundaries: line 19 (`oauth.token_exchange.*`) "Option-wired, not
  YAML-driven — see `sso.WithTokenExchangePolicy`", and line 41 (`server.issuer`)
  "stamped into JWT `iss`, discovery `issuer`, every RFC 9207 `iss`".
- `docs/deferred-backlog.md` line 30 (Product-surface boundary): "An SDK
  option is not automatically a stock-binary YAML feature."
- `ops/build/capabilities.json` `config_keys` are hand-maintained literal
  arrays; `ops/scripts/capability_registry.py` validates only that the field
  is non-empty (`empty_fields`, line 228), never that a listed key exists in
  the config surface.
- The only automated surface loops that exist are route→OpenAPI
  (`checks/route_contract.py`, `cli.py check-routes`) and generated-SDK→
  contract (`ops/scripts/sdk_surface.py`, `ops/build/sdk-surface.json`,
  `cli.py sdk-surface check`). No machine-checkable option→config mapping
  exists anywhere.

Dependency order: 1 → 2, 1 → 3 (the registry and gate land first; the other
two consume it). Each improvement lands with the mandatory gates (`go build
./... && go vet ./...`, `go test -run 'TestMaintainability_|TestArchitecture_'
.`) and a `python cli.py`-reachable check.

## Decision 1: Option-surface registry with a machine gate (`options check`)

**Name**: option→config reachability registry and gate, modeled on
`sdk-surface check` / `check-routes`.

**Problem**: whether an implemented SDK capability is reachable by an operator
of the stock `sso-server` is an undocumented, manually maintained, and
unverifiable property. Today the only fact source is prose: 42
`config-reference.md` sections vs 174 SDK options, with `capabilities.json`
`config_keys` hand-edited and `feature-matrix.md` annotated by hand. The
48-option unreachable set (verified above) includes shipped, tested features,
so "SDK-only" is currently an accident of wiring, not a decision.

**Evidence**:
- `interfaces/sso/options*.go` — 174 unique `func With*` declarations.
- `cmd/sso-server/build_app_*.go`, `build_stores.go`,
  `cmd/sso-server/serverbuildplatform/*.go` — 159 unique `sso.With*`
  references; 48 declared options with zero references (e.g.
  `options_grants.go:191 WithTokenExchangePolicy`,
  `server_backup.go:179 WithDataRetentionSweep`,
  `options_admin.go:52/62 WithBackupDir/WithBackupRetention`,
  `options.go:348 WithIssuer`).
- `docs/config-reference.md` — 42 sections; line 19 and 41 document the
  boundary in prose only.
- `docs/deferred-backlog.md:30` — "An SDK option is not automatically a
  stock-binary YAML feature."
- Precedent: `ops/scripts/sdk_surface.py` + `ops/build/sdk-surface.json` +
  `ops/build/sdk-surface.schema.json`; `checks/route_contract.py`.

**Proposed behavior**:
1. Add `ops/build/option-surface.json` (+ `option-surface.schema.json`), one
   entry per declared `With*` option, classified exactly one of:
   - `config` — reachable via YAML, with the `config_keys` it maps to (each
     key must exist in `docs/config-reference.md` and in the generated config
     schema, `config/schema` reflection over `config.Config` yaml tags);
   - `wired` — stock-wired via Go (`cmd/sso-server`), intentionally without
     YAML, with a one-line rationale;
   - `sdk-only` — explicit decision record that the option is embedder-only,
     with a one-line rationale (no silent default).
2. Add `checks/option_surface.py`: compile the declared set from
   `interfaces/sso/options*.go`, the referenced set from `cmd/sso-server`,
   require every declared option to have a registry entry, require every
   `config` entry's keys to exist in the config surface, and require the
   registry's `wired`/`config` sets to match the compiled reference set
   (no undocumented wiring, no phantom entries).
3. Wire `python cli.py options check` into `cli.py`'s command table, add a
   `make options-check` target, and register the check in
   `docs/agent-os/CHECKS_REGISTRY.md` and `make ci` (same slot as
   `sdk-surface check`).
4. Do not fix the 48 gaps in this decision; first make the inventory
   explicit and the classification a reviewed decision.

**Acceptance check**:
- `python cli.py options check` exits 0 and prints
  `declared=174 wired=159 config=N sdk-only=M` with no unclassified options.
- Deleting one registry entry (or wiring a new `sso.With*` in
  `cmd/sso-server` without registering it) makes the check fail with a
  diff-locating message.
- `make ci` runs the check; `docs/agent-os/CHECKS_REGISTRY.md` lists it.

## Decision 2: Close the two verified reachability defects (issuer drift, retention/backup family)

**Name**: wire the documented-but-unreachable YAML capabilities into the
stock binary.

**Problem**: two concrete, verified defects make documented YAML keys either
wrong or dead in stock deployments:
(a) `server.issuer` (documented to stamp JWT `iss`, discovery `issuer`, and
every RFC 9207 `iss`) is never applied to the SDK's `s.issuer` field, so
discovery and authorization responses fall back to the request base URL while
JWT `iss` comes from `cfg.Server.Issuer` — the two can disagree, breaking
RFC 9207 mix-up detection for clients in exactly the "public URL issuer,
internal host" topology the code comment describes.
(b) The compliance retention sweep and backup family
(`WithDataRetentionSweep` + `WithBackupDir/WithBackupRetention/
WithBackupSource`, incl. the `/admin/compliance/retention-sweep` route) are
implemented and tested but have zero YAML path; `audit.retention.*` and
`snapshot.retention.*` cover other sweepers only.

**Evidence**:
- `config/config_server.go:17` — `Issuer string yaml:"issuer"`; `docs/
  config-reference.md:41` documents the full stamping contract.
- `interfaces/sso/options.go:348-349` — `WithIssuer` sets `s.issuer`; it is
  the only writer (`sso.go:67` defaults to `DefaultIssuer`);
  `interfaces/sso/server_discovery.go:251 resolveIssuer` returns
  `s.issuer` only when set, else `requestBaseURL(ctx.Request())`.
- `cmd/sso-server/` — zero `sso.WithIssuer` references (grep verified);
  `cmd/sso-server/build_app_core.go:139` passes `cfg.Server` to
  `serverbuildsign.BuildSigningIssuer` (JWT side only).
- `interfaces/sso/server_backup.go:170-179` — `WithDataRetentionSweep` +
  `PathAdminComplianceRetentionSweep` (`server_backup.go:167`); zero stock
  references (grep verified); `options_admin.go:52/62`,
  `options_httpstack.go:198` same for the backup family.
- Admission of the class of bug: `cmd/sso-server/serverbuildplatform/
  build_governance.go:229` logs at runtime "the stock sso-server does not
  wire it" for `sso.WithTenantUserStore`, i.e. a YAML-configured feature
  (`token_policies` subject-role selectors) that can never match in stock.

**Proposed behavior**:
1. In `cmd/sso-server` wiring, apply `sso.WithIssuer(cfg.Server.Issuer)` when
   it differs from `DefaultIssuer`, restoring the documented
   JWT/discovery/RFC 9207 agreement; add an e2e assertion that discovery
   `issuer` equals the YAML issuer and the JWT `iss` for the same request.
2. Add YAML keys for the retention sweep (`retention.compliance.*`, matching
   the `compliance.RetentionConfig` shape) and backup
   (`backup.{dir,keep,source.*}`); wire them in `cmd/sso-server` via
   `WithDataRetentionSweep` and the `WithBackup*` family, including the
   `RunDataRetentionSweep` goroutine discipline documented at
   `server_backup.go:176`.
3. Update `docs/config-reference.md` (new sections/rows), the
   `config_keys` of the affected `ops/build/capabilities.json` entries, and
   the `feature-matrix.md` rows from `sdk` to `sdk`+`stock-binary`.
4. Reclassify `WithTenantUserStore` (or the `token_policies` subject-role
   selector) as either wired or explicitly `sdk-only` with the
   `build_governance.go:229` warning removed/kept to match the decision —
   no silent half-state.

**Acceptance check**:
- New `test/` e2e (package `ssotest`): stock server with
  `server.issuer: https://public.example.com` and an internal reach host
  returns discovery `issuer` = JWT `iss` = the YAML issuer, and an RFC 9207
  `iss` parameter equal to the discovery issuer on the authorization error
  path.
- E2e: YAML `retention.compliance.enabled: true` runs the sweep (assert
  audit-report-only counts and session-TTL cleanup behavior) and
  `backup.*` triggers the retention prune.
- `python cli.py options check` classifies all of the above as `config`, and
  `capabilities check` passes with the new `config_keys`.
- `go test ./... -race` and `make ci` green.

## Decision 3: `capabilities.json` `config_keys` becomes a verified fact source (feature-matrix lockstep)

**Name**: machine-verified capability→config mapping; feature-matrix
`sdk`/`stock-binary` columns derived from it.

**Problem**: `ops/build/capabilities.json` `config_keys` is the closest
existing thing to an option→config fact source, but it is hand-maintained and
validated only for non-emptiness. Nothing verifies that a listed key exists
in the config surface, that a `stock-binary`-available capability has at
least one reachable config key, or that `feature-matrix.md`'s
`sdk`/`stock-binary` annotations agree with the registry. The gap between
"capability is stock-wired" and "capability is YAML-reachable" is therefore
invisible to every existing gate.

**Evidence**:
- `ops/build/capabilities.json` — 28 `capabilities` entries; literal
  `config_keys` arrays (e.g. `["feature_gates.admin_api","admin"]` for
  `admin.control-plane`, `[]` for `api.docs-viewer`).
- `ops/scripts/capability_registry.py:228` — `empty_fields` check only;
  no key-existence or availability-coverage validation.
- `docs/feature-matrix.md:6-10` — "An `interfaces/sso` `With*` option is an
  **SDK** capability. A `config.yaml` key is a **stock `sso-server`**
  capability." — prose definitions with hand-annotated rows.
- Precedent: `cli.py sdk-surface check` already derives and validates the
  generated-SDK surface against OpenAPI + capabilities
  (`ops/scripts/sdk_surface.py`).

**Proposed behavior**:
1. Extend `capability_registry.py` validation (`cli.py capabilities check`):
   - every `config_keys` entry must exist in `docs/config-reference.md` and
     in the generated config schema (via `sso-ctl config schema` or the
     `config.Config` yaml-tag reflection);
   - every capability whose `availability` includes `stock-binary` must have
     ≥1 `config_keys` entry or an explicit `sdk_only_reason` field;
   - every capability whose `availability` is `sdk`-only must not list
     `config_keys` (must use `sdk_only_reason`).
2. Add a generator (same pattern as `capabilities generate`,
   `Makefile:124`) that emits the `feature-matrix.md` availability columns
   from the registry, so the hand-annotated table is replaced by a derived
   one; the doc-validate target (`Makefile:178`) runs it in diff mode.
3. Reconcile the 48 SDK-only options (Decision 1 registry) with capability
   entries: each option maps to a capability row or to a new
   `sdk-only`-classified row, so no option is left outside the
   capability→config lattice.

**Acceptance check**:
- `python cli.py capabilities check` fails when a planted `config_keys`
  value is not a real config key, when a `stock-binary` capability has no
  reachable config key, and when an `sdk`-only capability lists
  `config_keys`.
- `make docs-validate` fails on any diff between `feature-matrix.md` and the
  generated availability columns; `make capabilities-generate` converges.
- `feature-matrix.md` rows for the Decision 2 changes move from `sdk` to
  `sdk`+`stock-binary` without manual editing.
- All 174 options from Decision 1 appear in exactly one capability row.

---

**Handoff gate**: `make ci` (includes the new `options check` and the
extended `capabilities check`); `go test ./... -race`; e2e additions under
`test/` run with `go test ./test/ -run TestE2E -v`. Pre-existing gate
failures, if any, are reported separately.
