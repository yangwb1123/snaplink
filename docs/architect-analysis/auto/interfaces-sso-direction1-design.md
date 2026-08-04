# Design: interfaces/sso — Direction 1

Option-surface reachability registry, the two stock-wiring defects, and a
verified capability→config fact source.

Companion to [`interfaces-sso-direction1-spec.md`](interfaces-sso-direction1-spec.md).
Dependency order: Decision 1 → Decision 2, Decision 1 → Decision 3. Each
decision lands with the mandatory gates and a `python cli.py`-reachable check.

## 0. Verified baseline (re-measured for this design)

All counts re-verified against current code; the spec's headline numbers are
correct but scoped to `options*.go`, which matters for the registry design:

| Measurement | Count | Scope / method |
|---|---|---|
| Unique `func With*` declarations | **223** | All non-test `interfaces/sso/*.go` (`^func With[A-Za-z0-9_]+`) |
| …of which in the 7 `options*.go` files | 174 | Same, `options*.go` glob — the spec's "174" |
| `sso.With*` textual mentions, raw grep incl. `cmd/sso-server` test files | 159 | the spec's "159" — includes `_test.go` matches |
| …raw grep, non-test files only | 155 | `cmd/sso-server` + `serverbuild*` subpackages |
| …**comment/string-stripped, non-test** (the true wired set) | **153** | tokenizer removes comments and string/raw literals before matching |
| Phantom mentions (appear only in comments/strings, never called) | 2 | `WithTenantUserStore` in the `slog.Warn` text at `build_governance.go:229`; `WithTrustedDeviceStore` in a comment at `build_spiffe_caep.go:121` |
| Declared in `options*.go`, zero call sites (stripped) | 53 | includes `WithIssuer`, `WithBackupDir/Retention/Source`, `WithTokenExchangePolicy`, `WithCAEPStreamStore`, `WithRebacStore/Engine`, `WithTenantUserStore` (the spec's "48" was the raw-with-tests variant) |
| Declared anywhere in `interfaces/sso`, zero call sites (stripped) | **70** | full-package unreachable set = 53 in `options*.go` + 17 declared outside it (`WithDataRetentionSweep` in `server_backup.go:179`, `WithAPIDocsUI`, `WithAuthHook`, `WithPasswordPolicy`, `WithTokenExchangeChainStore`, …) |

Two consequences the design must absorb:

1. **The registry scope is the full 223-option package surface, not the 174
   `options*.go` subset.** The spec names `WithDataRetentionSweep` as a
   required registry subject, but it is declared in `server_backup.go`, i.e.
   outside the 174. A registry keyed to `options*.go` alone would omit the
   very option Decision 2 wires. The acceptance line `declared=174` is
   therefore reported as a sub-count; the gate's primary number is 223.
2. **Reference compilation must strip comments and string literals.** The
   naive grep counts `WithTenantUserStore` and `WithTrustedDeviceStore` as
   wired (they appear only in the `build_governance.go:229` warning text and
   a `build_spiffe_caep.go:121` comment). The registry must not bless a
   phantom wiring; Decision 2.4's reclassification of `WithTenantUserStore`
   depends on the honest count. Every non-test file in `cmd/sso-server`
   imports `interfaces/sso` under the canonical `sso` alias (verified across
   all 31 import sites), so alias resolution is a cheap per-file guard, not
   a liability.

Other verified facts the design relies on:

- `sso.NewServer(b.opts...)` at `cmd/sso-server/build_app.go:258`; the option
  slice is accumulated in `appBuilder` methods across `build_app_*.go`.
  `cmd/sso-minimal/app.go:79` already wires `sso.WithIssuer(cfg.Issuer)` —
  the stock binary is the outlier, not the SDK.
- JWT `iss` is stamped by `serverbuildsign.BuildSigningIssuer` from
  `cfg.Server.Issuer` (`build_signing_issuers.go:43`), while
  `sso.resolveIssuer` (`server_discovery.go:251`) only honors `s.issuer`
  (set by `WithIssuer`, never called in stock) and otherwise falls back to
  `requestBaseURL`. `sso.go:67` seeds `s.issuer = DefaultIssuer`; both
  `resolveIssuer` and `server_discovery_config.go:264` treat `""` and
  `DefaultIssuer` as "unset".
- `config.Backup` (`config/config_snapshot.go:180`) and the `backup.dir` /
  `backup.keep` rows in `docs/config-reference.md` already exist, are
  validated at boot (`config_load.go:188`), and are **never consumed** —
  zero references to `cfg.Backup` in `cmd/`. The admin backup endpoint
  (`server_backup.go:85`) iterates `s.backupSources`, which stock never
  populates. `test/admin_backup_test.go` proves the SDK path works when an
  embedder wires the options.
- The retention sweep route mounts only when `s.dataRetention.Enabled`
  (`server_backup.go:214-215`); `RunDataRetentionSweep` no-ops unless
  enabled and `interval > 0` (`server_backup.go:250`). `compliance.RetentionConfig`
  (`protocols/compliance/retention.go:26`) has a `Now` clock override for
  tests (`retention.go:93`), but the server-level `RunDataRetentionSweep`
  takes only `(ctx, interval)`.
- The feature-matrix availability table **is already generated** from
  `capabilities.json` (`capability_registry.py` `render_generated_section`,
  BEGIN/END markers in `docs/feature-matrix.md`), and `docs-validate`
  already runs `capabilities check` in diff mode. Decision 3's "add a
  generator" is therefore mostly satisfied; the real new work is the
  key-existence and availability-coverage validation plus the
  option→capability lattice (see Decision 3).
- `defaultimpl.NewMemoryTenantUserStore()` exists (used in
  `interfaces/sso` tests), so a stock wiring of `WithTenantUserStore` is
  technically possible but would be memory-only (process-local, lost on
  restart) — relevant to the Decision 2.4 reclassification.
- `sso-ctl config schema --out <file>` (`cmd/sso-ctl/configcmd/schema.go`)
  emits a JSON schema by reflection over `config.Config` yaml tags
  (`config/schema` package, no dependency on `config`). No committed
  artifact of it exists today, and it is not wired into any Make target.

---

## Decision 1: Option-surface registry with a machine gate (`options check`)

### API surface

New, mirroring the `sdk-surface check` / `check-routes` precedent:

- **`ops/build/option-surface.json`** — the registry: one entry per declared
  `With*` option, classified exactly one of:
  - `config` — reachable via YAML; `config_keys[]` lists the dotted keys it
    maps to (each must exist in the generated config schema **and** in
    `docs/config-reference.md`), plus a one-line `rationale`.
  - `wired` — stock-wired via Go in `cmd/sso-server`, intentionally without
    YAML; `rationale` required (e.g. `WithLogger`).
  - `sdk-only` — explicit embedder-only decision; `rationale` required.
  - `unclassified` — bootstrap-only state produced by `options generate`;
    `options check` fails on any unclassified entry. There is no silent
    default: the 70 currently-unreachable options must each receive a
    reviewed classification, not an automatic one.
  - Optional `capability` field: the `capabilities.json` capability id this
    option belongs to (Decision 3 consumes it; Decision 1 accepts null).
- **`ops/build/option-surface.schema.json`** — strict JSON Schema
  (draft 2020-12, `additionalProperties: false`, `schema_version: 1`),
  modeled on `sdk-surface.schema.json`.
- **`checks/option_surface.py`** — the gate, in `checks/` like
  `route_contract.py`, with unit tests `checks/test_option_surface.py`
  (precedent: `checks/test_route_contract.py`). Responsibilities:
  1. **Compile declared set**: `^func (With\w+)` over non-test
     `interfaces/sso/*.go` (all 223; the 174 `options*.go` sub-count is
     reported).
  2. **Compile referenced set**: `sso.WithX` selectors over non-test
     `cmd/sso-server/**/*.go` after stripping comments and string/raw
     literals (a small tokenizer, same house style as
     `capability_registry.py`'s regex-over-Go-source). Import-alias aware:
     resolve the per-file import alias for
     `github.com/yangwb1123/snaplink/interfaces/sso` so a future alias
     rename does not silently widen the wired set.
  3. **Completeness**: every declared option has exactly one registry entry;
     no registry entry names an undeclared option (no phantom entries).
  4. **Wiring agreement**: the registry's `config` + `wired` sets equal the
     compiled referenced set — a new `sso.With*` call in `cmd/sso-server`
     without a registry update fails with a diff-locating message, and a
     registry entry claiming wiring that the code does not contain fails
     too.
  5. **Config-key existence**: every `config` entry's `config_keys` entries
     exist in the generated config schema (Decision 1 depends on the
     `config-keys` artifact defined under Storage model) and in
     `docs/config-reference.md`'s key table.
  6. **Classification hygiene**: `config` ⇒ ≥1 key; `sdk-only`/`wired` ⇒ no
     keys; all non-`unclassified` entries have a non-empty `rationale`.
- **CLI/Make wiring**: `cli.py options check|list|generate` (same shape as
  `capabilities`), `make options-check`, a row in
  `docs/agent-os/CHECKS_REGISTRY.md` (both tables), and `make ci` directly
  after `sdk-surface-check`.

### Storage model

`option-surface.json` shape (schema_version 1):

```json
{
  "$schema": "./option-surface.schema.json",
  "schema_version": 1,
  "classes": ["config", "wired", "sdk-only", "unclassified"],
  "scope_note": "All func With* declared in interfaces/sso (non-test); options*.go subset is 174/223 today.",
  "options": [
    {
      "name": "WithIssuer",
      "declared_in": "interfaces/sso/options.go",
      "classification": "config",
      "config_keys": ["server.issuer"],
      "capability": "oidc.core",
      "rationale": "server.issuer stamps JWT iss, discovery, RFC 9207"
    }
  ]
}
```

`declared_in` is mechanical (first matching file) and diffable. Ordering:
sorted by name; the check rejects duplicates and unsorted entries.

**Config-key existence fact source.** Rather than shelling `go run
./cmd/sso-ctl config schema` inside every gate invocation, commit a derived
artifact:

- **`ops/build/config-keys.json`** — flat, sorted dotted key list produced
  by `cli.py config-keys generate`, which runs
  `go run ./cmd/sso-ctl config schema --out <tmp>` and flattens the
  `properties` tree to dotted paths (`a.b.c`; array items normalize to
  `a.b[]` and the bare `a.b` also counts as existing — the registry's
  `audit.webhook.subscriptions[].name`-style keys resolve to the array
  element schema).
- The generator is drift-checked inside both `options check` and
  `capabilities check` (regenerate into a temp buffer, diff against the
  committed file, fail with "run `python cli.py config-keys generate`").
- `docs/config-reference.md` key parsing: collect `| \`key\` |` table rows
  from `## ` sections; normalize brace-shorthand rows
  (`security.rar_limits.{max_bytes,max_elements}` → three literal keys).
  The schema is the authority; the reference-doc check catches doc drift and
  is allowed to be the binding constraint when it is stricter.

**Bootstrap**: `options generate` emits the full 223-entry inventory with
`classification: unclassified` and empty rationales; `options check` then
fails until a human reviews each entry. This makes the 70-option unreachable
set a visible, reviewed decision instead of an accident of wiring — the
point of the decision. Generation is idempotent: existing classifications
are preserved (merge by option name).

### Failure modes

| Mode | Effect | Mitigation |
|---|---|---|
| New `With*` option added without registry entry | `options check` fails; the diff message names the option and its file | `options generate` re-seeds as `unclassified`; the check failure is the intended friction |
| New wiring added in `cmd/sso-server` without registry update | Fails ("undocumented wiring") | Message shows the exact `sso.WithX` call site |
| Comment/string mentions counted as wiring (`WithTenantUserStore` in a `slog.Warn` string, `WithTrustedDeviceStore` in a comment — both today) | Registry blesses a phantom; Decision 2.4 half-state | Comment/literal stripping in the reference compiler; unit tests pin both known cases |
| Option referenced through a non-canonical import alias | Wired set undercounts → false failure | Per-file alias resolution; test with an aliased import |
| Option renamed or moved between files | Declared set changes; old registry entry becomes phantom | Phantom-entry check; rename = one-line registry update |
| `cmd/sso-minimal` wiring | Out of scope — it is a separate binary with its own surface | Reference compiler scoped to `cmd/sso-server` only; `scope_note` documents it |
| Config key renamed in `config/*.go` | `config-keys generate` diff fails | The committed artifact makes the drift explicit, not silent |
| Check runtime | `go run` per invocation would be slow in the dev loop | Checks read the committed `config-keys.json`; only `generate` shells Go |

### What could break the design

- **Scope disagreement (174 vs 223).** The spec's acceptance line says
  `declared=174`; the registry needs 223 to cover `WithDataRetentionSweep`
  and the other 17 non-`options*.go` options. If a reviewer insists on the
  literal 174, Decision 2's own target option escapes the registry and the
  gate validates a fiction. The check prints both numbers and the
  acceptance criterion is met when `declared=223 (options*.go subset 174)`.
- **Classification churn on first landing.** 223 entries, 70 of them
  unreachable, each needing a one-line rationale — a large review surface.
  Mitigated by `options generate` + one-entry-per-line diffs; the rationale
  requirement is deliberately minimal ("embedder-only: server has no YAML
  for X").
- **The gate becomes a tax, not a tool.** Every new SDK option now has a
  two-line cost (registry entry + classification). If it is felt as pure
  friction, teams will start routing options through bundles or aliases to
  dodge the gate — which the wiring-agreement check then catches, but only
  if the alias-resolution logic stays honest. Keep the reference compiler
  simple and visible.
- **Comment-stripper false negatives.** A future string literal containing
  `sso.WithX` (e.g. a log message) is stripped and ignored — safe direction
  (undercount → false failure, never phantom wiring). Acceptable.
- **`config-keys.json` staleness.** If generation is not wired into a
  frequent target, the artifact drifts and both gates fail confusingly.
  Mitigation: regenerate inside `capabilities generate` and
  `docs-validate`, so the normal doc-flow converges it.

---

## Decision 2: Close the two verified reachability defects

### API surface

**2a. Issuer drift (`server.issuer`).** Append
`sso.WithIssuer(cfg.Server.Issuer)` to `b.opts` in
`cmd/sso-server/build_app_core.go` (in `wireIdentitySigning`/
`wireSigningIssuer`, next to the `serverbuildsign.BuildSigningIssuer` call —
`cfg.Server` is already in scope there). Unconditional append is safe and
matches `cmd/sso-minimal/app.go:79`: `WithIssuer("")` leaves `s.issuer`
unset, which `resolveIssuer` and `server_discovery_config.go:264` already
treat as "fall back to request base URL", and `WithIssuer(DefaultIssuer)` is
likewise a no-op via the sentinel checks. Effect: with `server.issuer` set,
discovery `issuer`, RFC 9207 `iss`, and JWT `iss` all agree on the YAML
value; with it unset, behavior is byte-identical to today.

**2b. Retention sweep.** New config block `retention.compliance.*` in
`config/` (a new `config_compliance.go`; `config.Config` gains
`ComplianceRetention ComplianceRetentionConfig \`yaml:"compliance_retention"\``
or — matching the spec's naming — a `retention` section holding
`compliance`):

| YAML key | RetentionConfig field / wiring |
|---|---|
| `retention.compliance.enabled` | `Enabled` (gate; route + goroutine only when true) |
| `retention.compliance.interval` | `RunDataRetentionSweep(ctx, interval)` cadence; must be `> 0` when `enabled` (boot fail-loud, same style as `config_load.go` validators) |
| `retention.compliance.session_ttl_sweep` | `SessionTTLSweep` |
| `retention.compliance.dormant_after` | `DormantAfter` (duration) |
| `retention.compliance.auto_erase_dormant` | `AutoEraseDormant` |
| `retention.compliance.audit_report_max_age` | `AuditReportMaxAge` (duration) |
| `retention.compliance.dry_run` | `DryRun` |
| `retention.compliance.max_per_sweep` | `MaxPerSweep` |

Wiring: in `cmd/sso-server`, `sso.WithDataRetentionSweep(cfg.Retention...)`
mapped field-by-field (no config→struct type reuse across package
boundaries), and a goroutine following the existing `startBreakGlassSweeper`
pattern (`build_app_security.go:467-480`): `ctx` from the app lifecycle,
`done` channel, `defer close(done)`, cancel registered on the builder so
shutdown is deterministic. The route
`POST /admin/compliance/retention-sweep` mounts automatically once
`Enabled` is true (`server_backup.go:214`).

**2c. Backup family.** Wire the already-parsed, already-documented keys:

- `backup.dir` → `sso.WithBackupDir(cfg.Backup.Dir)`;
- `backup.keep` → `sso.WithBackupRetention(cfg.Backup.Keep)`;
- **new** `backup.sources[]` (list of SQLite file paths) → one
  `sso.WithBackupSource(...)` per entry, wrapping the path in a
  `core.BackupSource` adapter that opens the SQLite DB and runs
  `VACUUM INTO` (exactly the `test/admin_backup_test.go` adapter shape —
  that test becomes the reference implementation to lift into
  `cmd/sso-server/serverbuildstore` or `infrastructure/defaultimpl/sqlite`).

`backup.dir`/`backup.keep` rows already exist in `docs/config-reference.md`
(lines 538/554) and `config_keys` of the affected capabilities must be
updated; the new `backup.sources` row is added to the Backup section. No
name collision with `snapshot.retention.*` / `dr.*` — separate namespaces,
separate sweepers.

**2d. `WithTenantUserStore` reclassification.** `defaultimpl.NewMemoryTenantUserStore()`
exists, but a memory store is process-local and restarts reset role
membership — wiring it would make `token_policies` subject-role selectors
"work" in a single process and silently lose state on restart, which is
worse than the current honest fail-open. **Decision: classify
`WithTenantUserStore` as `sdk-only`** (rationale: role resolution needs a
durable tenant-user store; stock has none; `token_policies` role selectors
remain a documented no-op), **keep** the `build_governance.go:229` boot
warning (it now matches the registry, and the registry is the reviewed
record), and add one sentence to `docs/config-reference.md`'s Token Policies
section stating the stock limitation. No code path changes for this option.

### Storage model

- `config.Config` gains the retention block; `BackupConfig` gains
  `Sources []string \`yaml:"sources"\``. Boot validation additions:
  `retention.compliance.interval > 0` when enabled; `max_per_sweep >= 0`;
  `backup.sources[]` entries must be non-empty paths (existence checked at
  backup time, not boot — a path may be a later mount).
- `ops/build/option-surface.json`: `WithIssuer`, `WithDataRetentionSweep`,
  `WithBackupDir`, `WithBackupRetention`, `WithBackupSource` move from
  `unclassified` → `config` with their `config_keys`; `WithTenantUserStore`
  → `sdk-only` with rationale. `options check` proves the two sets agree
  with the new `cmd/sso-server` wiring.
- `ops/build/capabilities.json`: `config_keys` gains the new keys on the
  affected capabilities (audit/compliance row, backup row if a capability
  exists, else a capability update); `feature-matrix.md` rows re-derive via
  the existing generator (Decision 3 makes this diff-gated).
- `docs/config-reference.md`: new `retention.compliance.*` section rows and
  the `backup.sources` row; the `server.issuer` row text is unchanged (the
  code finally matches the documented contract).

### Failure modes

| Mode | Effect | Mitigation |
|---|---|---|
| Wiring `WithIssuer` changes discovery for deployments that set `server.issuer` and previously got request-base-URL discovery | Behavioral change — but toward the documented contract; RFC 9207 clients that relied on the buggy mix-up are the only breakage | Config-reference already documents the contract; e2e pins the new agreement; release note |
| `server.issuer` set to `DefaultIssuer` value | No-op by sentinel design; no behavior change | Existing `cmd/sso-server/issuer_test.go` guards the default is non-sentinel; keep |
| Sweep goroutine leak or double-start on reload | Two sweepers racing destructive steps | `startBreakGlassSweeper` pattern with ctx + done; single start site; `RunDataRetentionSweep` already no-ops on `interval <= 0` |
| `max_per_sweep: 0` (unlimited) with destructive steps enabled | Unbounded destructive sweep storm | Boot warning when enabled with `max_per_sweep == 0` and any destructive step; document (0 = unlimited is the SDK contract) |
| `auto_erase_dormant: true` without self-service Eraser wired | Step silently skipped | The SDK already reports `Skipped`; stock boots a warning if the key is set while erasure is unwired |
| `backup.sources[]` path invalid / not SQLite | Backup endpoint errors per source | Documented; the endpoint already reports per-source results; e2e covers the happy path only |
| Retention e2e timing flakiness | CI flakes | `compliance.RetentionSweeper` has a `Now` override but `RunDataRetentionSweep` does not expose a clock — e2e uses tiny windows (e.g. `dormant_after: 1ms`) and polls the sweep route; if flaky, thread a clock through the server's sweeper assembly as a follow-up (note: keep out of scope unless the e2e proves flaky) |

### What could break the design

- **The runtime warning becomes a lie.** If 2d lands as "wire it", the
  `build_governance.go:229` warning must be deleted and role rules must
  actually resolve — a memory store would half-satisfy this and regress
  fail-open honesty. The design chooses `sdk-only` + keep-warning for
  exactly this reason; the registry entry is the reviewed record that makes
  the warning a contract, not an admission.
- **`server.issuer` empty-path divergence.** With `server.issuer` unset, JWT
  `iss` comes from `defaultimpl`'s own fallback while discovery uses
  `requestBaseURL`. If those two fallbacks ever disagree, the mix-up risk
  reappears on the *default* path. Verification item for implementation:
  confirm `defaultimpl.WithEd25519Issuer("")` issues with the request base
  URL; if not, either wire `WithIssuer` from `requestBaseURL`-equivalent
  state or document the residual. The e2e asserts the set case; a unit
  assert on the unset case is cheap and should be added.
- **Config validation ordering.** `retention.compliance.interval <= 0` with
  `enabled: true` must fail boot before any goroutine starts; adding a
  validator must not disturb the existing `--validate-only` path.
- **e2e scope creep.** The two new e2e tests (issuer agreement; retention +
  backup wiring) live in `test/` (package `ssotest`) and run under
  `go test ./test/ -run TestE2E`. They must not require network, external
  stores, or a second replica; the backup e2e reuses the real-SQLite
  `VACUUM INTO` adapter already proven in `admin_backup_test.go`.
- **Capability row availability.** `retention.compliance.*` spans audit +
  session + account-lifecycle concerns; the registry must map it to exactly
  one capability row (or a new one) or the Decision 3 lattice check fails.
  Propose the `identity.self-service` / a new `compliance.retention`
  capability; decide during implementation against the 28 existing rows.

---

## Decision 3: `capabilities.json` `config_keys` becomes a verified fact source

### API surface

Extends the existing `capability_registry.py` (no new command; `cli.py
capabilities check` becomes stricter):

1. **Key existence.** Every `config_keys` entry must exist in
   `ops/build/config-keys.json` (the Decision 1 artifact) **and** in the
   parsed `docs/config-reference.md` key set. Removes the "hand-maintained
   literal arrays" gap (`empty_fields` at `capability_registry.py:228` stays
   but is no longer the only guard).
2. **Availability coverage.**
   - `availability` includes `stock-binary` ⇒ ≥1 `config_keys` entry **or**
     a new `sdk_only_reason` field (explicit carve-out for
     stock-wired-but-configless capabilities, e.g. probes).
   - `availability` is `sdk`-only (no `stock-binary`) ⇒ `config_keys` must
     be empty and `sdk_only_reason` must be present. Today `api.docs-viewer`
     (sdk-only, `[]`) is the only entry this bites; it gains a one-line
     reason. `external-frontend` and `module-only` entries are exempt (their
     invariants are already enforced by `_validate_external`).
   - `capability.schema.json` gains `sdk_only_reason` (string) and
     `options` (array of option names) fields.
3. **Option→capability lattice.** Each capability gains an `options[]`
   array; the union across all capabilities must equal the 223 declared
   options exactly (no duplicates, no strays). `capabilities check` reads
   `ops/build/option-surface.json` (Decision 1) — the two registries
   cross-validate: an option's `capability` field must match the capability
   whose `options[]` lists it. Options that fit no product row land in new
   `sdk`-only capability rows (e.g. `sdk.embedding` for `WithLogger`,
   `WithRouter`, `WithMetrics`-style plumbing) — the spec's "maps to a
   capability row or to a new sdk-only-classified row".
4. **Generated feature matrix.** The existing marker-based generator
   (`render_generated_section`) stays; extend the generated table with a
   `Config key(s)` column derived from `config_keys` so the "stock-binary
   means YAML-reachable" property is visible in the doc, and add the
   option-coverage count to the generated section header
   (`223/223 options mapped`). `docs-validate` already runs
   `capabilities check` in diff mode — unchanged wiring, now stricter
   content. The hand-annotated protocol spec table (the "Opt-in" column)
   stays manual; the lattice gives it a machine-checkable substrate, but
   deriving per-protocol-row columns is out of scope.

### Storage model

- `capabilities.json` entries gain `sdk_only_reason` and `options[]`;
  `config_keys` keeps its current dotted-path convention. `schema_version`
  stays 1 (additive, validated fields; the schema file is updated with the
  two new properties).
- `config-keys.json` (from Decision 1) is the single flattened key fact
  source; the capability check consumes it read-only. Dotted-path rules:
  `a.b.c` must resolve through the schema `properties` chain; array items
  (`audit.webhook.subscriptions[].name`) resolve against the `items`
  schema; inline structs (`keys.introspection_signing` embeds
  `SigningConfig`) must resolve through the reflection output — verify
  `config/schema` handles `yaml:",inline"` before relying on it (it is the
  one place this design touches reflection semantics).
- `feature-matrix.md`: generated region only; the profile table and the
  protocol spec table remain hand-maintained (unchanged).

### Failure modes

| Mode | Effect | Mitigation |
|---|---|---|
| `config_keys` typo (`feature_gates.admin_api` vs `admin_api`) | Fails with the exact missing key | Key-existence check against `config-keys.json`; message shows the schema path |
| Config key deleted from `config/*.go` | `config-keys` diff fails first | Regeneration in `docs-validate`/`capabilities generate` converges the artifact; failure message is actionable |
| Capability marked `stock-binary` with `[]` keys and no reason | Fails | Coverage rule; existing rows audited once at landing |
| `sdk`-only capability lists keys | Fails | Rule 2; `api.docs-viewer` fixed at landing |
| Option listed in two capabilities | Duplicate → fails | Lattice uniqueness check |
| Option listed in no capability | Coverage gap → fails | Lattice totals check; new `sdk`-only rows absorb plumbing options |
| `config-reference.md` prose key missed by the table parser | Doc side under-counts (schema side still binds) | Normalization for brace-shorthand rows; the schema is the authority, so a doc omission fails only when the doc check is stricter — acceptable, and it is the intended doc-drift signal |
| Inline yaml structs in schema reflection | `config-keys` artifact wrong → mass false failures | Verify `config/schema` inline handling at implementation start; if unsupported, `config-keys generate` flattens from `config/*.go` yaml tags instead and the schema remains a secondary source |
| New capability row added without `options` mapping | Empty `options[]` allowed (product-level row, e.g. frontends) | Only the *total coverage* invariant is enforced; empty rows are legal |

### What could break the design

- **The lattice forces awkward buckets.** Cross-cutting options
  (`WithLogger`, `WithRouter`, `WithMetricsRegistry`, `WithRequestLogging`)
  do not belong to any product row. The escape hatch (new `sdk`-only rows)
  keeps the "exactly one row" invariant without misclassifying plumbing —
  but expect 1–3 new rows and a reviewer conversation about each.
- **`config_keys` semantics widen.** Today keys are YAML sections
  (`admin`, `rebac`) or gate paths; the coverage rule pushes entries toward
  leaf keys. A `stock-binary` capability with only a section key
  (`admin.control-plane` lists `admin`) passes today's check; after 3.1 it
  still passes (the section exists) but the "reachable" reading is weaker.
  Do not over-tighten: the rule is ≥1 existing key, not ≥1 *leaf* key.
- **Spec drift on the generator.** The spec's "add a generator" is already
  shipped (`capabilities generate` + diff-mode `docs-validate`). If
  implementation treats the spec literally and adds a second generator, the
  doc gets two writers. The design instead extends the existing marker
  region — flag this explicitly in review.
- **Cross-check coupling.** `capabilities check` now depends on
  `option-surface.json`; `options check` depends on `config-keys.json`.
  Either dependency missing breaks both gates. Mitigation: both checks
  report the missing artifact with a generation command, and `make ci`
  orders them (`config-keys` generation target runs first via
  `docs-validate`/`capabilities generate`).
- **Test-suite churn.** `checks/test_capability_registry.py` plants
  deliberately-bad registries; the new rules add cases (bad key, sdk-only
  with keys, stock-binary without keys, lattice gaps) but must not break the
  existing planted fixtures — update fixtures in the same change.
- **Option-count churn.** Every new SDK option shifts the lattice total
  (223 → 224) and fails `capabilities check` until mapped. This is the same
  intended friction as Decision 1's completeness check; the two fire
  together so the fix is one registry edit.

---

## Handoff and verification plan

Ordered landing (each step runs the mandatory gates):

1. **Decision 1** — `config-keys.json` + generator, `option-surface.json` +
   schema + `checks/option_surface.py` + unit tests, `cli.py options`,
   `make options-check`, CHECKS_REGISTRY.md, `make ci` slot. Review-and-fill
   the 70 unreachable entries (each becomes `wired`/`config`/`sdk-only`
   with rationale; `WithTenantUserStore` lands `sdk-only` now, before
   Decision 2).
2. **Decision 3** — extend `capability_registry.py` + schema + fixtures;
   lattice mapping for all 223 options; feature-matrix generated column.
3. **Decision 2** — issuer wiring + e2e; retention config + wiring +
   goroutine + e2e; backup wiring + `backup.sources` + e2e; docs and
   `config_keys` updates; `WithTenantUserStore` stays `sdk-only`, warning
   kept.

Acceptance mapping (spec → design):

| Spec acceptance | Where proven |
|---|---|
| `options check` prints `declared=223 (options*.go subset 174) wired=153 config=N sdk-only=M`, zero unclassified; deletion/wiring without registry fails (spec's `wired=159` is the raw count including `cmd/sso-server` test files; the stripped non-test wired set is 153 and the check prints both) | `checks/option_surface.py` + `checks/test_option_surface.py` |
| `make ci` runs the check; CHECKS_REGISTRY lists it | Makefile `ci` target + registry doc |
| Issuer e2e: discovery `issuer` = JWT `iss` = YAML issuer; RFC 9207 `iss` on auth error path | `test/` package `ssotest`, run `go test ./test/ -run TestE2E -v` |
| Retention/backup e2e: sweep runs from YAML; backup prune from `backup.keep` | `test/` e2e (real SQLite adapter from `admin_backup_test.go`) |
| `capabilities check` fails on bad key / keyless `stock-binary` / keyed `sdk`-only | `capability_registry.py` + extended fixtures |
| `docs-validate` diff-gates `feature-matrix.md`; `capabilities generate` converges | existing marker generator, extended columns |
| All options in exactly one capability row | lattice totals check |
| `go test ./... -race`, `make ci` green | handoff gate |

Pre-existing failures (if any surface at first run of the extended gates —
e.g. a `config_keys` entry that does not resolve in `config-keys.json`) are
reported separately per AGENTS.md and fixed in the same change only if they
are part of this scope; otherwise they are filed with the first green run's
report.
