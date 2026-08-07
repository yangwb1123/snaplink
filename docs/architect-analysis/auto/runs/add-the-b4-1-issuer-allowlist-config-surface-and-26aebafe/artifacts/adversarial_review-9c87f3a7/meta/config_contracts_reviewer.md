# Verification verdict: B4-1 issuer-allowlist compatibility contract claims

All five claims verified against the working tree (HEAD `122bd251`, design not yet implemented — claims are about the planned additive change over current code). No files were modified; a temporary test file used for live experiments was removed.

## 1. Reflection schema emits `issuer_allowlist` (cases 13–14) — **CONFIRMED**

- `config/source.go:238-246` — `configSchema = schema.Generate(Config{})` at package init; `config.Schema()` returns it. `generateStruct` (`config/schema/generate.go:88-130`) walks **every** exported field via its `yaml` tag, so a new `IssuerAllowlist []string yaml:"issuer_allowlist"` is picked up with zero generator changes; `[]string` → `{type: "array", items: {type: "string"}}` and is excluded from `Required` (`isRequiredCandidate` rejects slices).
- **Live experiment** (temp test, since removed): struct mirroring the R1 field shape → `issuer_allowlist` emitted as array-of-string, not required. PASS.
- Current schema output (via `go run ./cmd/sso-ctl config schema`) has no `issuer_allowlist` — the key genuinely does not exist today; case 13 becomes true the moment the field lands.
- Case 14 holds by mechanism: `runValidateSchema` (`schema.go:48-85`) validates against the same reflection document, so the key becomes a known property; `AdditionalProperties: false` keeps unknown keys failing — `TestRun_ValidateSchema_UnknownKey` (exit 1) already exists (`main_test.go:99-105`).
- No golden-file schema test will break: `integration_test.go` only asserts section presence, not key inventories.

## 2. validate-schema semantics stay shape-only — **CONFIRMED**

`runValidateSchema` parses raw YAML into `map[string]any` and calls `schema.Validate` directly — it never calls `config.Load`, and `schema.Validate`'s contract (validate.go) is explicitly shape-only (unknown_field / type_mismatch only; Required never enforced; nil always accepted). The planned `validateIssuerGate` lives in `runValidate` only (§7 of the spec), so it cannot leak into validate-schema. The design's §4 non-goal ("No changes to validate-schema semantics") matches the code.

## 3. `config.Load` and server boot byte-identical; nil-vs-empty YAML — **CONFIRMED**

- `ServerOptions()` (`config_load.go:301-307`) wires explicit fields only (`sso.WithIssuer(c.Server.Issuer)`, etc.); the new field is never read at boot. `decodeStrictWithFallback` / `applyDefaults` / `validate()` iterate no field lists — existing configs (no key) decode identically. The only change for configs *using* the key is the intended one: it stops tripping the unknown-field warn + fallback decode.
- Boot path: `--validate-only` (`cmd/sso-server/main_wiring.go:62`) loads and validates only; no full-config marshaling anywhere in the boot path, so no output delta.
- **Nil-vs-empty (live experiment, goccy/go-yaml):** absent → `nil`; `issuer_allowlist:` (null) → `nil`; `issuer_allowlist: []` → empty non-nil slice; all `len == 0`. The gate's "≥ 1 entry" check (R2-2) treats nil and empty uniformly — no Load impact, no panic.
- **Precision note (not a violation):** `validate --print` (`printConfig`) will render the new key (`null` absent vs `[]` empty). That is an additive change to the resolved-config dump, outside the byte-identical claims' scope (config.Load/boot) and consistent with acceptance case 1's "config OK" scope.

## 4. 0/1/2 exit-code convention unchanged — **CONFIRMED**

`main.go` + `main_test.go:31-118` pin the convention: 0 = success (validate OK, schema, help); 1 = load/validation/IO failures (sentinel issuer, unknown key, missing file); 2 = usage errors (missing subcommand/flag, unknown subcommand, flag parse). The gate adds only exit-1 violation paths; R2's stated "0 = all checks pass; 1 = any violation; 2 = usage errors" matches the code exactly.

## 5. config-reference.md rows vs R1 doc comment — **CONFIRMED at semantic level, two precision notes**

- Current state: `server.issuer` row exists (`docs/config-reference.md:48` — "MUST differ from `sso.DefaultIssuer`; stamped into JWT `iss`, discovery `issuer`, every RFC 9207 `iss`"); no `server.issuer_allowlist` or `server.base_url` rows anywhere (verified by rg — base_url appears only under unrelated `smtp`/`scim`/`phone`/`magic_link` keys).
- Planned rows (§7): amended `server.issuer` (validate requires an absolute URL from the allowlist), new `issuer_allowlist` row, new `base_url` row ("not wired at boot", "declared advertised base for the configcmd coherence check").
- R1's doc comment (allowlist for the stamped issuer; validate requires the resolved issuer to be an absolute URL listed there; not read at boot; entries must be absolute http(s) URLs) is fully consistent with the planned row content; the `base_url` row content derives from R2-5, matching the verified dead-key state (`ServerOptions` explicitly skips `BaseURL` at `config_load.go:302-303`; `WithBaseURL` is a no-op at `options_security.go:399-404`).
- **Precision notes:** (a) §7 does not pin the exact `issuer_allowlist` row wording — implementation must draft it from the R1 comment; (b) the amended `server.issuer` row must preserve the existing boot-level sentinel statement, since the configcmd gate is a stricter *additional* layer, not a replacement of the boot contract. Neither is a contradiction; both are drafting requirements for the implementer.

**Overall:** all five compatibility contract claims hold against measured reality. The design's byte-identical, exit-code, schema-additive, and shape-only commitments are all mechanically sound; no gate run is triggered (no Go files touched by this verification; temp test removed).
