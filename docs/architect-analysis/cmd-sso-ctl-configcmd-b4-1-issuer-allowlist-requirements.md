# Requirements Spec: B4-1 issuer-allowlist config surface + issuer coherence gate in `sso-ctl config validate`

- Direction: B4-1 issuer-allowlist config surface (source: `docs/architect-analysis/auto/analyses/cmd-sso-ctl-configcmd-07f6fb9f.json`, entry 2)
- Module: `cmd/sso-ctl/configcmd` (+ one additive field in `config`)
- Status: requirements (evidence-verified against HEAD `ce759da6`; independently re-verified against HEAD `831009a0` — code-identical, the intervening commit adds only the requirements artifact)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `interfaces/sso/server_discovery.go:251-259` — `resolveIssuer` Host fallback | `func (s *Server) resolveIssuer` at :251; when `s.issuer == "" \|\| s.issuer == DefaultIssuer` returns `requestBaseURL(ctx.Request())` at :255 (fn ends :258). The "Critical invariant: the value returned here MUST equal `oidc.ProviderMetadata.Issuer` for the same request" comment is at :242-249 | Confirmed |
| `interfaces/sso/server_discovery_config.go:62,109,146` — request-derived discovery base | `handleOIDCDiscovery` computes `base := requestBaseURL(ctx.Request())` at :62 and passes it to `buildOIDCConfiguration` (:102, called at :109); `buildBaseMetadata` (:142) seeds `Issuer: base` (:144) and every endpoint `base + PathX` (:145-149, userinfo/end_session :160-161) | Confirmed (line drift: 109→102/109, 146→144-149) |
| `server_discovery_config.go` discovery `issuer` override | `applyMFAIssuerSigning` at :264-266: `if s.issuer != "" && s.issuer != DefaultIssuer { cfg.Issuer = s.issuer }` — discovery `issuer` is config-valued when `server.issuer` is set; only the ENDPOINTS remain request-derived | Confirmed — corrects the direction's mismatch pairing, see §2 |
| `config/config_load.go:60,183-184` — default + sentinel-only gate | `const DefaultServerIssuer = "sso-server"` at :60 (doc :48-59); `applyDefaults` sets it at :70-71 when empty; `validate()` rejects ONLY `c.Server.Issuer == sso.DefaultIssuer` at :183-184 (`DefaultIssuer = "snaplink-sso"`, `shared/core/consts_oauth.go:139`). A config with `issuer: sso-server` (the default) or a non-URL literal passes | Confirmed |
| `cmd/sso-ctl/configcmd/main_test.go` `TestRun_InvalidConfig_Sentinel` — only issuer gate | Present; it is the only issuer-related test. `validConfig` fixture sets `issuer: http://localhost:8080` + `base_url: http://localhost:8080`. No allowlist concept anywhere in the package | Confirmed |
| `infrastructure/defaultimpl/issue_payload.go:26` — `iss` stamped into payload | `buildAccessPayload` at :25-27 sets `Iss: issuer` at :28; callers pass `j.issuer` (ed25519_issue.go:43), which the cmd wires as `srv.Issuer` via `WithEd25519Issuer(srv.Issuer)` etc. (cmd/sso-server/serverbuildsign/build_signing_issuers.go:43,67,95) | Confirmed (line drift 1: :28) |
| "no allowlist key exists anywhere in config/" | `rg -i "issuer_allowlist\|iss_allowlist\|allowed_issuers"` across `config/` and `cmd/`: zero hits. The only `iss`-adjacent allowlist is CAEP's trusted-transmitter list (`config/config_caep.go:45,67-74`), an inbound SET-trust concept, not the stamped-issuer allowlist | Confirmed |
| `sso.WithIssuer` wiring at boot | `config.ServerOptions()` at `config/config_load.go:308` emits `sso.WithIssuer(c.Server.Issuer)`; `cmd/sso-server/build_app_core.go:154` appends it; `cmd/sso-server/build_app.go:257` calls `sso.NewServer(b.opts...)` | Confirmed — the B4-1 proposal's "WithIssuer never wired" note is stale at this HEAD |
| `server.base_url` semantics | `ServerConfig.BaseURL` (`config/config_server.go:18`) has no doc comment and no consumer: `ServerOptions()` explicitly does not wire it (`config/config_load.go:302-307`); `sso.WithBaseURL` is a no-op ("retained for source compatibility but has no effect", `interfaces/sso/options_security.go:399-404`); absent from `docs/config-reference.md` | Confirmed — the key is dead today; the gate makes it load-bearing as the operator's declared advertised base |
| CI gate interplay | `make config-validate-all` (`.github/workflows/ci.yml:126-129`, Makefile:400-410) validates the 7 deploy configs with `go run ./cmd/sso-server --validate-only` (the server loader), NOT `sso-ctl config validate` — so the new configcmd gate does not move CI; it is an operator/CI-pre-check surface | Confirmed |

### Re-verification results (HEAD `831009a0`)

All eight evidence citations re-checked against the working tree; every verdict holds (minor line drift from the worktree-dirty `config/config_load.go` B4-2 edit is within the cited ranges). Two additional corrections found during re-verification, both in §7:

1. **`bin/config.yaml` migration value**: the table's `sso-server → http://localhost:8080` replacement is wrong — that file declares `base_url: http://localhost:28898` (:22) and `listen: ":28898"` (:23). The replacement must be `http://localhost:28898`, else the new coherence check fails the migrated config.
2. **`ops/deploy/k8s/config.yaml` migration value**: `sso-server → http://localhost:8080` is wrong — the file declares `base_url: http://sso-server.snaplink-sso.svc.cluster.local:8080` (:13). The replacement must be the same cluster-internal URL (one-line change + allowlist), keeping the config's declared advertised base coherent.

`cmd/sso-server/config.yaml` (`base_url` :27 = `http://localhost:8080`) is coherent with the table's `localhost:8080` value as written. Rule added: the migrated `issuer` must equal the config's existing `base_url` origin when `base_url` is set.

## 2. Corrections to the direction's problem framing

The evidence above supports the direction's acceptance checks, but two mechanism claims need correction so the spec enforces the right thing:

1. **"validate currently exits 0 for a config that will issue Host-derived tokens"** — under the cmd config path, RFC 9068 JWT `iss` is never Host-derived: `WithIssuer(cfg.Server.Issuer)` is wired at boot, so `iss` = the configured value, defaulting to the literal `"sso-server"`. The Host-derived `requestBaseURL` fallback in `resolveIssuer` is reachable only for SDK embedders that never call `WithIssuer`. What IS true: a config omitting `server.issuer` (or using a non-URL literal) validates green today and deploys an issuer identity that (a) is a non-URL literal no OIDC RP can validate and (b) sits in a discovery document whose ENDPOINTS are Host-derived — an incoherent, un-rollout-able deployment. The "issuer absent ⇒ exit 1" acceptance check stays, but the failure message must describe the resolved non-URL issuer, not claim Host-derivation.
2. **"discovery.issuer != stamped iss"** — the code makes these always agree: both use the same `s.issuer`-if-set-else-requestBaseURL semantics (server_discovery.go:251-255 vs server_discovery_config.go:264-266). The real RFC 9207 §2 / OIDC §4.3 hazard is **issuer-origin vs endpoint-origins in the same discovery document**: with `issuer: https://sso.example.com`, a proxy that mangles X-Forwarded-Proto/Host produces a doc whose `issuer` is `https://sso.example.com` but whose endpoints are the mangled origin. The acceptance's "issuer vs base_url coherence" check is the correct offline proxy for this: `server.base_url` is the operator's declaration of the base the discovery endpoints will advertise; when both keys are set their origins must match.

## 3. Goal and user outcome

B4-1 requires `iss` to be operator-configurable via an allowlist and never Host-derived. The server-side enforcement (resolveIssuer/discovery changes) is B4-1 server work in a separate module; this direction delivers the **config surface + deploy pre-check half**: `sso-ctl config validate` becomes a hard gate that fails any config whose resolved issuer is not an allowlisted absolute URL, and any config whose issuer origin disagrees with the declared `base_url`.

Completion marker: an operator running

```bash
sso-ctl config validate --file config.yaml
```

gets exit 1 for: omitted `server.issuer` (defaulted to `sso-server`), a non-URL issuer, an issuer outside `server.issuer_allowlist`, or an issuer origin that differs from `server.base_url`'s origin; exit 0 only for a config whose resolved issuer is an absolute URL listed in the allowlist, with coherent origins.

## 4. Product boundary

- Surface: `sso-ctl config validate` (`cmd/sso-ctl/configcmd`) + one additive field on `config.ServerConfig`.
- Default: the gate is unconditional in `validate` — this is a deliberate strictness change (see §5 R2); the server itself is untouched, so boot behavior is byte-identical (the key is not read at boot).
- Explicit non-goals (do not implement):
  - No server-side changes: `resolveIssuer` fallback removal, discovery base-URL wiring, or runtime allowlist enforcement are B4-1 server work (`interfaces/sso`, `cmd/sso-server`) — separate module, out of this direction.
  - No enforcement inside `config.Load`/`validate()` — that path gates server boot and would break every existing config; the gate lives in `configcmd`'s `runValidate` only.
  - No `require_configured`-style toggle from the B4-1 proposal text (`docs/proposals/audit-contract-batch-snaplink.md:12`); the direction's acceptance is unconditional.
  - No `--issuer-allowlist` CLI flag (the never-implemented B4-3 design `docs/architect-analysis/cmd-sso-ctl-b4-3-t2-requirements.md` R2 is superseded by the config key; the flag does not exist in `main.go` today).
  - No changes to `validate-schema` semantics (shape-only; the reflection schema picks the new field up automatically) and no new `sso-ctl` subcommand or package (fan-out ceiling, see §7).
  - No OpenAPI/`Err*`/error-code changes (stderr text + existing exit-code convention only).

## 5. Requirements

### R1 — Config surface: `server.issuer_allowlist`

Add to `ServerConfig` (`config/config_server.go`), next to `Issuer`:

```go
// IssuerAllowlist is the B4-1 operator allowlist for the stamped issuer
// (JWT iss, RFC 9207 iss, discovery issuer). sso-ctl config validate
// requires the resolved server.issuer to be an absolute URL listed here;
// the key is not read at boot (server-side enforcement is B4-1 server
// work). Entries must be absolute http(s) URLs.
IssuerAllowlist []string `yaml:"issuer_allowlist"`
```

- Additive only: `config.Load` and `validate()` behavior is unchanged (boot T-9), and the reflection schema (`config/schema`) includes the key automatically.
- Naming collision check: no existing `issuer_allowlist` key in `config/` (CAEP's transmitter `iss` list is `caep.transmitters`, a different concept).

### R2 — Unconditional issuer gate in `runValidate`

After `config.Load` succeeds, `runValidate` runs a new `validateIssuerGate(cfg *config.Config) []string` (new file, pure function, unit-testable). Violations are all reported to stderr and the exit code is 1 when any is present:

1. **Absolute-URL issuer (covers "absent")**: the resolved `cfg.Server.Issuer` (defaults already applied — absence manifests as the `"sso-server"` literal) must parse with `url.Parse`, have scheme `http` or `https`, and a non-empty host. Violation message names the resolved value and the requirement. This is the check that turns "issuer absent ⇒ exit 1" into a testable rule.
2. **Allowlist present and non-empty**: `cfg.Server.IssuerAllowlist` must have ≥ 1 entry; missing/empty ⇒ violation directing the operator to add `server.issuer_allowlist` with the canonical URL(s). (Without this, no config could ever satisfy "allowlisted", and the "exits 0 only for an allowlisted absolute URL" acceptance would make the gate a silent always-fail.)
3. **Allowlist entries are absolute URLs**: every entry must parse with scheme `http`/`https` and non-empty host; malformed entries are violations (the schema cannot express this).
4. **Membership**: the resolved issuer must equal an allowlist entry after trimming one trailing `/` from both sides (exact string match otherwise). Violation message names the issuer and the allowlist.
5. **Issuer↔base_url coherence**: when `cfg.Server.BaseURL` is set, it must parse as an absolute http(s) URL and its origin (scheme + host + port, lowercased host; path and trailing `/` ignored) must equal the issuer's origin. Mismatch ⇒ violation naming both origins. When `base_url` is unset the check is skipped — the runtime advertised base is request-derived and has no offline signal; documented limitation. Normalization is fail-closed: ports compare literally (`https://sso.example.com:443` vs `https://sso.example.com` is a mismatch — the gate never assumes a default port), and trailing-slash trimming removes exactly one `/` (`//`-suffixed values remain distinct and fail).

Order of checks: 1 → 3 → 2 → 4 → 5, so the most specific message wins per violation set; all violations are collected (not first-wins).

Exit-code contract (unchanged convention): 0 = all checks pass; 1 = any violation; 2 = usage errors.

### R3 — Regression invariance

- `config.Load`/server boot: byte-identical (additive field only; `ServerOptions()` unchanged).
- `validate` without the new key in the file: behavior changes ONLY for configs whose resolved issuer is not an allowlisted absolute URL (the point of the gate); all other output/exit behavior identical.
- `schema` output: grows by the new key; everything else byte-identical.
- `validate-schema`: unchanged semantics; a config using the new key passes shape validation.

### Testable acceptance (Given/When/Then)

Tests live in `cmd/sso-ctl/configcmd/issuer_gate_test.go` (gate unit tests) plus `main_test.go` additions (end-to-end `Run` cases). The `validConfig` fixture gains `issuer_allowlist: [http://localhost:8080]`.

1. Given `validConfig` + `issuer_allowlist: [http://localhost:8080]` (matching issuer), when `validate` runs, then exit 0 and stdout `config OK: ...` (byte-identical shape to today).
2. Given a config with no `server.issuer` (resolves to default `sso-server`) and a matching allowlist, when `validate` runs, then exit 1 with stderr naming the resolved non-URL issuer.
3. Given `issuer: https://sso.example.com` and `issuer_allowlist: [https://sso.example.com]`, when `validate` runs, then exit 0.
4. Given `issuer: https://evil.example.com` and `issuer_allowlist: [https://sso.example.com]`, when `validate` runs, then exit 1 with stderr naming both the issuer and the allowlist.
5. Given a valid issuer but no `issuer_allowlist` key, when `validate` runs, then exit 1 with stderr directing the operator to the key.
6. Given `issuer_allowlist: []` (explicit empty), when `validate` runs, then exit 1 (empty allowlist).
7. Given `issuer: https://sso.example.com` and `issuer_allowlist: [https://sso.example.com/]` (trailing slash), when `validate` runs, then exit 0 (normalized match).
8. Given `issuer: https://sso.example.com`, `issuer_allowlist: [https://sso.example.com]`, and `base_url: https://internal.example.com`, when `validate` runs, then exit 1 with stderr naming both origins.
9. Given the same but `base_url: https://sso.example.com/` (trailing slash) and `base_url: https://sso.example.com/custom/path`, when `validate` runs, then exit 0 in both cases (origin equality; path ignored).
10. Given a valid allowlisted issuer and no `base_url`, when `validate` runs, then exit 0 (coherence check skipped).
11. Given `issuer_allowlist: [sso-server]` (non-URL entry), when `validate` runs, then exit 1 (entries must be absolute URLs).
12. Given a multi-entry allowlist `[https://sso.example.com, https://sso.internal]`, when `validate` runs with the issuer matching the second entry, then exit 0.
13. Given `Run(["schema"])`, when the output is captured, then it contains `"issuer_allowlist"`.
14. Given a config using `server.issuer_allowlist`, when `validate-schema` runs, then exit 0; the existing unknown-key case still exits 1.
15. Regression: `TestRun_InvalidConfig_Sentinel` (exit 1, config.Load-level), `TestRun_MissingFileFlagIsUsageError`, `TestRun_NoSubcommand`, `TestRun_UnknownSubcommand`, `TestRun_Help`, and the schema/validate-schema cases pass unchanged.
16. Given `issuer: https://sso.example.com` (no explicit port), `issuer_allowlist: [https://sso.example.com]`, and `base_url: https://sso.example.com:443`, when `validate` runs, then exit 1 (default-port normalization is fail-closed; the operator must spell the port consistently).

Maps to: T-8(a) — token `iss` from an operator allowlist, never Host-derived (deploy-gate half; `docs/campaigns/implementation-gate.md` row 1); T-2 — the `metadata.issuer == resolveIssuer` invariant (server_discovery.go:242-249) guarded on the config side by the origin-coherence check.

## 6. Engineering-gate constraints (verified)

- **Fan-out ceiling**: `cmd/sso-ctl/` has 16 immediate subdirectories; the committed Go gate (`TestArchitecture_DirectorySubdirFanout`, ceiling 16) has no configcmd exemption, so no new package — the gate is a new file inside `configcmd`. The Python mirror (`checks/directory_fanout.py`, max 15) already flags `cmd/sso-ctl/` at 16 — a pre-existing violation; do not worsen it (report separately, per AGENTS.md).
- **Budgets**: `configcmd` has 2 non-test files (main.go 120, schema.go 96) of the 10-file cap; adding `issuer_gate.go` keeps 3. New functions ≤ 50 lines / complexity ≤ 15 / nesting ≤ 3; `validateIssuerGate` returns a `[]string` of violations.
- **Worktree state**: `config/config_load.go` carries an unrelated in-progress B4-2 change (scope-registry validation). This spec touches `config/config_server.go` only — preserve the worktree diff.
- **Wire/contract invariants untouched**: no routes, no `Err*`, no OpenAPI, no server config-load behavior, no AGENTS.md §3 security-table change (the gate is an out-of-band operator check over already-loaded config).

## 7. Files

### Create

```text
cmd/sso-ctl/configcmd/issuer_gate.go — validateIssuerGate(cfg *config.Config) []string:
    absolute-URL issuer, allowlist present/non-empty, entry URL validity, normalized
    membership, issuer↔base_url origin coherence. Pure function; runValidate calls it
    after config.Load and prints each violation to stderr, returning 1 when non-empty.
cmd/sso-ctl/configcmd/issuer_gate_test.go — acceptance cases 2, 4-12 (unit-level) plus
    the schema assertion 13.
```

### Modify

```text
config/config_server.go — add ServerConfig.IssuerAllowlist []string `yaml:"issuer_allowlist"`
    with the doc comment in R1 (additive; Load/boot unchanged).
cmd/sso-ctl/configcmd/main.go — runValidate: call the gate after config.Load; extend the
    package doc + usage banner with one line about the issuer gate (stays < 500 lines).
cmd/sso-ctl/configcmd/main_test.go — validConfig fixture gains the allowlist key;
    append end-to-end cases 1, 3, 14, 15.
docs/config-reference.md — OIDC table: amend the server.issuer row (validate requires an
    absolute URL from the allowlist) and add the server.issuer_allowlist row; add a
    server.base_url row noting it is not wired at boot and is the declared advertised
    base for the configcmd coherence check.
```

### Deploy-tree configs (must satisfy the stricter contract; see §7 replacement rule)

The 7 CI-validated configs, the conformance fixture, the canonical kustomize base/overlay configs (which feed `bin/k8s-rendered/*`), and the Tier-B `ops/deploy/k8s-distributed` config set `issuer:` but none sets the allowlist; four use the non-URL literal `sso-server` (rows 1-3 plus the kustomize base — would fail the new gate). Update each to an absolute URL (unchanged where already absolute) plus a matching `issuer_allowlist`. **Replacement rule: when the config already sets `base_url`, the new `issuer` value MUST have the same origin as that `base_url` — otherwise the coherence check (R2-5) fails the migrated config. In the sentinel configs below this means `issuer := base_url` exactly, not a guessed port.** Verified replacement values against each file's existing `base_url`/`listen`:

```text
cmd/sso-server/config.yaml:19        sso-server → http://localhost:8080      (base_url :27 already localhost:8080; listen :28)  + allowlist
bin/config.yaml:17                   sso-server → http://localhost:28898    (base_url :22 is localhost:28898, NOT 8080; listen :23)  + allowlist
ops/deploy/k8s/config.yaml:11        sso-server → http://sso-server.snaplink-sso.svc.cluster.local:8080  (base_url :13; listen :14)  + allowlist
ops/deploy/kustomize/base/config.yaml:11  sso-server → http://sso-server.snaplink-sso.svc.cluster.local:8080  (canonical base; byte-identical duplicate of row 3's file; base_url :14; listen :15 — post-migration lines, the allowlist insertion at :12 shifts the original :13/:14)  + allowlist
docs/examples/basic/config.yaml:2    already absolute (+ allowlist)
ops/deploy/compose/config.yaml:10    already absolute (+ allowlist)
ops/deploy/baremetal-ha/sso/config.yaml:17  already absolute (+ allowlist)
ops/deploy/k8s-prod/config.yaml:12   already absolute (+ allowlist); no `base_url` key ⇒ R2-5 coherence check skipped (coherence N/A)
ops/deploy/kustomize/overlays/prod/config.yaml:12  already absolute (`https://sso.example.com`; quoted :12) (+ allowlist); no `base_url` key ⇒ R2-5 coherence check skipped (coherence N/A)
test/oidc-conformance/config.yaml:15 already absolute (+ allowlist); no `base_url` key ⇒ R2-5 coherence check skipped (coherence N/A)
ops/deploy/k8s-distributed/config.yaml:3  already absolute (`https://sso.ywbsd.site`) (+ allowlist); no `base_url` key ⇒ R2-5 coherence check skipped (coherence N/A)
```

The `bin/config.yaml` and `ops/deploy/k8s/config.yaml` rows deliberately differ from the naive `localhost:8080` replacement: the gate would flag those origins as incoherent with the configs' declared `base_url` (see acceptance 8). The kustomize base row carries the same cluster-DNS replacement as row 3 because the two files are byte-identical; without it, `make k8s-render` would keep emitting the sentinel issuer in `bin/k8s-rendered/dev/all.yaml`. Rows without a `base_url` key are labeled "coherence N/A": R2-5 is skipped by design (no offline advertised-base signal), so those rows assert allowlist membership only, never coherence. `bin/k8s-rendered/*` are generated outputs — regenerate via the existing k8s-render tooling, do not hand-edit.

### Do not modify

```text
config/config_load.go (worktree-dirty with B4-2; no Load behavior change)
interfaces/sso/*, cmd/sso-server/* — B4-1 server work, separate module
docs/error-codes.md, docs/openapi.yaml — no new error/endpoint surface
```

## 8. Dependencies and compatibility

- New/changed SPI: none. New option/store wiring: none.
- New YAML key: `server.issuer_allowlist` (read by configcmd only; documented in config-reference.md per AGENTS.md workflow rule 6).
- Storage migration: none. HTTP/proto compatibility: none.
- Rollout/rollback: removing the field and the gate restores the previous binary's behavior exactly; the gate is opt-in only in the sense that it runs when the operator invokes `validate` (the module's stated purpose).

## 9. Documentation

- [x] `docs/config-reference.md` — new `server.issuer_allowlist` row; amended `server.issuer` row; `server.base_url` row (currently undocumented).
- [ ] `docs/openapi.yaml` — not applicable (no server endpoint).
- [ ] `docs/error-codes.md` — not applicable (no new `Err*`; exit codes follow the existing 0/1/2 convention).
- [x] Feature/deferred-backlog note: B4-1 server-side enforcement (resolveIssuer no-Host fallback, runtime allowlist check, base_url wiring) remains the server module's own follow-on; this gate is its deploy-tree precondition.

## 10. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .        # fan-out gate must stay green
go test ./cmd/sso-ctl/configcmd/... -v -race
make ci
```

Pre-existing failures to report separately: `checks/directory_fanout.py` already fails for `cmd/sso-ctl/` (16 > 15) and other dirs; the committed Go gate passes today and must remain passing.
