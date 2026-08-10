# Requirements Spec: sso-ctl discovery-truthiness sweep + issuer-allowlist pre-check

- Direction: B4-3/T-2 (source: `docs/architect-analysis/auto/analyses/cmd-sso-ctl-7e52c2bb.json`, entry 2)
- Module: `cmd/sso-ctl` (`configcmd` package)
- Status: requirements (evidence-verified against HEAD)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `cmd/sso-ctl/configcmd/main.go:63-85` — runValidate via `config.Load` | `runValidate` actually spans lines 86–110; `config.Load(*file)` is at line 99. `Run`'s subcommand switch is lines 39–57. No discovery/sweep/allowlist surface exists anywhere in the package | Confirmed (line drift 3–14, symbol and behavior exact) |
| `config/config_load.go:48-71` — issuer default | `DefaultServerIssuer = "sso-server"` at line 60 (doc 48–59); `applyDefaults` sets it at 70–71 (`if c.Server.Issuer == ""`). Loader calls `applyDefaults()` then `validate()` (config/source.go:142-145) | Confirmed |
| `config/config_load.go:176-184` — sentinel rejection only, no allowlist | `validate()` rejects only `c.Server.Issuer == sso.DefaultIssuer` at lines 183–184 (comment 176–182). No issuer-allowlist concept anywhere in `config/` (the only `allowlist` hits are unrelated: `tenant_label_allowlist`, `ip_allow_list`, AAGUID allowlist, etc.) | Confirmed |
| `interfaces/sso/server_discovery.go:251-259` — `resolveIssuer` Host fallback | `func (s *Server) resolveIssuer` at line 251; when unset/sentinel it returns `requestBaseURL(ctx.Request())` at line 255 (function ends 258). `DefaultIssuer = "snaplink-sso"` (shared/core/consts_oauth.go:139, aliased interfaces/sso/aliases.go:179) | Confirmed |
| `interfaces/sso/server_discovery_config.go:142-161` — `buildBaseMetadata` real endpoints | Function at 142–161: `TokenEndpoint: base + PathToken` (146), `JWKSURI: base + PathJWKS` (147), `RevocationEndpoint: base + PathRevoke` (148), `IntrospectionEndpoint: base + PathIntrospect` (149); `AuthorizationEndpoint: base + PathLogin` (145); conditional `UserInfoEndpoint`/`EndSessionEndpoint`/`CheckSessionIframe` (153–157) | Confirmed |
| `shared/core/consts.go:21-23` — `PathToken=/token` etc. | `PathToken = "/token"` (21), `PathIntrospect = "/token/introspect"` (22), `PathRevoke = "/token/revoke"` (23). `PathJWKS = "/.well-known/jwks.json"` lives in shared/core/jwks.go:9 (moved per comment at server_discovery.go:35) | Confirmed (one constant relocated) |
| `interfaces/sso/rootcov_discovery_test.go:268` — non-nil-only assertions, no sweep | Line 268 is the 200-status check for both discovery paths; the only field assertions are non-nil: `doc["issuer"] == nil \|\| doc["authorization_endpoint"] == nil \|\| doc["token_endpoint"] == nil` (278–280). No endpoint-truthiness/equality assertions anywhere in the file | Confirmed (line drift 10) |
| `rg TestOIDCDiscovery` across tree: empty | 0 matches in 2842 Go files (`rg -n "TestOIDCDiscovery" -g '*.go'` → 0). The two legacy defect tests (`TestOIDCDiscovery` asserting `/authenticate`; `TestOIDCDiscoveryEndpoint` asserting the `8080:0` port bug, per docs/campaigns/implementation-gate.md row 3) are absent from this tree | Confirmed |
| "sweep/truthiness matches nothing in the module" | `rg -i "discovery|sweep" cmd/sso-ctl/` → 0 hits. No live discovery fetch exists in sso-ctl (auditverify's `--from-url` fetches the admin audit API, not discovery) | Confirmed |
| Deploy-tree discovery tests don't do a live sweep | `test/oidc_discovery_test.go` (`TestDiscovery_*`): asserts required fields non-nil, absolute-URL prefix, `issuer == WithIssuer`, grants, PKCE, scopes, snake_case. No per-endpoint GET sweep, no `token_endpoint == base+"/token"` equality, no `/authenticate`-absence or zero-port checks | Confirmed (supports, with nuance: it asserts URL *prefix*, not path equality) |
| T-2 / T-8(a) / T-9 taxonomy | docs/campaigns/campaign-snaplink-b4.yaml + implementation-gate.md: T-2 = "sweep 全绿（广告端点绝不 404）；`metadata.token_endpoint == "/token"`" (G5 gate, row 3); T-8(a) = `/token` 200 + kid + claims incl. `iss` (G1 gate, row 1); T-9 = regression retention of existing behavior | Confirmed |

## 2. Goal and user outcome

B4-3 requires the deploy tree to carry sweep/truthiness assertions (advertised endpoints never 404, `token_endpoint == "/token"`, no `/authenticate`, no `8080:0`-class zero/malformed port) and B4-1 requires `iss` to be an operator allowlist, never Host-derived. The server must not serve static checks, so the operator-facing deploy pre-check belongs in `sso-ctl`, the only deploy-surface host.

Completion marker: an operator can run, from CI or a deploy pre-check,

```bash
sso-ctl config check-discovery --url https://sso.example.com
sso-ctl config validate --file config.yaml --issuer-allowlist https://sso.example.com,https://sso.internal
```

and get a hard pass/fail (exit 0/1) on the discovery-document truthiness contract and the issuer-allowlist contract, before any traffic is cut over.

## 3. Product boundary

- Surface: `sso-ctl` operator toolbelt (`cmd/sso-ctl/configcmd`), offline/out-of-band checks only.
- Default: new `check-discovery` subcommand is opt-in (never invoked unless requested); `validate --issuer-allowlist` is opt-in (absent flag ⇒ today's behavior, byte-identical).
- Explicit non-goals (do not implement):
  - No server-side changes: `resolveIssuer`'s Host-derived fallback removal, `WithIssuer` wiring, and any `config` package schema/key additions are B4-1 server work in `interfaces/sso` / `config` — separate module, out of this direction.
  - No changes to `test/oidc_discovery_test.go` or `interfaces/sso/rootcov_discovery_test.go` (those belong to the server module; this spec adds the *operator-facing live* sweep in sso-ctl).
  - No new top-level `sso-ctl` subcommand package and no new entry in the `subcommands` map (cmd/sso-ctl/main.go) — see §6 gate constraint; the sweep is a `configcmd` sub-subcommand.
  - No new config keys / no `config.Config` struct or JSON-schema changes (T-9 requires `config schema` output and `--print` output to stay byte-identical).
  - No `/authenticate` route changes, no `token_endpoint` form-encoding enforcement (T-8(b)), no hashcmd cost knob (B4-4) — other directions.
  - No `--file`-derived base URL for the sweep (acceptance pins the surface to `--url`).

## 4. Module classification

- [x] Infrastructure/config/deployment (operator tooling)
- [ ] OAuth/OIDC protocol flow · [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Authorization · [ ] Cold module · [ ] Refactoring only

Owning layer/package: `cmd/sso-ctl/configcmd` (composition layer). It already imports `config` (+ `config/schema`); `cmd/sso-ctl/importcmd` and `cmd/sso-ctl/generate` already import `interfaces/sso`, so test-only import of `interfaces/sso` in `configcmd` tests is consistent with the module's existing composition pattern. Dependency direction: `cmd/*` → `config` → `interfaces/sso` → … → `shared/core`, no upward import introduced.

## 5. Requirements

### R1 — Discovery-truthiness sweep (`sso-ctl config check-discovery`)

New sub-subcommand wired into `configcmd.Run`'s switch (alongside `validate` / `schema` / `validate-schema`), with usage banner in the package doc.

Flags: `--url <base>` (required; http/https), `--timeout <dur>` (default 10s, bounds the entire sweep including every endpoint fetch).

Semantics: fetch `<base>/.well-known/openid-configuration` (use the server's own `PathOIDCDiscovery` constant), decode JSON, then assert:

1. **Document fetch**: HTTP 2xx and valid JSON, else violation "discovery document fetch failed" with the URL and status.
2. **Path equality** (exact string equality against `base` trimmed of a trailing `/`; a trailing `/` in `--url` is itself a violation since the server emits `base + Path` with a bare base):
   - `token_endpoint == base + core.PathToken` (`/token`) — the T-2 headline assertion;
   - `jwks_uri == base + core.PathJWKS` (`/.well-known/jwks.json`);
   - `revocation_endpoint == base + core.PathRevoke` (`/token/revoke`);
   - `introspection_endpoint == base + core.PathIntrospect` (`/token/introspect`).
   All four are always emitted by `buildBaseMetadata` (server_discovery_config.go:145-149), so absence of any of them is a violation. Conditional fields (`userinfo_endpoint == base + PathUserInfo`, `end_session_endpoint == base + PathEndSession`) are checked only when present (OIDC-gate-off deployments omit them legitimately).
3. **Every advertised endpoint never 404s**: for every URL-valued field present in the document (`issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `revocation_endpoint`, `introspection_endpoint`, `userinfo_endpoint`, `end_session_endpoint`, `check_session_iframe`, plus any of `registration_endpoint`, `pushed_authorization_request_endpoint`, `device_authorization_endpoint`, `backchannel_authentication_endpoint` when present), GET it and require status != 404. Any other status (200/204/400/401/405…) proves the route is mounted, which is exactly the T-2 "advertised endpoints never 404" contract. Fetch failures (dial/read/timeout) are violations.
4. **No `/authenticate` path**: no advertised endpoint's parsed URL path contains the path segment `authenticate` (legacy defect path; the real login route is `/auth/login` via `core.PathLogin`).
5. **No zero/malformed port**: every advertised endpoint must parse with `url.Parse` (catches the legacy `host:8080:0` double-colon form, which fails to parse), have scheme http/https and a non-empty host, and any explicit port must parse as an integer in 1–65535 (catches `host:0`).

Exit codes: 0 = all assertions pass; 1 = any violation or fetch failure (each violation printed to stderr naming the field and offending value); 2 = usage error (missing/unknown flags).

### R2 — Issuer-allowlist pre-check (`sso-ctl config validate --issuer-allowlist`)

Extend `runValidate` with an optional `--issuer-allowlist` flag: comma-separated, exact-match list of canonical issuer strings (trimmed; empty entries are a usage error — exit 2 — and an empty resulting list is a usage error).

- Flag absent ⇒ behavior byte-identical to today (T-9).
- Flag present: after `config.Load` succeeds (which applies defaults and rejects only the SDK sentinel), require `cfg.Server.Issuer` ∈ allowlist (exact string match). Not in list ⇒ stderr `config: server.issuer %q is not in the operator allowlist [%s]`, exit 1.
- The defaulted `"sso-server"` issuer is subject to the same check — an operator who pins an allowlist must list their canonical issuer(s) or the pre-check fails loudly (this is the B4-1 "iss is an operator allowlist, never Host-derived" deploy gate, T-8(a)-adjacent).

### R3 — Regression invariance (T-9)

- `sso-ctl config validate --file <valid>` — stdout and exit code byte-identical to the pre-change binary (no flag ⇒ no new output, no reordering).
- `sso-ctl config validate --file <valid> --print` — resolved JSON byte-identical (no struct/schema/option changes).
- `sso-ctl config schema` — output byte-identical.
- The sweep is read-only: it performs no server mutation; a stock server's discovery body is unchanged by running the sweep against it, and the sweep exits 0 against the stock server's current discovery output.

### Testable acceptance (Given/When/Then)

T-2 sweep — new tests in `cmd/sso-ctl/configcmd/discovery_check_test.go` (httptest-based, no network):

1. Given a stock server built exactly like `test/oidc_discovery_test.go`'s `newDiscoveryServer` (sso.NewServer + httptest), when `Run(["check-discovery", "--url", srv.URL])` runs, then exit 0 and no stderr output.
2. Given an httptest server whose doc has `token_endpoint` = base+`/v1/token` (wrong path), when the sweep runs, then exit 1 with a stderr line naming `token_endpoint` and the expected `base+/token`.
3. Given a doc whose `jwks_uri`/`revocation_endpoint`/`introspection_endpoint` differ from `base+Path*`, when the sweep runs, then exit 1, one violation per mismatched field.
4. Given a doc advertising an endpoint that returns 404, when the sweep runs, then exit 1 naming the 404 URL.
5. Given a doc advertising `http://sso.example.com/authenticate` as `authorization_endpoint`, when the sweep runs, then exit 1 naming the `authenticate` path.
6. Given a doc advertising `http://sso.example.com:0/token` and one advertising `http://sso.example.com:8080:0/token`, when the sweep runs, then exit 1 in both cases (zero port; unparseable double-colon host).
7. Given a doc advertising a route that returns 405 on GET (e.g. `/token` mounted POST-only), when the sweep runs, then exit 0 (405 ≠ 404 proves the route exists).
8. Given a server returning 500 or non-JSON on the discovery path, when the sweep runs, then exit 1 with the fetch diagnostic.
9. Given a stock server (T-2 case 1), when the discovery body is captured before and after the sweep, then the two bodies are byte-identical (read-only sweep).

T-8(a)-adjacent allowlist — extend `cmd/sso-ctl/configcmd/main_test.go`:

10. Given `--issuer-allowlist https://sso.example.com` and a config whose `server.issuer` matches, when `validate` runs, then exit 0 with stdout byte-identical to the no-flag run.
11. Given `--issuer-allowlist https://sso.example.com` and a config whose `server.issuer` is `https://evil.example.com`, when `validate` runs, then exit 1 with a stderr line naming the issuer and the allowlist.
12. Given `--issuer-allowlist https://sso.example.com` and a config with no `server.issuer` (resolves to the `sso-server` default), when `validate` runs, then exit 1 (default does not silently pass an allowlist).
13. Given `--issuer-allowlist https://sso.example.com,https://sso.internal` (multi-entry), when `validate` runs against either value, then exit 0.
14. Given `--issuer-allowlist ""` or `",,"`, when `validate` runs, then exit 2 (usage error).
15. Given the pre-change test set (`TestRun_ValidConfig`, `TestRun_InvalidConfig_Sentinel`, `TestRun_MissingFileFlagIsUsageError`, `TestRun_NoSubcommand`, `TestRun_UnknownSubcommand`), when run against the modified binary without the new flag, then all pass unchanged (T-9).

T-9 sweep-wiring regression:

16. Given `sso-ctl config` with no subcommand, an unknown subcommand, and `check-discovery` without `--url`, then exit 2 in all three cases (usage conventions preserved).

## 6. Engineering-gate constraints (verified)

- **Fan-out ceiling forces the configcmd extension.** `cmd/sso-ctl/` currently has 16 immediate subdirectories. The committed Go gate `directory_fanout_test.go` enforces `maxSubdirsPerDir = 16` (line 28) with no exemption for `cmd/sso-ctl`, so a 17th subdirectory (a new `discoverycmd` package) would fail `TestArchitecture_DirectorySubdirFanout`. The Python mirror (`checks/directory_fanout.py`, max 15) already flags `cmd/sso-ctl/` at 16 — a pre-existing, unrelated violation that must not be worsened. Therefore: no new package; the sweep is a sub-subcommand inside `configcmd`. This resolves the direction's "configcmd or a new discovery-check subcommand" alternative in favor of configcmd.
- **Budgets**: `configcmd` holds 2 non-test Go files (main.go 120 lines, schema.go 96) of the 10-file cap — room for one new file. New functions must stay ≤ 50 lines / complexity ≤ 15 / nesting ≤ 3; `Run`'s switch grows by exactly one case.
- **Wire/contract invariants untouched**: no HTTP routes, no `Err*`, no config keys, no OpenAPI surface are added; no `AGENTS.md` §3 security tables are affected (this is an out-of-band operator tool; the sweep's operator-supplied URL is not a server outbound path, so the SSRF-guarded dialer contract does not apply — same posture as `audit-verify --from-url`).

## 7. Files

### Create

```text
cmd/sso-ctl/configcmd/discovery_check.go — sweep implementation, factored as a
    pure, unit-testable checker: fetchDoc(base, client) + checkDoc(doc, base) []violation,
    plus runCheckDiscovery(args) int (flag parsing, exit codes). Path constants imported
    from shared/core (PathToken/PathJWKS/PathRevoke/PathIntrospect/PathUserInfo/
    PathEndSession) and interfaces/sso (PathOIDCDiscovery, the package that defines it;
    interfaces/sso import is precedented in this module via importcmd) — no literal
    path leaks.
cmd/sso-ctl/configcmd/discovery_check_test.go — acceptance cases 1–9 and 16
    (httptest servers incl. one built from interfaces/sso to pin the stock-doc contract).
```

### Modify

```text
cmd/sso-ctl/configcmd/main.go — add "check-discovery" case to Run's switch; add
    --issuer-allowlist to runValidate; extend the package doc + usage banner
    (stays < 500 lines, ~+30).
cmd/sso-ctl/configcmd/main_test.go — acceptance cases 10–15 (allowlist) appended;
    existing tests untouched.
```

### Do not modify

```text
cmd/sso-ctl/main.go — no new subcommands map entry (fan-out constraint; configcmd
    dispatch is nested under the existing "config" entry).
config/config_load.go, config/config.go, config/schema — no allowlist key (T-9;
    the server-side allowlist key is B4-1's separate server work).
interfaces/sso/*, test/oidc_discovery_test.go — server module; out of scope.
```

## 8. Dependencies and compatibility

- New/changed SPI: none.
- New option/store wiring: none.
- New YAML/env keys: none (CLI flag only).
- Storage migration: none.
- HTTP/proto compatibility: none (read-only operator fetches).
- Rollout/rollback: additive command + additive opt-in flag; removing either restores the previous binary's behavior exactly.

## 9. Documentation

- [ ] `docs/config-reference.md` — not applicable (no config knob; the flag is self-documenting in usage text). If the maintainer prefers a toolbelt page, the usage banner in the configcmd package doc is the single source.
- [ ] `docs/openapi.yaml` — not applicable (no server endpoint).
- [ ] `docs/error-codes.md` — not applicable (no new `Err*`; exit codes follow the existing 0/1/2 convention).
- [x] Feature/deferred-backlog entry: the B4-3 campaign row (implementation-gate.md row 3) is advanced by the operator-facing half; the server-side sweep assertions in `test/`/`interfaces/sso` tests remain the server module's own follow-on.

## 10. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .        # fan-out gate must stay green
go test ./cmd/sso-ctl/... -run 'TestRun_|TestCheck' -v         # new sweep + allowlist cases
go test ./cmd/sso-ctl/configcmd/... -race
make ci
```

Pre-existing failure to report separately: `checks/directory_fanout.py` already fails for `cmd/sso-ctl/` (16 > 15) and three other dirs; the committed Go gate (`TestArchitecture_DirectorySubdirFanout`, ceiling 16) passes today and must remain passing — the constraint this spec relies on.
