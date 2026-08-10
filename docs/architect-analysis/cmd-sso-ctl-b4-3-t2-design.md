# Design: sso-ctl discovery-truthiness sweep + issuer-allowlist pre-check (B4-3/T-2)

Companion to `docs/architect-analysis/cmd-sso-ctl-b4-3-t2-requirements.md`. This
document treats that spec (and the direction it cites) as untrusted evidence,
records what was independently verified, corrects the drift and defects found,
and turns the requirements into a concrete, ordered design with API changes,
compatibility constraints, failure modes, migration steps, and testable
acceptance mapping.

## 1. Evidence verification verdict

Every citation in the spec was re-checked against the tree. The spec's factual
citations are accurate. Three material defects were found in the spec's own
semantics (C1, C2 — they make acceptance case 1 unsatisfiable as written) and
one in its gate-state claim (C3). None invalidates the scope; all three are
incorporated below.

| # | Claim | Verdict |
|---|---|---|
| E1 | `configcmd/main.go` — `Run` switch (validate/schema/validate-schema) at 39–57; `runValidate` 86–112 with `config.Load` at 99; no discovery/sweep/allowlist surface | Confirmed. `usage()` 58–84; `printConfig` factored for testability (114–120). Package doc lists subcommands. |
| E2 | `config/config_load.go:48-71,176-184` — `DefaultServerIssuer = "sso-server"` at 60; applied at 70–71; only sentinel (`sso.DefaultIssuer = "snaplink-sso"`) rejected at 183–184; no allowlist concept in `config/` | Confirmed (exact lines). |
| E3 | `interfaces/sso/server_discovery.go:251-259` — `resolveIssuer` falls back to `requestBaseURL(ctx.Request())` at 255 when unset/sentinel | Confirmed. `requestBaseURL` = `middleware.BaseURL` = `scheme://host[:port]` only, never a path (server_federation.go:40, interfaces/middleware/request_url.go:22-47). |
| E4 | `server_discovery_config.go:142-167` — `buildBaseMetadata`: `token_endpoint = base+PathToken` (146), `jwks_uri` (147), `revocation` (148), `introspection` (149); conditional `userinfo`/`end_session`/`check_session_iframe` (159–165) | Confirmed. |
| E5 | `shared/core/consts.go:21-23` — `PathToken="/token"` (21), `PathIntrospect` (22), `PathRevoke` (23); `PathJWKS` at `shared/core/jwks.go:9` | Confirmed. Also `PathLogin="/auth/login"` (9), `PathUserInfo="/userinfo"` (29), `PathEndSession="/end_session"` (31), `PathPAR` (32), `PathBackchannelAuth` (33), `PathDeviceCode` (27). `PathOIDCDiscovery="/.well-known/openid-configuration"` lives in `interfaces/sso/server_discovery.go:18` (not core) — confirmed. |
| E6 | `rootcov_discovery_test.go:268/278-280` — non-nil-only assertions, no truthiness/equality anywhere in file | Confirmed. Only non-nil `doc["issuer"]/["authorization_endpoint"]/["token_endpoint"]` + ETag/byte-identity checks. |
| E7 | `rg TestOIDCDiscovery` empty (legacy `/authenticate` + `8080:0` defect tests absent) | Confirmed: 0 Go matches; only docs/campaigns prose references remain. |
| E8 | `rg -i "discovery\|sweep" cmd/sso-ctl/` → 0 hits; `audit-verify --from-url` precedent (operator-supplied base URL, `http.Client{Timeout}`, exit 2 on usage) | Confirmed (auditverify/main.go:166; `usageErr` exits 2). |
| E9 | Fan-out ceiling: `cmd/sso-ctl/` has exactly 16 immediate subdirs; Go gate caps at 16 | Confirmed, with drift: the constant `maxSubdirsPerDir = 16` is at `directory_fanout_test.go:35` (spec cited :28 — doc-comment region). `cmd/sso-ctl` is at exactly 16 = cap, so a 17th package fails the gate. |
| E10 | Python mirror (`checks/directory_fanout.py`, `engineering.yaml` `max_subdirs: 15`) already flags `cmd/sso-ctl/` (16 > 15) as pre-existing | Confirmed by execution: `cmd/sso-ctl/ has 16 subdirs (max 15)` plus 4 other dirs. |

### New corrections (C1–C3)

- **C1 — the GET-only probe rule (R1.3) is unimplementable on this server;
  acceptance case 1 is unsatisfiable as written.** Empirically verified against
  a stock server built exactly per `test/oidc_discovery_test.go`'s
  `newDiscoveryServer` (sso.NewServer + httptest):
  GET `/` → **404** (pure API backend, no root route; `buildProbeMux` routes
  "/" into the StdRouter, which registers no "/" pattern),
  GET `/token` → **404** (POST-only),
  GET `/token/introspect` → 404, GET `/token/revoke` → 404, GET `/par` → 404,
  GET `/device/code` → 404.
  The router is `http.ServeMux`-based (`NewStdRouter`, server_routes.go:193-198)
  with method dispatch inside the wrapped handler — method-mismatched requests
  answer **404, not 405**. R1.3's "GET every URL-valued field including
  `issuer`, require ≠ 404" would therefore fail on the four always-present
  POST endpoints and on `issuer` for a healthy stock server, contradicting
  acceptance case 1 ("stock server → exit 0"). Fix (C1a): probe each endpoint
  with GET; **only when GET returns 404, retry once with an empty-body POST**;
  violation iff both 404 (or both fetch-failed). Empty-body POST is
  empirically non-mutating on every credential endpoint: POST `/token` →
  `401 invalid_client`, `/token/introspect` → 401, `/token/revoke` → 401,
  `/par` → `501 par_not_configured`, `/device/code` →
  `501 device_code_not_configured`, `/auth/login` → 415 — all fail validation
  before any store write. Fix (C1b): `issuer` is an *identifier*, not an
  endpoint — RFC 8414 does not require the AS to serve anything at the issuer
  URL, and this server 404s there by design. `issuer` is excluded from
  probing but still subject to the URL/port/path-shape checks (R1.4/R1.5).
- **C2 — acceptance case 7's mechanism is wrong.** The spec's "a route that
  returns 405 on GET (e.g. `/token` mounted POST-only) → exit 0 (405 ≠ 404
  proves route existence)" assumes the router answers method mismatches with
  405. It answers 404 (see C1). The case's *intent* — POST-only routes must
  not fail the sweep — is exactly what C1a's GET-then-POST probe delivers; the
  corrected case 7 asserts the real mechanism: a GET-404/POST-non-404 route
  passes.
- **C3 — gate-state claim is wrong: `TestArchitecture_DirectorySubdirFanout`
  does NOT pass today.** Executed: it fails on `docs/` (18 > 16),
  `docs/architect-analysis/auto/runs` (80 > 16), and the root exempt-dir
  regression (24 > frozen 21). These are pre-existing failures unrelated to
  this change and must be reported separately (AGENTS.md §5.7). The load-
  bearing claim survives: `cmd/sso-ctl` is at exactly 16 = cap, so a 17th
  package would *add* a new failure to that gate; the design therefore adds no
  subdirectory.
- **C4 — `device_authorization_endpoint` is never emitted by this server**
  (0 non-test Go matches for the JSON field; `oidc.ProviderMetadata` has no
  such field — only `pushed_authorization_request_endpoint`,
  `backchannel_authentication_endpoint`, `registration_endpoint`).
  The spec's "when present" clause makes this harmless; the sweep's generic
  field enumeration still handles it for foreign docs.

## 2. API changes

No server, wire, config-key, OpenAPI, or `Err*` surface changes. Two additive
CLI surfaces on the existing `sso-ctl config` dispatch, exit codes following
the package's established 0/1/2 convention.

### 2.1 `sso-ctl config check-discovery --url <base> [--timeout <dur>]` (new)

- `--url` (required): base URL `http(s)://host[:port]`, no path, no trailing
  slash. Trailing slash or a path component is a *violation* (exit 1) — the
  server's `requestBaseURL` never emits one, so any doc built by this server
  cannot match a slashed base (R1.2). Unparseable URL, non-http(s) scheme, or
  empty host is a *usage error* (exit 2).
- `--timeout` (default `10s`, `time.ParseDuration`): bounds the **entire**
  sweep (doc fetch + every probe) via one `context.WithTimeout` shared by all
  requests. Parse failure → usage error (exit 2).
- Exit codes: 0 all assertions pass; 1 any violation/fetch failure (each
  violation printed to stderr as `sso-ctl config: check-discovery: <field>:
  <detail>`); 2 usage error.

Sweep assertions (field table; JSON names from `oidc.ProviderMetadata`,
protocols/oidc/metadata.go:17-33,288-309):

| JSON field | Role |
|---|---|
| `issuer` | shape checks only (R1.4/R1.5); never probed (C1b) |
| `authorization_endpoint` | probe |
| `token_endpoint` | equality `base+core.PathToken` + probe |
| `jwks_uri` | equality `base+core.PathJWKS` + probe |
| `revocation_endpoint` | equality `base+core.PathRevoke` + probe |
| `introspection_endpoint` | equality `base+core.PathIntrospect` + probe |
| `userinfo_endpoint` | equality `base+core.PathUserInfo` when present + probe |
| `end_session_endpoint` | equality `base+core.PathEndSession` when present + probe |
| `check_session_iframe` | probe when present |
| `registration_endpoint` | probe when present |
| `pushed_authorization_request_endpoint` | probe when present |
| `device_authorization_endpoint` | probe when present (never emitted today, C4) |
| `backchannel_authentication_endpoint` | probe when present |

1. **Doc fetch**: GET `<base>/<PathOIDCDiscovery>` (constant imported from
   `interfaces/sso`, server_discovery.go:18); 2xx + valid JSON required, else
   violation naming URL + status/diagnostic.
2. **Equality** (R1.2): exact string equality against `base` trimmed of one
   trailing `/`. Absence of any of the four always-present fields is itself a
   violation. Conditional fields checked only when present.
3. **Probe** (R1.3, corrected per C1a): for every present URL field except
   `issuer`: GET; on 404 only, retry with empty-body POST; violation iff both
   fail with 404 or a fetch error. Any other status (200/204/400/401/405/
   415/500/501…) proves the route is mounted — the T-2 "never 404" contract.
   Deduplicate identical endpoint strings before probing.
4. **No `/authenticate`** (R1.4): parsed path of every advertised URL —
   violation if any path segment equals `authenticate` (segment match, not
   substring, so `/authenticators` does not false-positive).
5. **URL shape** (R1.5): every advertised URL must `url.Parse`, be
   http/https, have a non-empty host, and any explicit port must parse as an
   integer in 1–65535. Catches both `host:0` and the unparseable
   `host:8080:0` double-colon legacy defect.

### 2.2 `sso-ctl config validate --file <yaml> [--print] [--issuer-allowlist <list>]` (extended)

- `--issuer-allowlist`: comma-separated exact-match list of canonical issuer
  strings. Entries trimmed of surrounding whitespace; a present flag whose
  value is empty, or that yields an empty entry (`",,"`), is a usage error
  (exit 2) — matching `--file`-required handling.
- Flag absent ⇒ today's behavior byte-identical (T-9): the flag is not parsed
  unless passed, and the check block is skipped.
- Flag present: after `config.Load` succeeds (defaults applied, sentinel
  rejected by the loader as today), require `cfg.Server.Issuer` to be an
  exact member of the allowlist. Not a member ⇒ stderr
  `sso-ctl config: server.issuer %q is not in the operator allowlist [%s]`,
  exit 1. The defaulted `"sso-server"` fails any allowlist loudly (B4-1
  deploy gate). Check runs before `--print` rendering; on failure nothing is
  printed to stdout.
- `--print` output, `schema`/`validate-schema` behavior, and exit codes for
  all pre-existing paths unchanged.

### 2.3 Wiring and file layout

- `configcmd.Run`'s switch gains exactly one case: `"check-discovery"` →
  `runCheckDiscovery(args[1:])`. No new top-level `subcommands` map entry in
  `cmd/sso-ctl/main.go` (E9: 16-subdir cap), no new package.
- `cmd/sso-ctl/configcmd/discovery_check.go` (new, est. ≤ 300 lines; budget
  check: configcmd non-test files 2 → 3 of 10 cap):
  - `runCheckDiscovery(args []string) int` — flag parsing, context/client
    construction, exit-code mapping (≤ 50 lines);
  - `fetchDiscoveryDoc(ctx, client, base) (map[string]any, error)`;
  - `checkDiscoveryDoc(doc map[string]any, base string) []violation` — pure,
    no I/O; field table + per-role helpers (`checkEquality`, `checkShape`,
    `segmentHasAuthenticate`);
  - `probeEndpoint(ctx, client, raw string) error` — GET-then-POST-on-404;
  - `type violation struct{ field, detail string }`.
  - Path constants imported from `shared/core` (`PathToken`, `PathIntrospect`,
    `PathRevoke`, `PathJWKS`, `PathUserInfo`, `PathEndSession`) and
    `interfaces/sso` (`PathOIDCDiscovery`). No literal path leaks (AGENTS.md
    §6). `configcmd → interfaces/sso` import is precedented in this module
    (importcmd/importer.go:11, generate/templates.go:12) and adds no new
    dependency edge — `interfaces/sso` is already in configcmd's transitive
    deps via `config`; no cycle (interfaces/sso imports no `cmd/*`).
- `cmd/sso-ctl/configcmd/discovery_check_test.go` (new): acceptance cases
  1–9, 16 (httptest; no network).
- `cmd/sso-ctl/configcmd/main.go` (modified, ~+30 lines; stays well under 500
  and `Run` stays low-complexity): switch case + `--issuer-allowlist` in
  `runValidate` + package-doc/usage-banner lines.
- `cmd/sso-ctl/configcmd/main_test.go` (modified): acceptance cases 10–15
  appended; existing tests untouched.
- Do **not** modify: `cmd/sso-ctl/main.go`, `config/*`, `interfaces/sso/*`,
  `test/oidc_discovery_test.go`, `shared/core/consts.go` (no new constants
  needed — all paths already exist), `docs/config-reference.md`,
  `docs/openapi.yaml`, `docs/error-codes.md` (no config knob, no endpoint, no
  new `Err*`).

## 3. Compatibility constraints

- **Byte-identical regressions (T-9)**: `validate` without the new flag,
  `validate --print` output, and `schema` output must be byte-identical to
  HEAD. Guaranteed structurally: no `config.Config`/schema change, no
  reordering of existing prints, allowlist check is a pure post-load gate that
  only runs when the flag is present. Existing tests
  (`TestRun_ValidConfig`, `TestRun_InvalidConfig_Sentinel`,
  `TestRun_MissingFileFlagIsUsageError`, `TestRun_NoSubcommand`,
  `TestRun_UnknownSubcommand`, schema/validate-schema set, help) pass
  unchanged — they are the lock.
- **Fan-out ceiling**: no new subdirectory under `cmd/sso-ctl/` (16 = Go-gate
  cap, E9); no new `subcommands` map entry (map stays 16 entries).
- **Budget ceilings**: `configcmd` grows to 3 non-test files (≤ 10);
  every new function ≤ 50 lines, complexity ≤ 15, nesting ≤ 3; `Run` switch
  +1 case only.
- **No wire/security-surface change**: no routes, no `Err*`, no config keys,
  no OpenAPI. The sweep is an out-of-band operator fetch of an
  operator-supplied URL — the SSRF-guarded server dialer contract does not
  apply (same posture as `audit-verify --from-url`); no `AGENTS.md` §3 table
  is affected.
- **Rollout/rollback**: purely additive; deleting the switch case + flag
  restores the previous binary's behavior exactly. No storage migration, no
  protocol change, no state.
- **Read-only sweep**: the sweep performs no server mutation; empty-body POST
  probes fail validation before any store write (verified empirically, C1a).
  Acceptance case 9 locks body-identity.

## 4. Failure modes

| Mode | Detection | Result |
|---|---|---|
| Discovery fetch: non-2xx (404 on the well-known path, 500, proxy error), non-JSON body, TLS/DNS failure | `fetchDiscoveryDoc` | exit 1, one diagnostic line naming URL + status/error |
| Sweep exceeds `--timeout` (total) | shared ctx deadline | exit 1, `check-discovery: sweep timed out after <dur>` |
| Advertised endpoint unreachable: dial/read error or 404 on both GET and POST | `probeEndpoint` | exit 1, violation naming field + URL |
| Advertised URL with path segment `authenticate` | shape check | exit 1 |
| Advertised URL unparseable (`host:8080:0`), non-http(s), empty host, explicit port 0 or >65535 | shape check | exit 1 |
| `--url` trailing slash or path component | base check | exit 1 (equality still evaluated against trimmed base so no cascading false violations) |
| `--url` unparseable / non-http(s) / empty / missing; `--timeout` unparseable | flag/URL validation | exit 2 |
| `--issuer-allowlist` empty value or empty entry (`",,"`) | flag validation | exit 2 |
| Config load failure (incl. sentinel rejection) with allowlist present | `config.Load` | exit 1, loader's existing message — allowlist never masks loader errors |
| `cfg.Server.Issuer` not in allowlist (incl. defaulted `"sso-server"`) | post-load gate | exit 1, stderr names issuer + allowlist |
| Method-mismatched route (POST-only `/token`; GET-404) | GET-then-POST probe | **passes** (the C1a correction; spec's 405-based case 7 mechanism is wrong, C2) |
| Unauthenticated `userinfo` (GET → 500/401) | probe | passes (≠404 proves mount) |
| `--par`/`/device/code` unwired (501) | probe | passes (route mounted, feature-off status is a config matter, not T-2) |
| Redirect chain to a 404 | probe (client follows) | violation — final target doesn't exist, correct |
| Flaky CI / slow deployment | `--timeout` default 10s | operator raises timeout; violation output is deterministic per run |

Known tradeoff (documented in the checker doc): an AS that answers
unauthenticated `userinfo` with 404 fails the sweep. This server answers
401/500, so the stock contract is unaffected; the tradeoff is inherent to a
no-credential sweep.

## 5. Migration steps (ordered; the tree stays green after each)

1. **Checker core (no wiring)**: add `discovery_check.go` with the pure
   `checkDiscoveryDoc` + `probeEndpoint` + shape helpers, and
   `discovery_check_test.go` driving them against hand-built docs (cases
   2–7, 9's doc-level half). No CLI surface yet — `Run` untouched, so every
   existing test passes.
   Gates: `go build ./... && go vet ./...`; `go test -run
   'TestMaintainability_|TestArchitecture_' .` (must not add new failures;
   C3's pre-existing failures reported separately); `go test
   ./cmd/sso-ctl/configcmd/... -race`.
2. **CLI wiring**: add the `"check-discovery"` case to `Run`, the `--url` /
   `--timeout` flags, exit-code mapping, usage banner + package doc. Add
   end-to-end `Run([...])` tests: stock-server green (case 1, with a local
   replica of `newDiscoveryServer` — same options as
   `test/oidc_discovery_test.go:21-39`; the real helper is unexported and
   importing package `ssotest` from configcmd tests would add a new
   cross-package test dependency for no gain), read-only body identity (case
   9), fetch failures (case 8), usage (case 16).
3. **Allowlist gate**: add `--issuer-allowlist` to `runValidate` + the
   post-load check + usage banner. Append cases 10–15 to `main_test.go`;
   run the full pre-existing `main_test.go` set unchanged (case 15).
4. **Full gates + handoff**: `go test ./... -race`; `go test ./test/ -run
   TestE2E -v`; `make ci`. Report separately the pre-existing failures (C3:
   Go `TestArchitecture_DirectorySubdirFanout` on `docs/` +
   `docs/architect-analysis/auto/runs` + root exempt regression; Python
   `directory_fanout` on `cmd/sso-ctl/` 16>15 and 4 other dirs). Confirm the
   change adds no new gate failures and no new `cmd/sso-ctl` subdir.

## 6. Testable acceptance mapping

All new tests live in `cmd/sso-ctl/configcmd/`; every assertion is
`Run([...])` exit code + captured stderr, httptest-based, no network. A local
`newStockServer(t)` helper mirrors `test/oidc_discovery_test.go`'s
`newDiscoveryServer` construction (sso.NewServer + httptest, WithIssuer +
MemoryClientStore + Ed25519JWTIssuer + jwt strategy). Final helper
construction per C5-R (run artifact `task-1-design-amended.md` §1): **keep
`WithIssuer`** — it overrides only the `issuer` claim (verified empirically:
endpoints derive from `requestBaseURL`, so the replica passes case 1), and
keeping it makes every green test also pin C1b (issuer != swept base is never
probed or equality-checked).

| # | Spec case | Corrected semantics | Test |
|---|---|---|---|
| 1 | Stock server → exit 0, no stderr | Requires C1: GET-only probe would 404 on `/`, `/token`, `/token/introspect`, `/token/revoke` | `TestCheckDiscovery_StockServerGreen` |
| 2 | `token_endpoint` = base+`/v1/token` → exit 1 naming field + expected | unchanged | `TestCheckDiscovery_TokenPathMismatch` |
| 3 | `jwks_uri`/`revocation_endpoint`/`introspection_endpoint` mismatch → exit 1, one violation each | unchanged | `TestCheckDiscovery_PathMismatchPerField` (table-driven, 3 sub-cases) |
| 4 | Advertised endpoint returns 404 (both methods) → exit 1 naming URL | unchanged (probe both methods per C1a) | `TestCheckDiscovery_AdvertisedEndpoint404` |
| 5 | `authorization_endpoint` = `…/authenticate` → exit 1 | unchanged; segment match (no `/authenticators` false positive — extra negative sub-case) | `TestCheckDiscovery_AuthenticateSegment` |
| 6 | `…:0/token` and `…:8080:0/token` → exit 1 both | unchanged (shape checks fire before probing) | `TestCheckDiscovery_ZeroPort`, `TestCheckDiscovery_MalformedPort` |
| 7 | 405 on GET proves route → exit 0 | **Corrected (C2):** router answers method-mismatch with 404; the real mechanism is GET-404 → POST-non-404. The POST-only stock `/token` is the canonical instance (covered by case 1); the case is pinned explicitly | `TestCheckDiscovery_MethodMismatchProbe` (handler: GET 404 / POST 200) |
| 8 | Discovery path 500 or non-JSON → exit 1 with diagnostic | unchanged | `TestCheckDiscovery_Fetch500`, `TestCheckDiscovery_NonJSON` |
| 9 | Discovery body before/after sweep byte-identical (read-only) | unchanged; captured via recording handler | `TestCheckDiscovery_ReadOnlyBodyIdentity` |
| 10 | Allowlist match → exit 0, stdout byte-identical to no-flag run | unchanged | `TestRun_Validate_IssuerAllowlist_Match` |
| 11 | Allowlist mismatch → exit 1, stderr names issuer + allowlist | unchanged | `TestRun_Validate_IssuerAllowlist_Mismatch` |
| 12 | No `server.issuer` (defaults to `"sso-server"`) + allowlist → exit 1 | unchanged (default fails loudly) | `TestRun_Validate_IssuerAllowlist_DefaultFails` |
| 13 | Multi-entry allowlist, either value → exit 0 | unchanged | `TestRun_Validate_IssuerAllowlist_MultiEntry` |
| 14 | `--issuer-allowlist ""` / `",,"` → exit 2 | unchanged | `TestRun_Validate_IssuerAllowlist_EmptyIsUsage` |
| 15 | Pre-change test set passes unchanged | structural guarantee; the 12 existing tests in `main_test.go` (validate/schema/validate-schema/help/usage) are the lock | existing tests, unmodified |
| 16 | `config` no subcommand / unknown subcommand / `check-discovery` without `--url` → exit 2 | + unparseable `--timeout` → exit 2 (extra) | `TestRun_CheckDiscovery_MissingURL`, `TestRun_CheckDiscovery_BadTimeout`; existing no-subcommand/unknown tests |

## 7. Out of scope (unchanged, with corrected justification)

- Server-side `resolveIssuer` Host-fallback removal, `WithIssuer` allowlist
  wiring, and any `config` issuer-allowlist key: B4-1 server work in
  `interfaces/sso`/`config` — separate module. This design only ships the
  operator-facing deploy gate that B4-1's server behavior must satisfy.
- Changes to `test/oidc_discovery_test.go` / `interfaces/sso/rootcov_discovery_test.go`:
  server-module tests; the operator-facing sweep lives in sso-ctl.
- New top-level subcommand / `subcommands` map entry: blocked by the 16-subdir
  ceiling (E9).
- Config keys, `config.Config`/schema changes: would break T-9 byte-identity.
- `/authenticate` route changes, `token_endpoint` form-encoding enforcement
  (T-8(b)), hashcmd cost knob (B4-4): other directions.
- `issuer == base` equality assertion in the sweep: deliberately not added —
  the spec's equality set is the four always-present endpoints plus
  conditional userinfo/end_session; issuer-identity enforcement is B4-1's
  allowlist, not the sweep's job.

## 8. Verification commands

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .        # no NEW failures (C3 pre-existing reported)
go test ./cmd/sso-ctl/... -run 'TestRun_|TestCheckDiscovery' -v
go test ./cmd/sso-ctl/configcmd/... -race -count=10            # race + flake
go test ./test/ -run TestE2E -v
make ci
python checks/directory_fanout.py                              # expect pre-existing FAIL; cmd/sso-ctl unchanged at 16
```
