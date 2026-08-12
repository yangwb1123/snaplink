# Design: cmd/gensdk discovery-truthiness sweep + spec-input purge (B4-3)

Companion to `docs/architect-analysis/cmd-gensdk-b4-3-discovery-truthiness-requirements.md`.
This document treats that spec (and the direction it cites) as untrusted
evidence, records what was independently verified, corrects the drift found,
and turns the requirements into a concrete, ordered design with API changes,
compatibility constraints, failure modes, migration steps, and testable
acceptance mapping.

## 1. Evidence verification verdict

Every citation in the spec was re-checked against HEAD. The spec's factual
citations are accurate — all 11 direction citations and all 8 additional
facts confirmed, including the two material findings it flags itself
(`"/authenticate"` exists in one `cmd/` `_test.go` file; the port assertion is
testable because discovery is request-derived). Three non-material
corrections (C1–C3) are incorporated below. Baselines re-verified by
execution: `go test ./cmd/sso-minimal/ ./cmd/gensdk/` and
`go test ./test/ -run 'TestDiscovery_'` are green at HEAD.

| # | Claim | Verdict |
|---|---|---|
| E1 | `docs/openapi.yaml:54-61` — `servers:` with `http://localhost:8080` "Local dev" entry (55-56); `https://{host}` production entry retained (57-61) | Confirmed (exact lines). Line 30 comment `http://localhost:8088` is docs-serve tooling, different port, untouched. |
| E2 | No gate asserts on `servers:` — no reference in `checks/`, `ops/scripts/`, `CHECKS_REGISTRY.md`; no `servers` handling in `cmd/gensdk` (0 hits) | Confirmed. `sdk_surface.py` validates operationId registry only. |
| E3 | `cmd/sso-minimal/edition_test.go` — `editionServer` helper at 112; five tests; no discovery sweep | Confirmed. 141 lines; tests at 17/39/56/82/99. `assertStatus` at 131, `getJSON` reused by R1. |
| E4 | `server_discovery_config.go:142-159` — `buildBaseMetadata` emits `base+PathLogin/PathToken/PathJWKS/PathRevoke/PathIntrospect` (145-149); `UserInfo`/`EndSession` OIDC-gate-conditional (159) | Confirmed. `CheckSessionIframe` additionally requires `sessionManagementEnabled` (162). |
| E5 | `handleOIDCDiscovery` derives `base := requestBaseURL(ctx.Request())` (server_discovery_config.go:62); alias served by the same handler (`mountDiscovery`, server_discovery.go:26-28) | Confirmed. `PathOIDCDiscovery` at server_discovery.go:18; `PathOAuthAuthorizationServerMetadata` at shared/core/consts.go:68. |
| E6 | `shared/core/consts.go:21-23` (`PathToken`/`PathIntrospect`/`PathRevoke`); `PathJWKS` at jwks.go:9 | Confirmed. Also `PathLogin="/auth/login"` (9), `PathUserInfo` (29), `PathEndSession` (31). |
| E7 | `test/oidc_discovery_test.go:88,200` — absolute-URL prefix coverage only, no suffix/truthiness | Confirmed. `TestDiscovery_EndpointsAreAbsoluteURLs` (prefix `http(s)://` on 7 fields), `TestDiscovery_RespectsXForwardedProto` (prefix only). 13 `TestDiscovery_*` tests green. |
| E8 | Legacy defect tests absent (`TestOIDCDiscovery`/`TestOIDCDiscoveryEndpoint` → 0 hits) | Confirmed (repo-wide `rg`, 0 Go matches). |
| E9 | `"/authenticate"` in `cmd/` — exactly 1 hit: `cmd/sso-ctl/generate/scaffold_contract_test.go:136` (`[]byte("/authenticate")`, `assertNoLegacyPathPort` guard); 0 in non-test cmd/ Go sources | Confirmed. The R2 `_test.go` exclusion is therefore mandatory, not cosmetic. |
| E10 | `edition.go:18-22` — `editionForProfile` maps "standard" → `editionMinimal`; `featureGatesForEdition` gates OIDC via `edition.oidcEnabled()` (app.go:184) | Confirmed. Only two runtime editions exist. |
| E11 | Generator spec input is `docs.OpenAPISpec` (docs/openapi_embed.go:28 embed; cmd/gensdk/main.go:63-70, `parseSpec` at 126) | Confirmed. `parseSpec` uses goccy/go-yaml with `AllowDuplicateMapKey` (already imported — no new dep for the R3 test). |
| E12 | `ops/build/sdk-surface.json` discovery group = 10 ops incl. `getJWKS`/`getOAuthAuthorizationServerMetadata`/`getOpenIDConfiguration`; `cli.py:39` routes `sdk-surface`; `generate` = `go run ./cmd/gensdk --lang=all` (sdk_surface.py:146-151) | Confirmed. |
| E13 | `docs/sdks/` — zero `8080` content; TS `getJWKS`/`getOAuthAuthorizationServerMetadata`/`getOpenIDConfiguration` at client.ts:2957-2976; Python `get_jwks` at client.py:2324 | Confirmed. |
| E14 | Campaign context: `docs/campaigns/implementation-gate.md` row 3 — legacy defect tests must not be carried into the deploy tree; T-2 sweep all green, `token_endpoint == "/token"` | Confirmed. |
| E15 | Budgets: `cmd/gensdk` 7 non-test files (≤10); `cmd/sso-minimal` 10 non-test files (= ceiling — test files exempt); `interfaces/sso` 60 non-test files (= ceiling, untouched) | Confirmed by `ls`/`wc`. |

### Corrections (C1–C3)

- **C1 — `edition_test.go` does not import `shared/core` today.** The spec's
  "edition_test.go imports both" (interfaces/sso + shared/core) is wrong: its
  imports are `domains/tenant`, `interfaces/sso`, `shared/spi`. The R1 sweep
  adds the `shared/core` import (for `PathToken`, `PathJWKS`, `PathLogin`,
  `PathRevoke`, `PathIntrospect`, `PathUserInfo`, `PathEndSession`,
  `PathOAuthAuthorizationServerMetadata`). No new dependency edge: the
  package already imports `shared/core` in production (`op_session.go:16`),
  and `cmd/sso-minimal` is a leaf composition package — import direction
  remains downward.
- **C2 — the minimal/standard discovery document also carries
  `check_session_iframe`.** `serverOptions` wires
  `sso.WithSessionManager(defaultimpl.NewMemorySessionManager())`
  unconditionally (app.go:82), so `sessionManagementEnabled` is true and the
  OIDC-on editions advertise `userinfo_endpoint`, `end_session_endpoint`,
  *and* `check_session_iframe`. The R1 sweep asserts the five unconditional
  `buildBaseMetadata` fields for all rows (the spec's contract) plus
  `userinfo`/`end_session` for the OIDC-on rows (deterministic per the
  edition gate, and a cheap truthiness gain). `check_session_iframe` is
  deliberately **not** asserted: its presence depends on session-management
  wiring, not the edition gate, and the requirements do not claim it.
- **C3 — R3's `:\d+` numeric-port regex has a variable hole.** A future
  dev-style entry `https://{host}:{port}` (variables default `8080`) passes
  the spec's three negatives (no `localhost`, no `127.0.0.1`, no `:\d+`).
  The design closes the drift class, not just the literal: the spec-input
  test additionally rejects any URL containing `8080`, any `{port}`-style
  variable, and any `variables` block whose `host` default is
  `localhost`/`127.0.0.1`. Stricter than the letter of R3; every acceptance
  case still holds (the current spec has only the two verified entries).

## 2. API changes

**No production API changes.** No server route, no CLI surface, no config
key, no `Err*`, no audit event, no wire byte. The only public-contract
artifact touched is `docs/openapi.yaml`'s `servers:` list, which is
informational: verified to be consumed by no generator (`cmd/gensdk` has
zero `servers` handling; `base_url` is a runtime constructor parameter,
gen_py.go:83-84) and by no gate (`sdk_surface` check reads operationIds and
capabilities only). The edit is therefore not an API break by any consumer;
`docs/openapi.yaml` stays the canonical contract and the deleted entry's
information (default listen) remains documented by `cmd/sso-server`'s sample
config, which is explicitly out of scope.

New test API surface (the only "API" this change adds):

| Symbol | Location | Role |
|---|---|---|
| `TestEditionDiscoveryTruthiness` | `cmd/sso-minimal/edition_test.go` (extended) | R1: served-document truthiness sweep across `{prototype, minimal, standard}` |
| `TestDeployTreeNoAuthenticateLiteral` | `cmd/sso-minimal/deploy_tree_test.go` (new, `package main`) | R2: deploy-tree regression lock |
| `TestSpecInputServersAreDeployTruthful` | `cmd/gensdk/spec_input_test.go` (new, `package main`) | R3: spec-input servers lock over `parseSpec(docs.OpenAPISpec)` |

## 3. Compatibility constraints

- **Byte-identical regeneration (R4)**: `python cli.py sdk-surface generate`
  must leave `docs/sdks/` byte-identical (`git diff --exit-code` empty).
  Structurally guaranteed: the generator never reads `servers:`, and the
  embedded spec changes only that list; `emit_test.go`/`schema_test.go` lock
  the emitter. `sdk-surface check` compares operationIds against the edited
  spec — the edit touches only `servers:`, so the registry check is
  unaffected.
- **Embed self-tracking**: `docs.OpenAPISpec` is a `go:embed` of
  `docs/openapi.yaml`; the R3 test re-parses the embedded bytes through the
  production `parseSpec`, so it automatically tracks any future spec edit
  (no regeneration step for the embed, no fixture copy to drift).
- **Edition behavior lock**: R1 depends on the locked prototype contract —
  `TestPrototypeExposesOAuthWithoutOIDC` pins 404 on `PathOIDCDiscovery` and
  a served RFC 8414 alias. R1 does not alter that test; it extends the same
  fixtures (`editionServer`), so edition behavior is asserted, not changed.
- **Hermeticity**: discovery is request-derived (`requestBaseURL`), so the
  httptest ephemeral port is what the served document advertises; R1's port
  assertions need no network, no fixed ports, no `localhost` assumption
  beyond httptest's own `127.0.0.1`.
- **Budgets**: no production Go edits. `cmd/gensdk` non-test files stay 7/10;
  `cmd/sso-minimal` non-test files stay 10/10 (new files are `_test.go`,
  exempt); `interfaces/sso` 60-file ceiling untouched (no edits there at
  all). New functions ≤ 50 lines, complexity trivial (table-driven).
- **Imports**: stdlib only for the new tests (`bytes`, `encoding/json`,
  `io/fs`, `net/http`, `net/http/httptest`, `net/url`, `os`,
  `path/filepath`, `regexp`, `runtime`, `strings`, `testing`) plus the
  already-present `goccy/go-yaml` (via `parseSpec`) in `cmd/gensdk`. No new
  module deps, no `go.mod`/`go.sum` change, no `go.work`, no nested-module
  edits. The R2 walk *reads* nested-module sources under `cmd/` (`sso-mcp`,
  `sso-operator`, `snaplink-billing`) — all verified clean today — but
  writes nothing.
- **Oracle/wire invariants**: untouched — no credential endpoint, no route,
  no error shape, no config; the AGENTS.md §3 tables are unaffected.
- **Rollout/rollback**: purely additive test coverage plus one spec-list
  deletion. Reverting = restore the two lines in `docs/openapi.yaml` and
  delete two test files. No state, no storage, no protocol.

## 4. Failure modes

| Mode | Detection | Result |
|---|---|---|
| R1: any advertised endpoint ≠ `server.URL + core.Path*` (suffix drift, e.g. `/authenticate` re-advertised as `authorization_endpoint`) | field equality | test fails naming field, got, want |
| R1: raw body contains `/authenticate` substring | `bytes.Contains` on raw body | test fails |
| R1: endpoint URL scheme ≠ `http`, empty/non-numeric port, port ≠ live httptest port, or port `8080`/`0` | `net/url` parse + string compare | test fails naming URL — the exact `8080`/`8080:0` legacy defect shapes |
| R1: prototype row — RFC 8414 alias starts 404ing (someone gates the alias behind `oidcGateOn`) | `getJSON`/status check | test fails; the alias-serving contract is locked |
| R1: OIDC-on rows — `userinfo_endpoint`/`end_session_endpoint` drift or become OIDC-gated | equality (C2 additions) | test fails |
| R2: a non-test `cmd/` Go file reintroduces `"/authenticate"` (literal path, not `core.Path*`) | walk + `bytes.Contains` | test fails naming file + line |
| R2: `_test.go` exclusion removed and the scaffold guard (`scaffold_contract_test.go:136`) gets scanned | same walk | fails on day one against the legitimate guard — the documented review invariant (acceptance case 6): the exclusion must stay |
| R2: repo-root resolution wrong (cwd-dependent) | `runtime.Caller`-derived root (same pattern as `scaffold_build_test.go:16`, 3 `Dir` levels from `cmd/sso-minimal/`) | immune by construction; a resolution failure is a test fatal |
| R3: `servers:` re-adds `localhost`/`127.0.0.1`/numeric-port literal/`8080`/`{port}` variable, or variables default to a loopback host | regex + string checks over parsed entries | test fails naming the offending URL |
| R3: `servers:` empties or the `https://{host}` entry is removed | count check (exactly 1) | test fails — the production entry is part of the contract |
| R3: `servers:` moves out from under `doc["servers"]` (restructure) or `parseSpec` breaks | type-assertion failure / parse error | test fails (parse error is a fatal, naming the cause) |
| R4: generator output drifts (nondeterminism, emitter change) | `git diff --exit-code docs/sdks/` | CI diff fails; pre-existing emitter tests (`emit_test.go`) also lock this |
| R4/R5: `sdk-surface check` red for an unrelated operationId drift | registry check | report separately per AGENTS.md §5.7 if pre-existing; this change cannot cause it (`servers:` is unreferenced) |

Known accepted limitation (documented, not silent): R2 scans the literal
`"/authenticate"` only — a concatenation-based reintroduction
(`"/auth" + "enticate"`) passes the guard. That is intentional: the guard is
a regression lock over the deploy tree, and the *behavioral* truthiness gate
is R1, which catches any such route at the served-document level regardless
of how the path was constructed. Same posture as the existing
`assertNoLegacyPathPort` scaffold guard.

## 5. Migration steps (ordered; the tree stays green after each)

1. **Spec purge (R3 edit only)**: delete lines 55-56 of `docs/openapi.yaml`
   (`- url: http://localhost:8080` + its description). Verify
   `grep -n 'localhost:8080' docs/openapi.yaml` → 0 hits; the
   `https://{host}` entry and the line-30 `8088` docs-serve comment are
   untouched. No Go change — `go build ./...` trivially green; the embed
   picks the edit up on next compile.
   Gate: `grep -n 'localhost:8080' docs/openapi.yaml` (0 hits),
   `go build ./... && go vet ./...`.
2. **Spec-input lock (R3 test)**: add `cmd/gensdk/spec_input_test.go`
   (`TestSpecInputServersAreDeployTruthful`; `parseSpec(docs.OpenAPISpec)`;
   assertions per §4 R3 rows; exactly-one-`https://{host}` count).
   Gate: `go test ./cmd/gensdk/ -run TestSpecInputServersAreDeployTruthful -v`.
3. **Edition sweep (R1)**: extend `cmd/sso-minimal/edition_test.go` with
   `TestEditionDiscoveryTruthiness` — three-row table
   `{prototype → core.PathOAuthAuthorizationServerMetadata, minimal →
   sso.PathOIDCDiscovery, standard → sso.PathOIDCDiscovery}` via
   `editionForProfile`; reuse `editionServer`; add the `shared/core` import
   (C1). Five unconditional fields asserted for every row; `userinfo`/
   `end_session` additionally for OIDC-on rows (C2); raw-body
   `/authenticate` absence; per-URL `net/url` port truthiness vs the live
   httptest port.
   Gate: `go test ./cmd/sso-minimal/ -run TestEditionDiscoveryTruthiness -v`
   then the full package (`go test ./cmd/sso-minimal/ -race`).
4. **Deploy-tree guard (R2)**: add `cmd/sso-minimal/deploy_tree_test.go`
   (`TestDeployTreeNoAuthenticateLiteral`; `runtime.Caller` root; `WalkDir`
   over `cmd/`; skip `_test.go`; report file + line via `bytes.Index` +
   newline count). The `_test.go` exclusion is load-bearing (C/E9).
   Gate: `go test ./cmd/sso-minimal/ -run TestDeployTreeNoAuthenticateLiteral -v`.
5. **Regeneration stability (R4)**: `python cli.py sdk-surface generate &&
   python cli.py sdk-surface check`; `git diff --exit-code docs/sdks/` must
   be empty.
   Gate: both exit 0 and the diff is empty.
6. **Full gates + handoff**: `go build ./... && go vet ./...`;
   `go test -run 'TestMaintainability_|TestArchitecture_' .`;
   `go test ./test/ -run 'TestDiscovery_' -v` (R5);
   `rg -n 'TestOIDCDiscovery|TestOIDCDiscoveryEndpoint' -g '*.go'` → 0 hits
   (R5 absence, review-time); `go test ./... -race`; `make ci`. Report any
   pre-existing failure separately (AGENTS.md §5.7).

## 6. Testable acceptance mapping

| # | Spec case | Semantics | Test + assertion |
|---|---|---|---|
| 1 | prototype row: served alias doc is truthful | RFC 8414 alias served for prototype (OIDC discovery 404 is the locked gate) | `TestEditionDiscoveryTruthiness/prototype` — fetch `server.URL+core.PathOAuthAuthorizationServerMetadata`; 5 unconditional fields byte-equal `server.URL+core.Path*`; no `/authenticate` in raw body; each URL's parsed port == httptest port, `!= 8080`, `!= 0` |
| 2 | minimal + standard rows: same truthiness | both resolve to `editionMinimal` via `editionForProfile` | `TestEditionDiscoveryTruthiness/minimal`, `/standard` — fetch `server.URL+sso.PathOIDCDiscovery`; same 5-field + port + substring assertions; plus `userinfo_endpoint`/`end_session_endpoint` equality (C2) |
| 3 | regression: `/authenticate` or hardcoded port re-advertised → sweep fails naming field + expected constant | the sweep's assertion message is the contract | message-format sub-assertions baked into the per-field `t.Errorf` (field, got, want); verified by code review, exercised by the mismatch paths of cases 1-2 |
| 4 | deploy tree at HEAD → 0 offenders | pure regression lock; verified 0 non-test hits today | `TestDeployTreeNoAuthenticateLiteral` — walk `cmd/`, skip `_test.go`; offender list empty; also asserts the walk actually visited files (sanity count > 0, so a root-resolution bug fails loudly, not vacuously) |
| 5 | future non-test reintroduction → fails naming file | compile-time corollary: a `core.Path*` reintroduction is inherently safe (`PathLogin = "/auth/login"`) | the same guard; failure path exercised by construction (test data = HEAD tree, currently clean) |
| 6 | review invariant: `_test.go` exclusion keeps case 4 true | the scaffold guard at `scaffold_contract_test.go:136` is the only `"/authenticate"` holder; scanning tests would fail on day one | documented invariant; a review-time `rg` on the final diff confirms the exclusion line exists |
| 7 | edited spec → no loopback/numeric-port URL; exactly one `https://{host}` | plus C3 strengthenings (no `8080` literal, no `{port}` variable, variables `host` default not loopback) | `TestSpecInputServersAreDeployTruthful` — parse `docs.OpenAPISpec` via production `parseSpec`; `servers` non-empty; per-entry url checks; host-count == 1; variables-default check |
| 8 | future re-add of a dev server entry → fails naming URL | same test | message names the offending `url` value |
| 9 | `sdk-surface generate && check` exit 0 | registry vs edited spec stays consistent | run via `python cli.py sdk-surface generate && python cli.py sdk-surface check` (step 5) |
| 10 | `git diff --exit-code docs/sdks/` empty after generate | wire shape byte-identical incl. `getJWKS`/`getOAuthAuthorizationServerMetadata`/`getOpenIDConfiguration` + `OpenIDConfiguration`/`JWKS` types (client.ts:2957-2976, client.py:2324) | step 5 gate |
| 11 | `go test ./test/ -run 'TestDiscovery_'` green unchanged | `TestDiscovery_EndpointsAreAbsoluteURLs`, `TestDiscovery_RespectsXForwardedProto`, 11 siblings — zero edits to `test/oidc_discovery_test.go` | step 6 gate; baseline re-verified green at HEAD |
| 12 | review-time: `TestOIDCDiscovery`/`TestOIDCDiscoveryEndpoint` stay absent | absence, no gate can fail on a non-test | `rg -n 'TestOIDCDiscovery|TestOIDCDiscoveryEndpoint' -g '*.go'` → 0 hits in the final diff review |

Grade: 12/12 as stated by the spec — cases 1-5, 7-11 fail on regression under
a named gate; case 6 is a design invariant (vacuous as a failing test, kept
as a review check); case 12 is review-time absence. No case is weakened by
C1–C3; C2 adds assertions to cases 1-2, C3 adds assertions to cases 7-8.

## 7. Out of scope (unchanged, with justification)

- `interfaces/sso/*`, `shared/core/*`, `protocols/*`: the server is already
  truthful (`buildBaseMetadata` = `requestBaseURL + core.Path*`); this
  change only locks that behavior with tests. No edits.
- `test/oidc_discovery_test.go` + `interfaces/sso/rootcov_discovery_test.go`:
  server-module coverage; the B4-3/T-2 deploy-tree sweep is the
  sso-minimal/gensdk pair, per the direction's module split (the sso-ctl
  sweep is the sibling direction, `cmd-sso-ctl-b4-3-t2-design.md`).
- Legacy defect tests: deliberately not recreated — the absence (R5) is
  itself the contract (campaign gate row 3).
- Port/`8080` sweep inside the R2 deploy-tree guard: the requirements scope
  it to `/authenticate` only; ports are covered by R1 (served doc) and R3
  (spec input). The existing `assertNoLegacyPathPort` scaffold guard
  (scaffold_contract_test.go:134-147) already covers generated-scaffold
  ports and stays untouched.
- `cmd/sso-server/config.yaml` (`base_url: http://localhost:8080`): a
  sample-config value, not the generator's input; the direction's drift is
  the spec entry only.
- Issuer/allowlist work (B4-1), `resolveIssuer`, `WithIssuer`: separate
  direction; the discovery doc's `issuer` field is not asserted here (it is
  also request-derived today; issuer truthiness policy is B4-1's job).
- `docs/config-reference.md`, `docs/error-codes.md`, `docs/feature-matrix.md`:
  no new config, errors, or features.

## 8. Verification commands

```bash
grep -n 'localhost:8080' docs/openapi.yaml          # 0 hits after step 1
go build ./... && go vet ./...
go test ./cmd/gensdk/ -run TestSpecInputServersAreDeployTruthful -v
go test ./cmd/sso-minimal/ -run 'TestEditionDiscoveryTruthiness|TestDeployTreeNoAuthenticateLiteral' -v
go test ./cmd/sso-minimal/ ./cmd/gensdk/ -race
python cli.py sdk-surface generate && python cli.py sdk-surface check
git diff --exit-code docs/sdks/                     # empty
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./test/ -run 'TestDiscovery_' -v
rg -n 'TestOIDCDiscovery|TestOIDCDiscoveryEndpoint' -g '*.go'   # 0 hits (review-time)
go test ./... -race
make ci
```
