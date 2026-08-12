# Requirements Spec: raise the scaffold verification gate from bare `go build` to vet plus contract/sweep assertions

- Direction: entry 2 of `docs/architect-analysis/auto/analyses/cmd-sso-ctl-generate-3176af89.json` (selected; the prior `auto/SUMMARY.md` rejection predates the acceptance checks now supplied with this selection — the acceptance section below resolves that gap)
- Module: `cmd/sso-ctl/generate` (`verify.go`, `scaffold_build_test.go`, `templates_handler.go`)
- Status: requirements (evidence-verified against HEAD)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `cmd/sso-ctl/generate/verify.go` — `verifyGeneratedBuild` runs bare `go build` only | Function at line 27: `exec.Command("go", "build", target)` (line 35), no vet, no content checks; error path wraps build output only. `--skip-build-check` (cmd.go, `--skip-build-check` flag at lines 61–62) skips it entirely | Confirmed |
| `cmd/sso-ctl/generate/scaffold_build_test.go` — `TestGeneratedScaffoldsCompile` runs `go build ./...` in an isolated module, no vet/pattern checks | Test at line 64; per-kind subtests (authenticator/store/handler/grant) each `Generate` into a temp module (`newBuildableModule`, lines 28–55, real-module replace + copied go.sum, `GOFLAGS=-mod=mod GOPROXY=off`) then run bare `go build ./...` (lines 107–116). No vet, no file-content assertions. Generated filenames per `generate.go`: `%s.go` (auth), `%s_store.go`, `%s_handler.go`, `%s_grant.go` (raw `s.Name`). Baseline gate passes at HEAD (`go test -run TestGeneratedScaffoldsCompile` → ok, 0.085s) | Confirmed |
| `cmd/sso-ctl/generate/templates_handler.go` — `core.ErrorBody("not_implemented")` unregistered in `docs/error-codes.md` and `shared/core/consts.go` | `grep -rn "not_implemented" docs/error-codes.md shared/core/consts.go` → 0 hits (exit 1); the only Go-tree occurrence is `templates_handler.go` (lines 64, 86, 95, 104 — the four 501 stub bodies) | Confirmed |
| Handler template's POST example binds via `ctx.Bind` with no Content-Type guard | `handle{{.Name}}Post` example (lines 71–82): `ctx.Bind(&req)` at line 73; no `Content-Type`/`application/x-www-form-urlencoded` occurrence anywhere in the template | Confirmed |
| `TestOIDCDiscovery`/`TestOIDCDiscoveryEndpoint` zero matches in tree | `grep -rn "TestOIDCDiscovery" --include="*.go" .` → exit 1 (0 matches) | Confirmed — deletion is moot here; the legacy defect shapes (`/authenticate`, `8080:0`) are the sweep patterns this spec asserts against generated output (T-2 mirror) |
| `interfaces/sso/server_discovery.go:251` + `shared/core/consts.go:9,21-23` — discovery truthiness anchors | `resolveIssuer` at server_discovery.go:251 (Host fallback at 255); consts.go:9 = `PathLogin`, 21–23 = `PathToken`/`PathIntrospect`/`PathRevoke`. consts.go holds 143 `Path*` constants (campaign row 3 cites exactly these anchors) | Confirmed |
| Registered-set extractability | `docs/error-codes.md` has 250 rows of the form `\| \`code\` \|` (first-column backticked code, regex `^\| \`[a-z_][a-z0-9_]*\``); `shared/core/errors.go` declares `ErrX = "code"` pairs (`ErrInvalidRequest` 81, `ErrInternal` 95, `ErrNoTokenStrategy` 115, `ErrInvalidGrant` 165, `ErrNotFound` 198, `ErrNotSupported` 199). Precedent for 501 + registered code: `interfaces/admin/governance.go:462` (`ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrNotSupported))`) | Confirmed — both the doc set and the constant map are mechanically parseable from `repoRoot` |
| Drift inventory of unregistered codes emitted by the handler template | Beyond `not_implemented` (×4): `method_not_allowed` (line 45, the 405 default branch) and `create_failed` (line 79, commented POST example) are also absent from the doc set (`grep -qE '^\| \`method_not_allowed\`' docs/error-codes.md` → exit 1, same for `create_failed`). The grant template emits only `core.Err*` constants (`ErrInvalidGrant` in code; `ErrInvalidRequest`/`ErrNoTokenStrategy`/`ErrInternal` in the commented example) — all registered. Authenticator/store templates emit no `ErrorBody` calls and no path/port literals | New finding, same drift class — folded into R2a |
| Inline path literal inventory | The only slash-prefixed quoted literal in all template output is `"/path"` in the handler doc comment (templates_handler.go:30, `router.GET("/path", ...)`). No `8080`, no `:0`, no `/authenticate`, no URL-with-explicit-port occurs in any template | Confirmed — R3a's fix surface is exactly one comment |
| T-2 / T-8(b) mapping | `docs/campaigns/implementation-gate.md` row 3 (B4-3): T-2 = "sweep 全绿（广告端点绝不 404）；`metadata.token_endpoint == "/token"`" with legacy `TestOIDCDiscovery`/`TestOIDCDiscoveryEndpoint` (asserting `/authenticate` and the `8080:0` bug) not to be carried into the deploy tree; row 4 (B4-4): T-8(b) = Content-Type enforced form-urlencoded (JSON → 400). The deploy-tree sweep itself is `cmd-sso-ctl-b4-3-t2`'s module (its own spec, committed); this direction mirrors the *assertion style* onto generated output | Confirmed |

Net: all direction claims hold. The gate is compile-only at both surfaces; the drift it fails to catch is real and slightly wider than the direction states (`method_not_allowed`, `create_failed` join `not_implemented`); the fix surface for the literal-path ban is a single doc comment; the error-code registry and constant map are mechanically parseable for a test.

## 2. Goal and user outcome

`sso-ctl generate`'s only regression lock is compilation: `verifyGeneratedBuild` (generation time) and `TestGeneratedScaffoldsCompile` (CI) run bare `go build`, so a template edit can silently reintroduce exactly what B4-3/B4-4 forbid — unregistered error codes, legacy `/authenticate` paths, `8080:0`-class port literals, inline path strings instead of `shared/core/consts.go` `Path*` constants, body binding with no Content-Type guard — and still pass every gate. That drift is already present at HEAD (R2a's inventory).

Completion marker: a template regression in any of the four kinds that (a) breaks compilation or vet, (b) emits an error code outside the registered set, (c) reintroduces a legacy path/port pattern or an inline path literal, or (d) drops the form-urlencoded Content-Type guard from the generated POST handler path, fails `TestGeneratedScaffoldsCompile` with a named assertion — and generation-time `verifyGeneratedBuild` vets the output in addition to building it.

## 3. Product boundary

- Surface: `cmd/sso-ctl/generate` (templates, `verify.go`, `cmd.go` flag help, the regression test). No server, protocol, config, or docs-registry changes under the default mapping.
- Default: gate raising is unconditional (the test runs in the existing suite; `verifyGeneratedBuild` vets unless `--skip-build-check`); template text changes alter the output of *new* scaffolds only.
- Explicit non-goals (do not implement):
  - No server-side Content-Type enforcement: `protocols/oauth/oauthwire/bind.go`, `interfaces/sso/server_token*.go` etc. are B4-4's own module (see `cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-requirements.md`). The scaffold only *teaches* the guard posture (R4); it does not enforce anything at runtime.
  - No live discovery sweep in this module: the deploy-tree `sso-ctl config check-discovery` sweep is `cmd-sso-ctl-b4-3-t2`'s deliverable (its spec is committed). This direction mirrors the sweep's assertion *patterns* onto generated output.
  - No new scaffold kinds, no new CLI flags (the `--skip-build-check` flag keeps its name and semantics, only its help text widens).
  - No changes to `grantTemplate`'s teaching content (scope gate / tenant binding / roles markers are entry 1's territory, `cmd-sso-ctl-generate-b4-1-2-grant-scaffold-requirements.md`; not landed at HEAD — this spec must not depend on them, and it does not: its grant-kind assertions are registration/path/port-only).
  - No changes to `templates.go` (authenticator/store templates emit no `ErrorBody` calls, no path or port literals — verified; nothing to assert against or fix there).
  - No new `Err*` constants under the default mapping (R2a's precedent mapping reuses registered codes). Registering new codes is permitted only as an explicitly-labeled alternative, with `docs/error-codes.md` + `shared/core/errors.go` updated in the same change (AGENTS.md §5.6).

## 4. Module classification

- [x] Infrastructure/config/deployment (scaffolding tooling)
- [ ] OAuth/OIDC protocol flow · [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Authorization · [ ] Cold module · [ ] Refactoring only

Owning layer/package: `cmd/sso-ctl/generate` (composition layer). No import-graph change: the new helpers read `docs/error-codes.md`, `shared/core/errors.go`, `shared/core/consts.go` via `repoRoot(t)` file paths (the pattern `newBuildableModule` already uses), they do not import those packages.

## 5. Requirements

### R1 — Vet joins the gate at both surfaces

- **R1a (CI gate, acceptance-pinned)**: each kind subtest of `TestGeneratedScaffoldsCompile`, after `Generate`, runs `go vet ./...` in the isolated module with the same environment as the existing build (`GOFLAGS=-mod=mod`, `GOPROXY=off`) and requires it to succeed, alongside the existing `go build ./...` (which stays). Vet failure fails the subtest with the vet output.
- **R1b (generation-time gate, title's "raise the gate" applied to `verifyGeneratedBuild`)**: `verifyGeneratedBuild` (verify.go) runs `go vet` on the target in addition to `go build` (same `./`-prefix path logic). `--skip-build-check` skips both; exit codes (0/1) and the error-message shape are unchanged. The flag's help text in cmd.go ("Skip running 'go build' on the generated output") widens to name the build+vet check.

Rationale for the split: the contract/sweep assertions (R2–R4) require `docs/error-codes.md` and the `shared/core` constant files, resolvable only from the repo root; `verifyGeneratedBuild` may run against an output dir outside the repo. So vet is generation-time; the content assertions are CI-time. This matches the direction's "vet plus contract/sweep assertions" division.

### R2 — Every `core.ErrorBody` code in generated output is in the registered set

For each generated file (all four kinds, comment text included — the teaching comments are part of the generated artifact), every `ErrorBody(...)` occurrence must resolve to a code registered in `docs/error-codes.md`:

- Raw-string form `ErrorBody("code")` → `code` must be a first-column backticked code in the doc (regex `^\| \`[a-z_][a-z0-9_]*\``; 250 rows at HEAD).
- Constant form `ErrorBody(core.ErrX)` → resolve `ErrX` through the `ErrX = "code"` declarations in `shared/core/errors.go`, then check the doc set the same way.
- A code in neither form (unresolvable constant, or constant absent from errors.go) is a failure naming the symbol.

**R2a — handler template conformance (drift fix)**: `templates_handler.go` stops emitting unregistered codes. Default mapping, reusing registered codes with repo precedent:

- The four 501 stubs: `core.ErrorBody("not_implemented")` → `core.ErrorBody(core.ErrNotSupported)` (`not_supported` registered; 501 + `ErrNotSupported` is the repo's own shape at `interfaces/admin/governance.go:462`).
- The 405 default branch: `core.ErrorBody("method_not_allowed")` → a registered code (default choice `core.ErrInvalidRequest`; alternatively register a `method_not_allowed` code — doc + errors.go in the same change).
- The commented POST example's `core.ErrorBody("create_failed")` → `core.ErrorBody(core.ErrInternal)` (registered; the example already uses `http.StatusInternalServerError`).
- All emitted codes are `core.Err*` constants, never raw string literals (AGENTS.md §6 literal discipline; `grantTemplate` already models this). The commented GET example's `"not_found"` and `"invalid_request"` are already registered and may stay raw or move to constants.

### R3 — No legacy path/port patterns; no inline path literals

For each generated file (all four kinds), assert:

1. No `/authenticate` occurrence (slash-prefixed legacy login path; the modern route is `core.PathLogin = "/auth/login"`).
2. No `8080` literal; no quoted URL authority with an explicit numeric port (regex `https?://[^"/]*:[0-9]+` — catches `host:8080`, `host:0`, and the unparseable double-colon `host:8080:0` form); no `host:port:port` double-colon shape.
3. No slash-prefixed quoted string literal (inline endpoint-path literal). Endpoint paths in generated output may appear only as `core.Path*` constant references, and every `Path*` symbol referenced must exist in `shared/core/consts.go`'s `Path*` const block (143 constants at HEAD) — a typo'd or removed constant fails the gate.

**R3a — template conformance**: the only offending literal is the handler doc comment `router.GET("/path", ...)` (templates_handler.go:30). Reword the wiring comment to teach the path-constant source without a literal — e.g. cite that route paths must be `core.Path*` constants from `shared/core/consts.go` (the composition-root wiring example may reference a real constant). No other template contains a slash-prefixed literal (verified); `templates.go`'s `"https://idp.example.com/auth?state=..."` comment is a full URL with no port and no `/authenticate` segment — it satisfies R3 as-is.

### R4 — Form-urlencoded Content-Type guard in the generated POST handler path (T-8(b) mirror)

The generated handler file (`webhook_handler.go` for the test case) must contain, in its POST path:

- the media-type literal `application/x-www-form-urlencoded`, and
- a Content-Type check on the request header (`Header.Get("Content-Type")` or the canonical form B4-4's server work settles on), positioned before any `ctx.Bind(` occurrence in the file (ordering via `strings.Index` comparison, mirroring entry 1's A1 style).

**R4a — template conformance**: `handle{{.Name}}Post`'s commented example (templates_handler.go:71–82) teaches the guard before `ctx.Bind(&req)` — repo precedent for the check shape is `interfaces/sso/server_login_resolve.go:425` (`strings.HasPrefix(r.Header.Get("Content-Type"), ...)`). The `strings` import joins the generated handler's import block. Scope note: the guard requirement applies to the handler kind only — the grant kind's `Handle` receives an already-bound `oauth.TokenRequest` (body binding is the server's `bindOAuthParams` surface, B4-4's own module), and the authenticator/store kinds have no HTTP handler path.

### R5 — Assertion structure and mutation testability

- The content assertions live in the test (not `verifyGeneratedBuild`): they need `repoRoot` to resolve the doc and constant files (R1 rationale).
- Each assertion is a separately named check with its own failure message naming the violated invariant and the offending literal/code, so a template regression fails with the exact violated contract (mutation coverage, cases 6 below).
- Assertions run on the generated artifact (which embeds the template's comment text verbatim), not on the template source, so a template regression fails the gate exactly as the direction requires.

### Testable acceptance (Given/When/Then)

1. Given each of the four kind subtests of `TestGeneratedScaffoldsCompile`, when the test runs, then `go vet ./...` executes in the isolated module and passes in addition to the existing `go build ./...` (R1a). Mutations: a generated file with a vet violation (e.g. an unused variable) fails the subtest.
2. Given generated output containing `core.ErrorBody("not_implemented")`, `core.ErrorBody("method_not_allowed")`, or `core.ErrorBody("create_failed")` — in code or in a comment, any kind — when the contract assertions run, then the test fails naming the unregistered code (R2). At HEAD this case FAILS for the handler kind; R2a's template fix makes it pass.
3. Given a generated file containing `core.ErrorBody(core.ErrNoSuchConst)` (constant absent from `shared/core/errors.go`), when assertions run, then the test fails naming the symbol (R2 constant-resolution path).
4. Given generated output containing `/authenticate`, the literal `8080`, a quoted `https://host:PORT/...`, or a slash-prefixed quoted path literal, when assertions run, then the test fails naming the pattern (R3). At HEAD the only offending literal is `"/path"` in the handler doc comment; R3a removes it.
5. Given a generated handler file whose POST path binds via `ctx.Bind(` with no preceding `application/x-www-form-urlencoded` Content-Type check, when assertions run, then the test fails (R4); given the fixed template, then it passes (R4a).
6. Given each template mutation — unregistered code reintroduced; `/authenticate` or `8080` or `":8080"`-style port literal reintroduced; `"/path"` literal reintroduced; Content-Type guard dropped from the POST example — when `go test ./cmd/sso-ctl/generate/` runs, then exactly the corresponding named assertion fails (mutation coverage of R2–R4).
7. Given `sso-ctl generate handler --name webhook --package internal/handler` (skip-build-check absent), when it runs against the fixed templates, then generation succeeds and the output is vetted at generation time (R1b); with `--skip-build-check`, then neither build nor vet runs, exit 0, output otherwise unchanged (T-9).
8. Given the pre-change behavior set — all four kinds generate and compile; unknown kind → exit 2; missing `--name`/`--package` → exit 2; build-check failure → exit 1 — when the change lands, then all still hold (T-9).
9. Given `docs/error-codes.md` at HEAD, when the registered set is extracted with the `^\| \`code\`` row regex, then exactly 250 codes are extracted and the set contains every code the fixed templates emit (`invalid_request`, `invalid_grant`, `internal_error`, `not_found`, `no_token_strategy`, `not_supported`).

Mapping: R2+R3 mirror the T-2 sweep's truthiness style (advertised endpoints never 404; no `/authenticate`; no `8080:0`-class ports; `token_endpoint == /token` via `Path*` constants) applied to generated output; R4 mirrors T-8(b) (form-urlencoded Content-Type enforced) as scaffold teaching. Wire-level T-2/T-8(b) remain the B4-3/B4-4 server deliverables.

## 6. Engineering-gate constraints (verified)

- **Budgets**: `verify.go` is 40 lines; the added vet exec keeps `verifyGeneratedBuild` ≤ 50 lines (~40). `scaffold_build_test.go` is 122 lines; assertion helpers go into a new test-only file `scaffold_contract_test.go` (test files do not count toward the 10-file non-test cap; the directory stays at 5 non-test files). `templates_handler.go` is 215 lines, grows to ~250 (cap 500). New test functions ≤ 50 lines / complexity ≤ 15 / nesting ≤ 3 (guard-style helpers).
- **Fan-out**: `cmd/sso-ctl/` has 16 immediate subdirs (gate ceiling 16; the Python mirror already flags it at 15+). No new directories are created — no fan-out change.
- `interfaces/sso` 60-file ceiling untouched.
- **No new `Err*` under the default mapping** (R2a reuses registered codes); if the design instead registers `method_not_allowed`, the same change updates `docs/error-codes.md` + `shared/core/errors.go` (AGENTS.md §5.6).
- **Wire/security contracts untouched**: no HTTP routes, no `oauthwire`/binding behavior, no credential-endpoint semantics change (B4-4's server enforcement is its own module). `verifyGeneratedBuild`'s failure path stays exit 1 with the same caller message shape.
- Baseline at HEAD: `go test ./cmd/sso-ctl/generate/ -run TestGeneratedScaffoldsCompile` passes (ok, 0.085s) — the new assertions must keep it green after the template fixes.

## 7. Files

### Create

```text
cmd/sso-ctl/generate/scaffold_contract_test.go — test-only helpers, each a
    small named assertion: registeredSet(t, root) (parse docs/error-codes.md
    `| `code` |` rows), resolveErrCode (parse shared/core/errors.go
    ErrX = "code" pairs), assertRegisteredErrorCodes, assertNoLegacyPathPort,
    assertNoPathLiterals (incl. Path* existence check against
    shared/core/consts.go), assertFormContentTypeGuard; per-file scan of the
    generated artifact with named failures.
```

### Modify

```text
cmd/sso-ctl/generate/scaffold_build_test.go — each kind subtest: after
    Generate, read the generated file (filename rule per generate.go), run
    the R2/R3 assertions (all kinds) and R4 (handler kind), then the existing
    `go build ./...` plus a new `go vet ./...` (same env), both required.
cmd/sso-ctl/generate/verify.go — verifyGeneratedBuild: `go vet` alongside
    `go build` on the target (same ./ path logic), combined failure message.
cmd/sso-ctl/generate/cmd.go — widen the --skip-build-check help text to name
    the build+vet check (no flag semantics change).
cmd/sso-ctl/generate/templates_handler.go — R2a: replace not_implemented ×4,
    method_not_allowed, create_failed with registered core.Err* codes
    (default mapping in R2a); R3a: reword the router.GET("/path", ...) doc
    comment to teach core.Path* constants without a literal; R4a: add the
    form-urlencoded Content-Type guard before ctx.Bind in the POST example
    (+ strings import in the generated import block).
```

### Do not modify

```text
cmd/sso-ctl/generate/templates.go — authenticator/store templates: no
    ErrorBody calls, no path/port literals (verified); leave untouched.
cmd/sso-ctl/generate/templates_handler.go grantTemplate — entry 1's
    teaching content (GrantedScopes/TenantID/roles markers) is that
    direction's territory; only the shared code-registration invariant in
    R2 applies to its output (already satisfied: ErrInvalidGrant +
    commented ErrInvalidRequest/ErrNoTokenStrategy/ErrInternal all
    registered).
protocols/oauth/oauthwire, interfaces/sso/server_token*.go — B4-4 server
    enforcement, its own module.
docs/error-codes.md, shared/core/errors.go — unchanged under the default
    mapping (R2a reuses registered codes).
```

## 8. Dependencies and compatibility

- New/changed SPI: none. New option/store wiring: none. New YAML/env keys: none. Storage migration: none.
- HTTP/proto compatibility: none — no server surface changes; this module is scaffolding tooling.
- Rollout/rollback: pure generator + test change. Generated output text changes for NEW scaffolds only (already-generated files are untouched). Reverting the template/verify changes restores prior behavior exactly; `--skip-build-check` remains the operator bypass.
- Sequencing: entry 1 (grant scaffold teaching content) may land before or after this spec — R2–R4 do not reference its markers; if entry 1 lands first, its markers must themselves satisfy R2 (they use registered codes) and R3 (no literals) — no interaction.

## 9. Documentation

- [ ] `docs/openapi.yaml` — not applicable (no server endpoint).
- [ ] `docs/error-codes.md` — not applicable under the default mapping (the scaffold now emits only registered codes; no new codes). If the design registers `method_not_allowed`, the doc row lands in the same change.
- [ ] `docs/config-reference.md` — not applicable (no config knob).
- [x] Campaign traceability: advances `docs/campaigns/implementation-gate.md` row 3 (B4-3/T-2) on the generated-output axis — the scaffold can no longer reintroduce the `/authenticate`/`8080:0` defect shapes the legacy `TestOIDCDiscovery*` tests locked (absent from this tree, verified) — and row 4 (B4-4/T-8(b)) on the scaffold-teaching axis. The wire-level sweep (`sso-ctl config check-discovery`) and credential-endpoint enforcement remain the B4-3/B4-4 server deliverables per their own specs.

## 10. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/generate/ -run TestGeneratedScaffoldsCompile -v
go test ./cmd/sso-ctl/generate/ -race
make ci
```

Mutation pass (per acceptance case 6): temporarily reintroduce each banned pattern into `templates_handler.go` and confirm exactly the named assertion fails, then restore.
