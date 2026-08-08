Audit complete. I verified every load-bearing claim against HEAD by reading the code paths end-to-end: `clientscmd` (Run/runGet/usage, e2e fixture), the admin gateway (`clientToProto`, GetClient), `WithScopeRegistry`, the `/token` seams (`dispatchTokenGrant` → `rejectUnregisteredScopes`, `token_client_credentials.go` branch check, `oauthvalidate.GrantedScopes`), `scoperegistry` (NewMemory/Registered/RejectUnregistered), `runT8d`/`mint` in `apiclient`, and the A-1b pin. Verdict: **the R3 triple and byte-identical claim are implementable as written, but the acceptance mapping has one real defect (E3) and FM/stderr coverage is incomplete as written.**

## 1. Registry-wired fixture in `clientscmd` — IMPLEMENTABLE (verified end-to-end)

- `newCLIDeployment` already proves the shape: outer mux mounts `srv.Handler()` at `/` (so `/token` and discovery are live) and the admin gateway under `AdminMiddleware`; E-5 already drives a cc mint + T-8d probe through that same deployment, and E-4 drives the CLI via `t.Setenv(apiclient.EnvAddr/EnvToken)` — `apiclient.New()` reads env per call (apiclient.go:52-61), so one test can set env for `Run(["validate",...])` and still `http.Post(srv.URL+"/token", ...)` directly. `sso.WithScopeRegistry(scoperegistry.NewMemory(scopecontract.Matrix(), nil))` exists (options_misc.go:494) and `clientToProto` copies `AllowedScopes` into the `{"client":{...}}` gateway shape E1a needs.
- E1a: `billing:typo` unregistered, `openid`/`profile` pre-seeded (registry.go:48-60), `admin:read` passes via `admin:*` (registry.go:115-125) → exit 1 naming only `billing:typo` ✓.
- E1b: `billing:typo` is **in** client-v's allowlist, so the allowlist gate passes and the registry seam (dispatch-level at server_token.go:130-132, plus cc branch at token_client_credentials.go:46) is what rejects — the test genuinely exercises the registry, not the allowlist ✓.
- E1c/E2b: `admin:read` (via pattern) and all 9 matrix rows mint 200; the rows including `admin:*` itself pass exact-match ✓.

## 2. Byte-identical body claim — MATCHES the pin

A-1b (`test/scope_registry_test.go:154-162`) pins `want := `{"error":"invalid_scope"}`` compared via `strings.TrimSpace(got) != want` plus a no-`trace_id` assertion. The spec's E1b wording ("body trimmed byte-identical `{"error":"invalid_scope"}` (A-1b pin)") is the identical comparison; the raw body is `{"error":"invalid_scope"}\n` (same literal as `runT8d`'s wantBody at token.go:375, emitted via `core.ErrorBody`), and any trace_id leak would break the trimmed comparison. ✓

## 3. FM-1..FM-7 direct coverage — NOT satisfied as written

| FM | Coverage in U1-U9/E1-E3 | Verdict |
|---|---|---|
| FM-1 unreachable/timeout | **none** (all unit fixtures respond; no closed-port test) | gap, cheap to add |
| FM-2 404 | U6 ✓ | covered |
| FM-3 malformed response | **none** (U9 is the valid flat shape, not garbage) | gap, cheap to add |
| FM-4 construction error | none — unreachable through the real path (`NewMemory(Matrix(), nil)` cannot fail; all 9 patterns valid); untestable without making construction injectable | documented unreachable, but not "direct coverage" |
| FM-5 provisioned-matrix false positive | **none** | gap — implementable: second fixture wiring a provisioned matrix makes `/token` mint 200 for a scope the CLI rejects |
| FM-6 vacuous pass | U8 ✓ (exit 0 + stderr notice) | covered |
| FM-7 extra_scopes false positive | **none** | gap — implementable: wire `WithScopeRegistry(NewMemory(Matrix(), []string{"tenant:extra"}))`; CLI exit 1 while `/token` mints 200, no server changes needed |

Note the question's label "FM-6 (false-positive on provisioned/extra-scope deployments)" actually describes FM-5/FM-7 — the spec's FM-6 is the vacuous pass, which U8 does cover. The false-positive family the audit cares about has zero direct coverage; it is implementable in `clientscmd` without touching `test/` or the server, but no such test exists in the mapping. FM-5's false-*negative* direction (built-in-matrix scope absent from a provisioned matrix: CLI passes, `/token` 400s) is also unmentioned.

## 4. Exit-code-2 path — covered, with one behavioral note

U7a (missing client-id) and U7b (`c1 --nope`) directly assert exit 2 + usage on stderr. But `runGet` ignores trailing args, so `runValidate` must deliberately add a `len(args) > 1 → usage + 2` guard for U7b to pass — implementable, though it's an addition beyond "mirror runGet". Edge not covered: `Run(["validate","--nope"])` (flag as first positional) would be treated as a client-id → 404 → exit 1, not 2, unless a `--`-prefix check is added.

## 5. Stderr-only assertions — mostly present, one gap

Present: U1 asserts stderr empty on pass; U4/U5/U6/U7a/E1a assert stderr content on failure; U8 asserts the vacuous notice lands on stderr; U5 asserts lexical dedup order. Missing: **no test asserts stdout is empty on exit 1** — the §7 "offenders on stderr only, stdout carries only `validate: OK`" script-safety half is never pinned (trivial to add to U4/E1a; `captureStdoutAndStderr` already exists in the package).

## 6. Defect: E3 fails as written

`sso-ctl check --client-id client-v --client-secret s` with **no `--scope`** on the registry-wired deployment: T-8a's mint sends no scope → `GrantedScopes` rule 4 defaults to client-v's allowlist minus openid = `[profile, billing:typo, admin:read]` → the cc branch's `RejectUnregistered` (token_client_credentials.go:46) rejects `billing:typo` → `mint: FAIL` → `check FAIL`, exit 1. T-8d would print `invalid_scope: OK`, but the sweep is red — contradicting "keeps the live probe green (no regression)". Fix (one line): run E3 against **client-m** (defaulted scope = all 9 registered rows → mint OK; T-8d probe unregistered → OK; T-9 OK), or pass `--scope openid`, or seed a third registry-conformant client. Also worth noting: T-8d on client-v would pass even unwired (non-empty allowlist rejects the probe first) — it cannot isolate registry enforcement, consistent with T-8d's documented oracle-safe semantics.

## Bottom line

R1/R2/R3/R4/R5 and the U/E tables are implementable as written, with the byte-identical pin matching A-1b exactly. Two must-fix items before this maps to code: **E3's client choice (breaks the sweep it claims is green)** and **the missing FM-1/FM-3/FM-5/FM-7 tests plus the stdout-empty-on-failure assertion** — all cheap to add within the existing fixture pattern, none requiring `test/` imports or server changes.
