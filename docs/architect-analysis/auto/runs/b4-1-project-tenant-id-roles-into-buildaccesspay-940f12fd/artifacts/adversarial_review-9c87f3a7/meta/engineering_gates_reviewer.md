All checks complete. Here is the gate/budget verification verdict.

## Verdict: design passes all five checks, with three corrections to record

### 1. 500-line / 50-line limits — satisfied (but unenforced for test files)

Both new files are `_test.go`, and **both gate stacks exclude test files**:
- Committed Go gates: `TestMaintainability_FileSizeBudget` and `TestMaintainability_FunctionLength`/`CyclomaticComplexity` skip `_test.go` (verified in `maintainability_budget_test.go`, `maintainability_complexity_test.go`).
- Python harness: `engineering.yaml` filesize `ignore_patterns` includes `"_test.go"`; complexity `ignore_pattern` includes `_test.go|cmd/|test/`.

So the 500/50 constraints are trivially satisfied and can never trip — **correction C1**: the design's "stay under" claim is self-discipline only, not gate-enforced. The design should state explicit per-file budgets (e2e ~450 / matrix ~450 lines is plausible from its structure: 6 cases + fixture vs. 7-grant table + roles/introspection + the ~40-line JWT-bearer validator). The validator interface `ValidateAssertion(ctx core.HandlerContext, assertion string) (issuer, subject string, err error)` (token_jwt_bearer.go:30-36) is implementable in-test with stdlib crypto — confirmed.

### 2. interfaces/sso 60-file ceiling — untouched ✓

Count is 60 non-test files today (frozen exemption in `directory_fanout_test.go`); the new files land in `cmd/sso-ctl/entitiescmd/` and `test/` — zero files added to `interfaces/sso`, and the gate counts non-test files only.

### 3. cmd/sso-ctl 16/16 fan-out — cannot trip ✓

`cmd/sso-ctl` has exactly 16 immediate subdirs today (at the cap; violation is `>16`). Both files go into **existing** dirs: no new subdirectory anywhere (`entitiescmd` non-test stays 2, `test/` non-test stays 0, `test/` subdirs stay 6, root unchanged). **Correction C2**: §1/§3.3's "entitiescmd = 4 non-test files" is wrong — it's 2 non-test (tenants.go, users.go) + 2 test = 4 total; gate-irrelevant (2 ≤ 10).

### 4. Pre-R0 green — build/vet yes; TestArchitecture_ claim overstated

- `go build ./... && go vet ./...` — **clean at HEAD**, and every API citation the tests depend on is present: `apiclient.EnvAddr/EnvToken` with per-construction env reads (`apiclient.New()` inside `doWrite`/`fetchList`), `sso.WithJWTBearerGrant` (options_grants.go:98), `WithIssuer/WithClientStore/WithDefaultTokenStrategy/WithPermissionProvider`, `grpcadmin.TenantAdminService` methods at :77/:177/:194/:315 (nil-safe `NewTenantAdminService` at :50), `adminv1.CreateTenantRequest{Get,SetTenantStatus}` (tenants.pb.go :449/:355/:731, `body:"tenant"`), `defaultimpl.NewEd25519JWTIssuer` (:257), `permissions.NewMemoryProvider`/`AssignRoles`, `domains/tenant/memory.New`, `decodeJWTPayload` (oidc_test.go:33), `RunTenants` entry, and the CLI's URL shapes (`/api/v1/admin/tenants`, `/…/{id}`, `/…/{id}:set-status` at tenants.go:229) match the design's route families. Claim-map assertions (never R0 struct fields) keep it compile-safe pre-R0; case 3/11's hedge is correct (with `WithIssuer` set, `resolveIssuer` already returns the configured value today).
- `t.Setenv` — valid: identical to the existing `withMockAdmin` precedent in tenants_test.go; no `t.Parallel` (correct — `t.Setenv` panics under parallel).
- Byte-identity — valid: tenants.go/users.go untouched; `go test ./cmd/sso-ctl/entitiescmd/...` passes today.
- **Correction C3 (material)**: `TestArchitecture_` is **already red at HEAD** — `TestArchitecture_DirectorySubdirFanout` (root `.` = 24 subdirs > frozen 21) and `TestArchitecture_DirectoryDepth` (220 dirs under `docs/architect-analysis/auto/runs`, 128 of them tracked). `TestMaintainability_` is fully green. The design's §3.5 step 3 / §4 claim "fan-out must stay green" is inaccurate; it must be reworded to "cannot be worsened by this change (no new dirs/files in measured scope); pre-existing reds reported separately" — the same treatment F9 already gives the Python check (whose `cmd/sso-ctl` 16>15 failure I confirmed by direct run, along with dist/, docs/, auto/runs/, platform/).

### 5. G1 rollback — exactly reversible ✓

The module's footprint is exactly the two new files: no production edits, no gate/exemption/config/docs/proto changes (T-9 pins byte-identity), no new dependencies (stdlib + existing root-module deps only). Deleting the two files restores HEAD byte-for-byte. The rollback claim is correctly scoped — full G1 rollback additionally involves the sibling R0 server module, which is outside this module's surface.

**Baseline note**: gates were measured with the pre-existing worktree state (53 modified + 306 untracked entries, incl. the large auditexport changes); `FileSizeBudget` still passes with those, and neither red test is caused by them.

Want me to patch the design doc with corrections C1–C3 (entitiescmd file count, TestArchitecture_ pre-existing red, explicit per-file line budgets)?
