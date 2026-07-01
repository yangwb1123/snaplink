Here's the full gate status across all 6 maintainability gates:

---

## Gate Audit Results — 6 gates, 5 failures

### ✅ Passing (4 subtests)
| Gate | Status |
|---|---|
| `TestArchitecture_ImportBoundaries` | ✅ Pass |
| `TestArchitecture_DirectoryDepth` | ✅ Pass |
| `TestArchitecture_DirectoryFanoutExemptionsDoNotGrow` | ✅ Pass |
| `TestMaintainability_ExemptionsDoNotGrow` / `FileSizeExemptionsDoNotGrow` | ✅ Pass |

### ❌ Failing (5 subtests)

#### 1. `TestArchitecture_LayerBoundaries` — `admin/v1` unclassified
The `admin/v1` package (generated protobuf) has no layer classification. Needs an entry in `layerName()` or an exemption.

#### 2. `TestArchitecture_DirectoryFileFanout` — 7 violations
- **Over 10-file budget (new):** `admin/v1` (20), `internal/handler/tokengrant` (11), `shared/security` (11)
- **Exempt dirs regressed past frozen ceiling:** `config` (27 > 26), `infrastructure/defaultimpl` (27 > 26), `interfaces/sso` (61 > 57), `shared/core` (24 > 23)

#### 3. `TestArchitecture_DirectorySubdirFanout` — root regressed
Root `.` has 22 subdirs vs frozen ceiling of 21.

#### 4. `TestMaintainability_FileSizeBudget` — 17 files over 500 lines
Mostly generated protobuf stubs (`admin/v1/*.pb.go`, `.pb.gw.go`, `*_grpc.pb.go`) plus 4 hand-written files:
- `cmd/sso-ctl/generate/templates.go` (589)
- `interfaces/sso/options_misc.go` (549)
- `interfaces/sso/server_login.go` (583)
- `interfaces/sso/server_token.go` (554)
- `shared/core/types.go` (503)

#### 5. `TestMaintainability_CyclomaticComplexity` — 6 functions over cyclo 15
- 4 generated functions in `admin/v1/*.pb.gw.go`
- 2 hand-written: `(*Server).handleLogin` (cyclo 21), `(*Server).handleToken` (cyclo 17)

#### 6. `TestMaintainability_FunctionLength` — 24 functions over 50 lines
- 14 generated functions in `admin/v1/*.pb.gw.go`
- 10 hand-written in `interfaces/sso/`, `cmd/sso-ctl/`, `cmd/sso-server/`, `shared/security/`

---

The new root-cause is clear: the `admin/v1/` protobuf-generated package (created after the gates were seeded) isn't classified in the layer model, its generated-file functions blow both cyclo and length budgets, and its file count pushes fanout limits. The hand-written files that exceed budgets are a secondary concern.

Would you like me to fix these one at a time? The logical order would be:

1. **Classify `admin/v1`** in `architecture_layer_test.go` as a generated/composition layer
2. **Regenerate the directory fanout exemptions** (which will account for the new `admin/v1` dir and the root subdir count)
3. **Add size/cyclo/length exemptions** for the generated `admin/v1/*.pb.go` / `.pb.gw.go` / `*_grpc.pb.go` files (they're generated code — the doc explicitly says "non-generated production `.go` file" for the file-size budget)
4. **Refactor the hand-written violations** (the 4 over-500-line files, the 2 high-cyclo functions, the 10 long functions)
