I've now compared the documentation against the actual gate tests. There are **significant discrepancies** — the doc describes a pristine state, but the codebase has accumulated violations across every gate:

### Discrepancies found

| Gate | Doc claim | Reality |
|---|---|---|
| **File ≤ 500 lines** | "Every production file is under budget" | 17 files over (12 generated `admin/v1/*.pb*.go`, `cmd/sso-ctl/generate/templates.go`, `interfaces/sso/options_misc.go`, `interfaces/sso/server_token.go`, `shared/core/types.go`) |
| **Cyclo ≤ 15** | "`cycloExemptions` map empty (cap 0)" — empty but violations exist | 6 functions over: generated `admin/v1/*.pb.gw.go` (4x), `server_login.go:handleLogin` (21), `server_token.go:handleToken` (17) |
| **Func len ≤ 50** | "`funcLenExemptions` map empty (cap 0)" — same | 26 functions over (mostly generated handlers + several hand-written ones) |
| **Layer boundaries** | 9 grandfathered exemptions | `admin/v1` is **unclassified** — not in `layerName()` |
| **Dir go-file fan-out** | Dirs at/under grandfathered caps | 3 new over-cap dirs (`admin/v1`: 21, `internal/handler/tokengrant`: 11, `shared/security`: 11) + **4 regressions** (config 26→28, defaultimpl 26→27, sso 57→65, core 23→24) |
| **Dir subdir fan-out** | `.` at frozen 21 | `.` regressed to 23 subdirs |
| **Dir depth ≤ 3** | All ≤ 3 | 8 `docs/skills/*/__pycache__` dirs at depth 4 |

The doc's `fileSizeExemptions`, `cycloExemptions`, and `funcLenExemptions` maps are indeed empty (matching the doc), but that's because the violations were never exempted — they just appeared as new violations.

What would you like me to do?

1. **Fix the violations** to bring the codebase back into compliance with the docs
2. **Update the docs** to reflect the current state
3. **Re-seed the gate exemptions** (run `SEED_MAINTAINABILITY=1` and `SEED_DIRFANOUT=1`) to match current reality, then fix forward
