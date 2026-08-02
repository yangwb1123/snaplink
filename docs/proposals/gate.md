# Gatekeeper Cross-Check: Review Findings vs Design

**Evidence base**: design at HEAD (`a9a2a2ce`, unmodified — `git diff HEAD -- docs/auto/interfaces-cors-design.md` is empty, so the design is byte-identical to the revision all six reviews examined). I independently re-verified the load-bearing claims with grep/`wc -l`/`git show`.

## Independent re-verification (gatekeeper's own checks)

| Claim | My check | Result |
|---|---|---|
| `toPolicy()` unexported | `config_load.go:472` `func (c *CORSConfig) toPolicy()` — lowercase | **Confirmed** — design line 134 calls it from package `main` |
| `core.HeaderOrigin` absent | `HeaderOrigin` only at `interfaces/cors/consts.go:7`; zero hits in `shared/` | **Confirmed** — design line 217 references it |
| `server_login.go` at ceiling | HEAD version = 498 lines (reviews measured 500 at their revision); gate fails at `>500` (`maintainability_budget_test.go:34,87`) | **Confirmed, slack ≈ 0–2 lines** |
| `corsPolicy` read points | 5 refs / 3 functions (`origin_validation.go:105,110`; `server_login.go:167`; `server_routes.go:451,452`) + field decl/assign | **Design's "仅 2 处" is wrong** |
| `applyRateLimit` has no `Enabled` check | grep `Enabled` in `reload.go` → only comments re `Set*GateEnabled` | **Confirmed** — design's "与 rate_limit 的 enabled 契约一致" is false |
| `CORSConfig` = 7 fields, no `path_overrides` | `config_admin.go` struct confirmed | **Confirmed** |
| Third mapping copy | `build_app_security.go:169-181` inline literal | **Confirmed** |

## Finding-by-finding disposition

| Review finding | In design? | Disposition |
|---|---|---|
| **H-1** `toPolicy()` unexported → compile failure (QA/Arch/Sec/Principal) | Design line 134 still `c.toPolicy()` in `main_wiring.go` | **NOT RESOLVED** |
| **M-1** `core.HeaderOrigin` doesn't exist → compile failure | Design line 217 still `core.HeaderOrigin` | **NOT RESOLVED** |
| **H-2** `server_login.go` ~500-line ceiling, absent from constraint table, D3 edits it (+doc comment, +import) | Design still targets `server_login.go` for gate rewrite + extended doc comment; no net-zero rule | **NOT RESOLVED** |
| **M-2/Arch F1** per-request config rebuild contradicts "热路径仍走预计算 config"; ratelimit mirror is alloc-free | Storage model still `atomic.Pointer[Policy]` + "`buildConfig` 每次从 Policy 值新建" — no `policyEntry`-with-precomputed-configs; the fix the reviews require is not in the design | **NOT RESOLVED** |
| **M-3** `path_overrides` doc row implies nonexistent YAML knob; `SetCORSPolicy` whole-policy replacement (drops boot `PathOverrides`) undocumented | Design D2 doc row still says "`path_overrides` 说明最长前缀优先"; `SetCORSPolicy` doc lacks the whole-policy-replacement statement | **NOT RESOLVED** |
| **M-4** aliasing claims factually wrong (`&policy` hold; "store 化后不可能" — element-level alias persists) | False claims remain verbatim; doc-contract mitigation *is* mentioned (What-could-break #3), deep-copy decision unmade | **PARTIAL** (mitigation mentioned; false claims + T2 decision outstanding) |
| **M-5/Arch F4** three mapping copies; `build_app_security.go` literal not unified | Not mentioned in design | **NOT RESOLVED** |
| **L-1** "与 rate_limit 的 enabled 契约一致" factually false (rate_limit is driftier; CORS stricter) | Wrong claim still in failure-mode table; must not relax CORS — design is correct on behavior, wrong on the justification | **NOT RESOLVED** (wording) |
| **L-2** `corsPolicy` count wrong (2 → 5 refs/3 functions) | "仅 2 处" still in §0 and 关键推论 | **NOT RESOLVED** (doc accuracy) |
| **L-3** reload Applied entry lacks origins | `applyCORS` still returns `"security.cors: policy rebuilt"` | **NOT RESOLVED** |
| **L-4** preflight-cache non-retroactivity; boot/reload fail-closed asymmetry | Asymmetry planned for Hot Reload row (**partial**); preflight-cache lag absent | **PARTIAL** |
| **I-1/I-2/I-3** stale package doc; one-request-apart note; identity fast-path scope | Not addressed | **NOT RESOLVED** (Info) |

## Verdict rationale

The design document is **unchanged** from the exact revision the reviews reviewed. None of the review findings are resolved in the document, and none are dismissed with reasons. The principal reviewer's own gate — "实现前前置条件（设计文档修订，一次 change）" — is entirely unmet. Three findings are literal compile/gate failures if implemented as written (`c.toPolicy()`, `core.HeaderOrigin`, `server_login.go` ≤500), one is a self-contradicting hot-path allocation regression (DynamicMiddleware storage model), and the remainder are contract-doc drift and factually wrong claims that all reviews independently flagged.

The direction is sound and no reviewer found a High/Critical architectural flaw — but the required design revisions (a bounded, single-change doc update per principal §4) must land before implementation proceeds. "Conditionally ready" with unmet preconditions is not ready.

VERDICT: FAIL - blocking issues: (1) `c.toPolicy()` called from package main — `CORSConfig.toPolicy` is unexported (compile failure; must export `ToPolicy` or add a cmd-side helper, and unify the `build_app_security.go` inline mapping, M-1/M-5); (2) `core.HeaderOrigin` does not exist — D3 gate rewrite must use `cors.HeaderOrigin` or keep the `"Origin"` literal (M-1); (3) D3 edits `server_login.go` at a ~498–500-line ceiling with no net-zero discipline in the design's constraint table (H-2 — `TestMaintainability_` will fail); (4) D1 storage model `atomic.Pointer[Policy]` + per-value `buildConfig` rebuild contradicts the design's own "热路径仍走预计算 config" claim and the alloc-free ratelimit mirror — must adopt the `policyEntry{policy, defaultCfg, overrideCfgs}` precompute-at-Set model (M-2); (5) config-reference Security row documents `path_overrides` as a knob `CORSConfig` does not have, and `SetCORSPolicy`'s whole-policy replacement (dropping boot `PathOverrides`) is undocumented (M-3); (6) factually wrong claims still in the doc: "与 rate_limit 的 enabled 契约一致" (rate_limit has no Enabled check), "corsPolicy 仅 2 处读取点" (5 refs/3 functions), "原实现持有调用方指针 / store 化后不可能" (element-level alias persists; deep-copy decision unmade) (L-1/L-2/M-4); (7) reload Applied entry lacks the new origins list (L-3). All seven must be corrected in the design doc (per principal reviewer §4 preconditions) before the implementation stage starts.
