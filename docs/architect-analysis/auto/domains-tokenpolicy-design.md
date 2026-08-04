# Tokenpolicy 治理生命周期闭环 — Design

Design for [方向一 spec](domains-tokenpolicy-spec.md): three improvements forming
one lifecycle — rules enter validated (严格解析 + `Policy.Validate` + 默认 TTL
可见性), mutate through a writable admin API (PUT/DELETE/GET by name), and live
in a durable single source of truth (SQLite store + cross-replica invalidation).

Ground truth anchors (all grep-confirmed against current code):

- `domains/tokenpolicy/yaml.go` `ParseYAML` — bare `yaml.Unmarshal`, sole caller
  `cmd/sso-server/serverbuildplatform/build_governance.go:197` `BuildTokenPolicyStore`.
- `domains/tokenpolicy/tokenpolicy.go` — `Store` = `Policies()` only; `Policy.MaxTTL`
  comment admits "the engine cannot see that default".
- `domains/tokenpolicy/evaluate.go` — `clampTTL` turns a positive `MaxTTL` into a
  concrete TTL for `RequestedTTL == 0` (issuer-default sentinel); `denyReason`
  ignores negative dimensions.
- `domains/tokenpolicy/memory/store.go` — slice COW + `Replace` with zero non-test
  callers. Sibling precedent: `domains/threataction/{policy.go,admin.go,memory,sqlite}`
  and `domains/tokenexchange/sqlite/chain_store.go`.
- Wiring seams: `interfaces/sso/sso.go:349` (GET-only handler), `sso.go:489-498`
  (threat-policy CRUD wrappers), `server_routes_admin.go:122-140` (mount gates),
  `server_helpers.go:67` (`NewClampingIssuer` wrap site), `server_invalidation.go`
  (bus dispatch), `config/config_snapshot.go:298` (`TokenPolicyConfig`),
  `cmd/sso-server/build_app_security.go:281` (`BuildTokenPolicyStore` call site),
  `cmd/sso-server/serverbuildsign/build_signing_issuers.go:44,68` (issuer default
  TTL plumbing — `WithEd25519TokenTTL(srv.TokenTTL)`), `shared/core/consts_oauth.go:134`
  (`DefaultTokenTTL = time.Hour`).

Every decision below is chosen to keep the strictest existing contracts: fail-open
evaluation, oracle-safe wire responses, `admin:read`/`admin:write` gating, and
"config/seed never silently overrides admin-authored state".

---

## 决策 1: `ParseYAML` 严格化 — 只做解析，不引入 defaultTTL 依赖

`ParseYAML` switches to `yaml.UnmarshalWithOptions(data, &f, yaml.DisallowUnknownField())`.
Signature stays `func ParseYAML(data []byte) ([]Policy, error)`.

Deliberate refinement of the spec's "ParseYAML 并对每条规则调用 Validate": validation
does NOT move inside `ParseYAML`. `Policy.Validate` needs `defaultTTL`, which is a
*wiring* concern (the issuer default lives in `cfg.Server.TokenTTL`, not in the
bundle). Keeping `ParseYAML` a pure parser means:

- the parser has one job (unknown-field rejection), testable with table tests;
- `BuildTokenPolicyStore` owns the dual-seam validation (决策 4) and can log
  advisories with the actual default TTL;
- no signature churn for the parser's existing callers beyond the strictness change.

The conditionalaccess comparison (`LoadPolicies` = strict parse + per-policy
`Validate` inside one function) is noted; `LoadPolicies` needs no external input,
`ParseYAML` would — that difference justifies the split. The *strictness parity*
(the actual drift being fixed) is fully achieved: a misspelled dimension now fails
boot loudly.

## 决策 2: `Policy.Validate` 契约 — 硬错误与告警分离

New pure file `domains/tokenpolicy/validate.go` (no I/O, no clock — same
testability contract as `Evaluate`):

```go
// Hard errors: reject load/write. Returns the first violation.
func (p Policy) Validate(defaultTTL time.Duration) error

// Advisory: must be loud but never blocks. Returns human-readable warnings.
func (p Policy) AdvisoryWarnings(defaultTTL time.Duration) []string
```

Two functions instead of one `(warnings, error)` return: the spec's stated
signature is `Validate(defaultTTL) error`; warnings are a separate concern that
must never be conflated with rejection, and the two call sites consume them
differently (boot `logger.Warn` vs. PUT 200-body field).

Hard errors:

| Check | Rationale |
|---|---|
| `MaxTTL < 0` | negative ceiling is a mistake; zero = unset (valid) |
| `MaxRefreshDepth < 0` | negative depth is inert forever in `denyReason` (`>=` never trips) |
| `MaxActiveSessions < 0` | same inertness |
| `RequireRenewAfter < 0 \|\| > 1` | fraction must be in (0,1]; zero = unset (valid) |
| empty / whitespace-only `Name` | mirrors `conditionalaccess.Policy.Validate`; a rule with no name is unmanageable via the keyed admin API (PUT/DELETE/GET `:name`). All existing fixtures carry names. |

Advisory: `0 < MaxTTL && defaultTTL > 0 && MaxTTL > defaultTTL` → one warning
naming the policy and both durations. After 决策 3 the widening is *mechanically
impossible*, so this is not a rejection — it tells the operator the `max_ttl` is
inert for default-TTL clients (it never binds below the issuer default).

`BlockScopeCombos` gets no validation: empty inner groups are already defined as
ignored by `violatesScopeCombos` (documented behavior, not a mistake).

## 决策 3: 发行方默认 TTL 可见性 — `PolicyInput.DefaultTTL` + `ClampingIssuer` 签名

Root fix: the engine learns the issuer default. `PolicyInput` gains:

```go
// DefaultTTL is the issuer's default access-token lifetime, used when
// RequestedTTL == 0 (the "issuer default" sentinel). When > 0, a matching
// MaxTTL caps at min(MaxTTL, DefaultTTL), so a misconfigured MaxTTL can
// NEVER widen a default-client lifetime. Zero = legacy behavior (MaxTTL
// becomes the concrete ceiling).
DefaultTTL time.Duration
```

`Evaluate`'s combination loop applies the per-policy cap as
`cap = p.MaxTTL; if in.RequestedTTL <= 0 && in.DefaultTTL > 0 && p.MaxTTL > in.DefaultTTL { cap = in.DefaultTTL }`
— unset `MaxTTL` still yields `EffectiveTTL == 0` ("leave the issuer default"),
unchanged. Downward-only invariant preserved: `EffectiveTTL` is never above a
positive `RequestedTTL`, and for `RequestedTTL == 0` never above `DefaultTTL`.

`NewClampingIssuer` gains the default:

```go
func NewClampingIssuer(inner core.TokenIssuer, store Store, defaultTTL time.Duration) core.TokenIssuer
```

nil-store → `inner` unchanged (byte-identical no-op) stays. Call sites:
`interfaces/sso/server_helpers.go:67` passes `s.tokenPolicyDefaultTTL`.

`interfaces/sso.Server` gains `tokenPolicyDefaultTTL time.Duration` (default
`core.DefaultTokenTTL`) set by a new option `WithTokenPolicyDefaultTTL(ttl)`,
wired in `cmd/sso-server` from `b.cfg.Server.TokenTTL` — the SAME value
`build_signing_issuers.go` already passes to `WithEd25519TokenTTL` /
`WithECDSATokenTTL`. This single-source invariant is what makes the fix correct:
if the engine's default diverged from the issuer's actual configured TTL
(e.g. engine thinks 1h, issuer configured 30m), a `max_ttl: 2h` rule would clamp
to 1h and *widen* 30m clients — the exact bug class this improvement kills.

Direct `Evaluate` callers that do not issue (`server_oauth.go:177`,
`sso_protocol.go:486`) keep `DefaultTTL == 0` → legacy clamp semantics, which is
fine: they never apply a TTL. The `ClampingIssuer` is the uniform TTL seam (its
package doc already says so); the `DefaultTTL` field doc warns future issuers to
pass it.

## 决策 4: 校验接入点 — 启动/写入双重校验

Two seams call `Validate` (hard) + `AdvisoryWarnings` (advisory), per the spec:

1. **Boot (config wiring)**: `BuildTokenPolicyStore(cfg config.TokenPolicyConfig,
   defaultTTL time.Duration)` — signature gains `defaultTTL`; validates every
   rule from File (post-`ParseYAML`) and inline `Policies`. Hard error → boot
   failure with the policy name (same loud contract as `BuildConditionalAccess`).
   Advisory → `logger.Warn` per rule. Call site `build_app_security.go:281` passes
   `b.cfg.Server.TokenTTL`.
2. **Write (admin PUT)**: `HandleAdminPutPolicy` (决策 7) validates before
   `Store.Put`; hard failure → `400 invalid_policy` + `error_description`; advisory
   → echoed in the 200 response body (and logged).

The stores themselves (`memory`, `sqlite`) do NOT validate on `Put` — they are
dumb persistence layers, same as `threataction`. Validation lives at the two
entry points where human/config input crosses the trust boundary.

## 决策 5: `Store` SPI 扩展 — `Get`/`Put`/`Delete` + `ErrPolicyNotFound`

```go
// tokenpolicy.go
var ErrPolicyNotFound = errors.New("tokenpolicy: policy not found")

type Store interface {
    Policies(ctx context.Context) ([]Policy, error)      // unchanged contract (COW, read-only)
    Get(ctx context.Context, name string) (Policy, error)
    Put(ctx context.Context, policy Policy) error        // upsert by Name
    Delete(ctx context.Context, name string) error
}
```

Shapes mirror `ThreatPolicyStore` (List/Get/Put/Delete) with one refinement: `Get`
returns `Policy` by value (not `*Policy`) — `Policy` is a small value type with no
nil-ambiguity semantics; `ErrPolicyNotFound` distinguishes absence. Breaking change
to the interface — in-repo implementers are only `memory.Store`, the new `sqlite`
store, and test fakes (grep-verified: no third-party implementations); all are
updated in this change. `Policies()` keeps its read-only-slice contract so the
hot path is untouched.

## 决策 6: `memory.Store` 改造 — map 键控 COW，保留插入序

`memory.Store` holds `policies []Policy` (the COW snapshot `Policies()` returns)
plus `byName map[string]Policy`. Mutations (`Put`, `Delete`, retained `Replace`
for startup seeding) rebuild both under the write lock; `Policies()` still returns
the backing snapshot under `RLock` — a reader holding a returned slice is never
disturbed (COW preserved, race-free).

**Ordering decision**: the snapshot preserves *insertion/config order*; `Put`
replaces an existing rule in place (position kept) and appends new rules; `Delete`
removes. Rationale: `Evaluate`'s deny reason is "the FIRST matching deny (in policy
order, then dimension order)" — re-sorting by name (threataction's approach) would
silently change which reason lands in the audit/metric for overlapping rules on
existing config-seeded deployments. Config order is the operator-authored order.
Deterministic, backward-compatible, and only the reason label (never the deny
outcome, never the wire) is affected.

## 决策 7: Admin API 表面 — 三条 `:name` 路由 + 错误拆分 + 门控

New handlers in `domains/tokenpolicy/admin.go` (package consts
`paramPolicyName = "name"`, `keyPolicy = "policy"` — the `ctx.Param` key is the
bare `"name"` exactly as `threataction` documents):

```go
func HandleAdminGetPolicy(store Store, log spi.Logger, ctx core.HandlerContext)
func HandleAdminPutPolicy(store Store, defaultTTL time.Duration, log spi.Logger, ctx core.HandlerContext) bool
func HandleAdminDeletePolicy(store Store, log spi.Logger, ctx core.HandlerContext)
```

| Route | Scope | Success | Decode/semantic failure | Unknown name |
|---|---|---|---|---|
| `GET /api/v1/admin/token-policies/:name` | `admin:read` | 200 `{status, policy}` | — | 404 `not_found` |
| `PUT /api/v1/admin/token-policies/:name` | `admin:write` | 200 `{status, policy, warning?}` | 400 `invalid_request` (decode) / 400 `invalid_policy` + `error_description` (Validate) | — (upsert) |
| `DELETE /api/v1/admin/token-policies/:name` | `admin:write` | 200 `{status}` | — | 404 `not_found` |

- `policy.Name` is taken from the route param (mirrors `HandleAdminPutPolicy`'s
  `policy.Name = name`) — the body's `name` field is ignored, preventing
  path/body divergence.
- The decode-vs-semantic split reuses `ErrInvalidRequest` vs `ErrInvalidPolicy`
  (`shared/core/errors.go:313`) — same split threataction and
  `HandleAdminProposeChange` already ship.
- **`HandleAdminPutPolicy` returns `bool`** (true = stored): the thin server
  wrapper needs success knowledge to publish the cross-replica invalidation
  (决策 8) after the response is written. The response is still written by the
  domain handler; the wrapper only publishes. This is the minimal contract change
  that keeps bus coupling out of the domain package.
- Gating: `interfaces/admin` middleware default method rule — GET → `admin:read`,
  PUT/DELETE → `admin:write`; 401 `Bearer realm="admin"` on missing/insufficient
  token. No `methodScopes` override needed.
- Mount: `server_routes_admin.go` `mountAdminTokenGovernance`, inside the existing
  `if s.tokenPolicyStore != nil` block: `GET` list + `GET`/`PUT`/`DELETE` by name.
  Unwired → route absent → 404 (byte-identical to a build without the feature;
  existing `rootcov_admin_token_policies_test.go` unmounted-404 test extends to
  the new methods).
- New path const `PathAdminTokenPolicyByID = "/admin/token-policies/:name"` in
  `shared/core/consts_wire.go` beside `PathAdminThreatPolicyByID`; re-aliased in
  `interfaces/sso/aliases.go`; `shared/core/consts.go:214` "read-only" comment updated.
- Server wrappers in `sso.go` mirror the threat-policy wrappers
  (`sso.go:489-498`); the PUT wrapper additionally publishes on `true`.

## 决策 8: 跨副本失效 — `KindTokenPolicyChange` + 快照 `Refresh`

New bus kind `KindTokenPolicyChange EventKind = "token_policy.change"` in
`platform/cluster/bus.go` (dot notation per the existing convention; the set is
open by design — "new coordinated caches add a kind here and a dispatch arm on
the subscriber side"). `Key` is unused: the policy set is a whole-list cache,
like `KindDiscoveryReload` — a per-name eviction buys nothing because `Policies()`
serves one snapshot.

Publish side (writer): after a successful PUT/DELETE, the server wrapper calls a
new `s.InvalidateTokenPolicies()` — publish `{Kind: KindTokenPolicyChange}`,
best-effort with logged failure (mirrors `InvalidateConnectionCache`; the writer's
own snapshot was already refreshed synchronously inside its store, so a failed
publish only delays peers).

Receive side (peers): `applyControlPlaneInvalidation` gains a
`case cluster.KindTokenPolicyChange:` arm that type-asserts `s.tokenPolicyStore`
to `interface{ Refresh(context.Context) error }` (the same "wired store may not
implement the optional extension" pattern used elsewhere in `interfaces/sso`) and
refreshes the snapshot; failure is logged and the stale snapshot keeps serving
(fail open). `flushInvalidationCaches` (bus-recovery reseed, `KindControlPlaneRestore`)
also refreshes the token-policy snapshot — recovery must converge missed events.

AGENTS.md §4's cross-replica list and the `applyControlPlaneInvalidation` doc
comment are extended in the same change (spec requirement).

## 决策 9: SQLite 存储模型 — 单表 JSON 列 + 版本化迁移

New root-module package `domains/tokenpolicy/sqlite` (depth 3, allowed; mirrors
`domains/threataction/sqlite/policy_store.go` — same table shape, same reasons:
nothing queries by SQL WHERE, flattening would only add migration surface):

```sql
CREATE TABLE IF NOT EXISTS token_policies (
    name        TEXT PRIMARY KEY,
    policy_json TEXT NOT NULL DEFAULT '{}'
);
```

- `platform/migrate` versioned migrations, baseline `{Version: 1, Name: "baseline"}`;
  `TokenPolicyMaxVersion() int` via `migrate.MaxVersion` for the boot
  `CheckSQLiteSchema` check (mirrors `domains/threataction/sqlite/maxversions.go`
  and the `CheckSQLiteSchema` call pattern in `build_app_*.go`).
- API mirrors the threat store: `New(dsn)` (open + ping + migrate),
  `NewWithDB(db)` (shared-pool deployments), `Close()`, `DB()`, `Ping(ctx)`
  (for the storage-health schema reporter), plus the `Store` methods.
- `modernc.org/sqlite` (already a root-module dependency; no CGO, no nested-module
  trigger). Driver registered via blank import in the sqlite package, as the
  sibling stores do.
- `Policies()` orders by `name` (`ORDER BY name`) — deterministic across replicas.
  Documented divergence from the memory store's insertion order: affects only the
  deny-reason label precedence for overlapping rules (audit-only, never the wire);
  the deny outcome is order-independent.
- Writes: `Put` = `INSERT ... ON CONFLICT(name) DO UPDATE SET policy_json = excluded.policy_json`
  (upsert); `Delete` = `DELETE ... WHERE name = ?` + `RowsAffected() == 0` →
  `ErrPolicyNotFound`; both then refresh the in-memory snapshot before returning.
  Store does NOT validate (决策 4).

## 决策 10: 快照刷新模型 — 写同步刷新 + 事件驱动刷新 + FAIL OPEN

The sqlite store keeps an in-memory snapshot (`[]Policy` + `byName`, mutexed,
built on `New` from the DB). Hot-path contract unchanged: `Policies()` serves the
snapshot — never a per-request disk read. Refresh points:

1. `New`/`NewWithDB` — initial load.
2. `Put`/`Delete` — synchronous refresh after the DB write, before returning to
   the admin handler (the writer replica is immediately consistent).
3. `Refresh(ctx)` — called by the bus arm / recovery flush on peer replicas
   (决策 8).

Failure modes: `Policies()` never touches the DB → a DB outage mid-flight cannot
fail issuance (fail open, unchanged). A failed `Refresh` logs and keeps the stale
snapshot — the replica converges on the next event or restart. The bounded stale
window (admin write on A → B enforces old set until the event lands) is accepted:
the set is a governance knob, not a credential check; a stale rule can only
over-deny or over-allow within one convergence interval, and a dropped event is
covered by the recovery reseed.

## 决策 11: `TokenPolicyConfig` 接线 — `sqlite` DSN + 首启播种语义

`config/config_snapshot.go:298` gains `Sqlite string yaml:"sqlite"`. The spec's
two sentences ("与 File/Policies 互斥" and "启动时若表为空则以 config/File 播种一次")
are reconciled as one explicit contract:

- `File` vs `Policies` remain mutually exclusive (existing rule, boot error when
  both set — unchanged).
- `sqlite` may be combined with at most one of `File`/`Policies` as a
  **first-boot seed contract**: on startup, if the `token_policies` table is
  empty, the config/File rules are validated and seeded once; if the table is
  non-empty, seeding is skipped (with a loud boot log line naming the skip).
  After first boot, admin writes are the sole source of truth — config edits do
  NOT re-apply (this is the point of persistence; documented in config-reference).
- `sqlite` alone (no File/Policies): no seeding; an empty table starts with zero
  rules (fail-open governance default) until an admin writes.

Rationale: strict three-way exclusivity would make the spec's own "seed when
empty" unreachable — a first boot with `sqlite` only would always be empty, and
there would be no config to seed from. The seed contract is idempotent
(empty-checked, never overwrite) and gives operators one config file for
"migrate this policy set into the durable store on day one".

`BuildTokenPolicyStore(cfg, defaultTTL)` branches: absent section → `(nil, nil)`
(byte-identical); File/Policies only → memory store (existing path + validation);
sqlite → open/migrate, seed-if-empty, return the sqlite store. The cmd builder
appends `WithTokenPolicy(store)` plus, when sqlite is used, `WithTokenPolicyDefaultTTL(cfg.Server.TokenTTL)`
and registers the store's `DB()`/`Ping` with the storage-health schema reporter
(mirroring `test/storage_health_test.go`'s sqlite sources) and the boot
`CheckSQLiteSchema` check.

## 决策 12: 契约文档同步清单（同一变更）

| Doc | Change |
|---|---|
| `docs/openapi.yaml` | `get`/`put`/`delete` operations under `/api/v1/admin/token-policies/{name}`; update the list-`get` description (read-only → CRUD surface) |
| `docs/error-codes.md` | extend the `invalid_policy` row (line ~1010) with the token-policy usage (`max_ttl`/`max_refresh_depth`/`max_active_sessions` negative, `require_renew_after` outside (0,1], empty name) |
| `docs/config-reference.md` | `token_policies.sqlite` knob + seed-only-when-empty semantics + the File/Policies/sqlite combination contract |
| `docs/architecture/DIRECTORY_MAP.md` | new `domains/tokenpolicy/sqlite` package ownership |
| `AGENTS.md` §4 | cross-replica invalidation list gains token-policy changes |
| `platform/cluster/bus.go` + `bus_test.go` | new kind + kind-set tests |

---

## Failure modes（总表）

| Mode | Behavior | Contract |
|---|---|---|
| Store outage at issuance (`Policies()` error) | issue unclamped | FAIL OPEN (unchanged) |
| Store outage at admin GET/PUT/DELETE | `500 internal` | governance surface, not credential path (unchanged) |
| Unknown YAML field in bundle | boot fails loud | new; replaces silent disable |
| Negative dimension / renew fraction / empty name (config or PUT) | boot fails / `400 invalid_policy` + description | new; replaces silent inertness |
| `max_ttl` > issuer default | advisory: boot `logger.Warn` / PUT 200 `warning`; effective cap = default | new; widening mechanically impossible |
| sqlite open/migrate failure at boot | boot fails loud (config error) | mirrors threat-policy sqlite |
| sqlite DB down after boot | snapshot serves; writes fail `500` | FAIL OPEN for evaluation |
| Bus publish failure after PUT/DELETE | logged; writer's snapshot already fresh; peers converge on next event/restart | FAIL OPEN (best-effort, mirrors `InvalidateConnectionCache`) |
| Bus receive failure / dropped event | stale snapshot serves; recovery reseed converges | FAIL OPEN |
| `KindControlPlaneRestore` | full flush incl. token-policy snapshot refresh | recovery convergence |
| Unknown kind from newer peer | ignored (`default` arm) | mixed-version rollout unchanged |

## What could break the design（风险与缓解）

1. **默认 TTL 漂移（最危险）**: if `WithTokenPolicyDefaultTTL` is wired from a
   different value than the issuers' `WithEd25519TokenTTL`/`WithECDSATokenTTL`,
   the min-clamp can still widen (engine default > issuer default). Mitigation:
   single plumbing from `cfg.Server.TokenTTL` at one call site
   (`wireTokenPolicy`/`build_signing_issuers` both read `b.cfg.Server.TokenTTL`),
   an invariant comment on both, and a rootcov server test asserting
   default-client issuance ≤ the configured TokenTTL with a non-1h value.
2. **`Store` 接口扩展是破坏性变更**: any implementer outside `domains/tokenpolicy`
   breaks. Grep-verified in-repo implementers are `memory`, the new `sqlite`, and
   test fakes; all updated in the same change. The server holds the store as
   `tokenpolicy.Store` (sso_protocol.go:50) — no other assertion points.
3. **拒绝顺序/理由标签跨后端漂移**: sqlite `ORDER BY name` vs memory insertion
   order changes which deny reason is recorded for overlapping rules. Deny outcome
   and wire response are order-independent; the reason is audit/metric-only. Mitigated
   by documenting the divergence on both stores; accepted.
4. **播种语义被误解**: an operator edits `token_policies.policies` expecting it to
   apply to an existing DB — it silently won't (table non-empty). Mitigation: loud
   boot log when seeding is skipped, config-reference documentation, and the
   seed contract is empty-checked only (never overwrite).
5. **陈旧快照过度拒绝**: a peer with a stale snapshot may keep denying after a
   rule was deleted until the event lands. Accepted (governance knob, converges);
   `Refresh` failures are logged. If this ever matters, the escape hatch is
   `Refresh` on a short TTL — deliberately NOT in scope (hot path stays disk-free).
6. **PUT 发布遗漏**: the `bool` return of `HandleAdminPutPolicy` is the only link
   between "stored" and "published". A refactor that changes the handler's response
   shape could silently drop the publish. Mitigation: server-level test asserting
   the publish (the two-server `test/` integration is exactly this), plus the
   comment contract on the handler.
7. **严格解析的既有部署兼容性**: deployments with typo'd/negative fields that were
   silently inert now fail boot. This is the intended loud failure, but it is a
   boot-breaking change for them; documented in config-reference as a migration note.
8. **`clamp_issuer_test.go` 签名变更**: `NewClampingIssuer` gains a parameter —
   existing tests updated in the same change; behavior for `MaxTTL ≤ default` and
   nil-store no-op must stay byte-identical (regression-covered by the existing
   tests, which stay green).
9. **迁移命名空间/表名冲突**: shared-DB deployments (multiple stores in one file
   via `NewWithDB`) need distinct `migrate` namespaces and table names —
   `"token_policies"` is unique vs `"threat_policies"` etc. The boot
   `CheckSQLiteSchema` check uses `TokenPolicyMaxVersion()` so an older binary
   against a forward-migrated DB fails loud.

## 验收映射（make ci 之前）

- `yaml_test.go`: typo-field rejection (`max_ttl_`), existing fixtures byte-identical.
- `validate_test.go` (new): negative depth/sessions/TTL, `require_renew_after: 2`,
  empty name → error; `max_ttl: 2h` + `defaultTTL: 1h` → advisory only.
- `evaluate_test.go`: `DefaultTTL` min-clamp truth table; legacy zero-DefaultTTL
  behavior unchanged.
- `clamp_issuer_test.go`: new signature; default-TTL client ≤ default; nil-store no-op.
- `memory/store_test.go`: CRUD, overwrite-in-place, delete-unknown →
  `ErrPolicyNotFound`, concurrent Put/Policies COW (`-race -count=10+`).
- `rootcov_admin_token_policies_test.go`: PUT→GET→DELETE, 400 `invalid_request` vs
  `invalid_policy`, 401 `realm="admin"`, unmounted 404 for all three methods.
- `domains/tokenpolicy/sqlite/*_test.go`: CRUD round-trip, reopen persistence,
  migration idempotency (double `New`), concurrent Put/Policies `-race`.
- `test/` (package `ssotest`): two servers, one DB file — PUT via A visible on B
  after invalidation flush; B restart survival.
- Gates: `go build ./... && go vet ./...`, architecture/maintainability tests,
  `make ci` (openapi check included).

---

# Distributed-systems 审查（状态地图 / Findings / 场景表 / 保证）

证据标注：**Verified** = 本次对当前树的 grep/代码核实；**Proposed** = 本设计新增、尚未实现。本设计不引入新的凭据/撤销状态，不触碰 JTI/refresh-family/会话状态机；token-policy 是治理旋钮，其失效收敛机制与 fail-CLOSED 的撤销 reseed（`reseedRevocationDenySets`，失败保持 degraded）刻意分属两侧：策略快照刷新失败只记录日志并继续服务陈旧快照。

## 状态地图（State Map）

| 状态 | Owner | 存储 | 持久性 | 一致性 | 复制 | 故障转移 |
|---|---|---|---|---|---|---|
| 生效策略集（每副本评估快照） | `domains/tokenpolicy.Store` 实现（`memory` slice COW / 新 `sqlite` 内存快照） | 进程内存 | 无（可从 DB/config 重建） | 写者副本立即一致（写后同步刷新、响应前完成）；对端最终一致（总线事件驱动） | 每副本一份；sqlite 场景经共享文件 + 事件刷新 | 启动 `New` 重建；`Refresh` 恢复；陈旧快照继续服务（fail open） |
| 持久化策略行 | 新 `domains/tokenpolicy/sqlite` | `token_policies` 表（`name TEXT PRIMARY KEY`, `policy_json`），SQLite 文件 | 持久（SQLite journal；单行 upsert 原子） | 单写者串行（SQLite 文件锁）；按 name 最后写者胜（LWW），无版本号 | 多副本指向同一文件 = 单一事实源（threataction/sqlite 同款部署模型，Verified 包文档） | boot open/migrate 失败响亮失败（配置错误）；运行中写失败 `500`；评估不受影响 |
| 迁移版本 | `platform/migrate` + `serverbuildsign.CheckSQLiteSchema`（Verified 模式：build_app_core.go:64-71 等） | 命名空间化迁移表；`Run` 用单连接 `BEGIN IMMEDIATE` + busy_timeout（Verified migrate.go:161-200） | 持久 | n/a | 每副本 boot 时独立校验 | 旧二进制 × 前向迁移 DB → boot 响亮失败（决策 9 风险 9） |
| 跨副本失效事件 | `platform/cluster` bus（`memory` / `etcd`）+ `StartInvalidationBus` 自愈循环（Verified server_invalidation.go） | etcd 短 lease 键 / 进程内 channel | 短暂（event TTL） | best-effort、无顺序保证、幂等（bus.go 契约："a dropped Event degrades a replica to its existing TTL fallback, never to a wrong answer"） | etcd watch 扇出；memory 非阻塞投递、慢消费者丢弃 | 订阅关闭 → degraded 标记 + 指数退避 1s→30s（确定性抖动）重订阅 + `resubscribeAndReseed`；/readyz 转 not-ready（仅接总线时） |
| 发行方默认 TTL | `cfg.Server.TokenTTL` → `WithEd25519TokenTTL`/`WithECDSATokenTTL`/`WithRSATokenTTL`（Verified build_signing_issuers.go:44,68,97）+ 新 `WithTokenPolicyDefaultTTL` | 配置 | n/a | 单点来源（同一 cfg 字段，双消费者） | 经配置分发 | n/a（接线期不变量，见 F1） |

## Findings（按严重度）

### F1 [High] 默认 TTL 双管道漂移——min-clamp 可放宽的唯一剩余通道

- **证据**（Verified + Proposed）：issuer 侧三个 TTL 接线点均读 `b.cfg.Server.TokenTTL`（build_signing_issuers.go:44,68,97）；设计新增 `WithTokenPolicyDefaultTTL` 也从同一字段接线（build_app_security.go:281 调用点附近）。当前不存在该字段（Proposed）。
- **触发**：未来某次改动只改 issuer 侧或只改 engine 侧的接线值（例如 issuer 改为 30m 而 engine 仍 1h）。
- **用户影响**：`max_ttl: 2h` 规则对默认客户端把寿命从 30m 拉到 1h——治理"只收紧不放宽"不变量被破坏；这是安全相邻（治理绕行）而非凭据泄露。
- **恢复**：修正接线值；已放宽的令牌按各自 exp 自然过期。
- **纠正模式**：单一接线点（两处都读 `b.cfg.Server.TokenTTL`）+ 不变量注释 + rootcov 服务器测试：非 1h `TokenTTL` 配置下，默认客户端（`RequestedTTL==0`）签发 TTL ≤ 配置值。该测试是 F1 的回归闸门，缺它则风险 1 无验证。

### F2 [Medium] 陈旧快照无 TTL 兜底——总线永久丢失时收敛无界

- **证据**（Verified + Proposed）：bus.go 契约声称丢事件"只退化为既有 TTL 兜底"，但 token-policy 快照（决策 10）**没有** TTL 兜底：`Policies()` 永不落盘，刷新仅由 `KindTokenPolicyChange`、`KindControlPlaneRestore`、重启触发——一个被丢弃的 policy 事件不会被其他 kind 的事件（如 `KindClientChange`）顺带治愈。
- **触发**：总线永久丢失（etcd 不可达超过退避上限且订阅长期不恢复）、或事件在投递中被丢且之后再无 policy 写。
- **用户影响**：对端副本无限期服务过旧策略集：已删规则继续拒绝（over-deny）或新规则不生效（under-enforce）。治理旋钮非凭据面，但**违反**总线契约"never a wrong answer"的前提（陈旧快照即 wrong answer，只是后果有界）。
- **恢复**：重启该副本；或总线恢复后 `resubscribeAndReseed` → `flushInvalidationCaches`（设计将 policy 刷新并入）。
- **纠正模式**：接受 + 文档化（决策 10/风险 5 已列）；建议新增"快照年龄"metric（上次成功 Refresh 的时间戳）以便告警发现无界陈旧——低成本、不动热路径。周期 `Refresh` 逃逸口维持 out of scope。

### F3 [Medium] 共享文件拓扑约束未显式声明——per-replica DSN 会静默分裂"单一事实源"

- **证据**（Verified + Proposed）：threataction/sqlite 包文档声明"shared across replicas pointed at the same database file"；SQLite 依赖 POSIX 文件锁（对象存储/非 POSIX 挂载下锁语义失效或写失败）；`migrate.Run` 依赖单连接 `BEGIN IMMEDIATE`（migrate.go:161-200）。
- **触发**：各副本配置了**不同的** `sqlite` DSN 路径（每副本独立文件），或把文件放在 S3/对象存储挂载上。
- **用户影响**：规则跨副本发散且无任何机制检测（config-digest 漂移检测只覆盖配置文件，不覆盖 DB 内容）；写锁异常时 admin 写 `500`。
- **恢复**：修正 DSN 指向同一 POSIX 共享文件；按需重建/重播种。
- **纠正模式**：config-reference 显式声明部署不变量："多副本 sqlite 必须指向同一 POSIX 共享文件系统（NFS/GPFS 等）上的同一文件"；per-replica 文件列为不支持拓扑（见下）。并发双写同一 name 的 LWW 语义文档化（与 threataction 一致）。

### F4 [Low] DELETE 非幂等重试——重试方收到 404 误报

- **证据**（Verified）：threataction `HandleAdminDeletePolicy` 未知 name → `404 not_found` 先例；决策 7 沿袭。
- **触发**：admin 客户端 PUT/DELETE 响应超时后重试 DELETE。
- **用户影响**：第二次 DELETE 返回 404，客户端可能把"已删除"误判为"删除失败"而重试/告警；无状态损坏（效果幂等）。
- **恢复**：无需；404 即"已不存在"。
- **纠正模式**：文档化该语义（错误码表 + openapi 描述）；幂等键机制 out of scope（治理低频面，与 threataction 对齐）。

### F5 [Low] 播种竞态——双副本同时首启空表

- **证据**（Proposed）：决策 11 seed-if-empty；种子经校验后写入（upsert）。
- **触发**：两个副本同时对新空共享文件 boot，均读到空表、均执行播种。
- **用户影响**：各副本种子配置一致（正常部署）→ 逐 name upsert 幂等收敛，良性；配置不一致（本身是配置错误；config-digest 漂移检测仅报告不阻止）→ 按 name LWW 混合态。
- **恢复**：修正配置、手工收敛。
- **纠正模式**：文档声明"各副本种子配置必须一致"；可选强化：种子写为单事务"仅当表空时 INSERT-if-absent"，消除混合态角落（低成本，非必须）。

### F6 [Info] 发布为同步网络往返——admin PUT 尾延迟受总线影响

- **证据**（Verified）：etcd `Publish` = `Grant`+`Put`（etcd.go:108），调用方传 `context.Background()`（InvalidateConnectionCache 同款），无显式超时；memory bus 非阻塞。
- **触发**：etcd 慢或分区。
- **用户影响**：admin PUT/DELETE 尾延迟上升；发布失败仅日志、写不回滚（正确）。
- **恢复**：无。
- **纠正模式**：沿用现有模式（与 `InvalidateConnectionCache` 字节同级）；不引入 `WithTimeout` 以免偏离既有先例。

### F7 [Info] deny-reason 标签跨后端/跨迁移漂移（audit-only）

- **证据**（Verified）：memory 保留插入序（决策 6）vs sqlite `ORDER BY name`（决策 9）；`Evaluate` 中顺序只决定 reason 标签，deny 结果与 `EffectiveTTL`/`RenewAfter` 均为顺序无关（组合取最严、deny 任一匹配即拒）。
- **触发**：后端切换（config 播种 → sqlite 迁移）或跨后端混跑；重叠规则的首个 deny reason 变化。
- **用户影响**：audit/metric 标签变化；wire 与 deny 结果不变。
- **恢复**：无。
- **纠正模式**：两处存储的 doc 注释互指（决策 6/9 已做）；在 feature-matrix 备注该差异。

## 场景表（Scenario Table）

| 场景 | 触发 | 行为 | 契约/恢复 |
|---|---|---|---|
| 分区（副本 A 与总线隔离、共享 DB 可达） | etcd 分区；A 的 PUT 直接落 DB，发布失败仅日志 | A 快照新鲜（写后同步刷新）；对端无事件 → 陈旧直到下一个 policy 事件/`KindControlPlaneRestore`/重启 | fail open；收敛由恢复或重启保证（F2） |
| 分区（共享 DB 也不可达） | A 的 admin 写 `500`；评估仍走本地快照 | 评估照常签发 | fail open 评估、治理面失败（现状不变） |
| 崩溃（PUT 落库后、快照刷新前） | 进程死亡 | sqlite 单行 upsert 原子；重启 `New` 从 DB 重载 → 一致 | 持久性由 DB 保证，无半写态 |
| 崩溃（迁移中途） | 首启迁移中死亡 | `BEGIN IMMEDIATE` 单事务 → 无半迁移态；二次启动幂等 | boot 安全（migrate.go:161-200） |
| 崩溃（总线订阅） | Subscribe channel 关闭（etcd watch 压缩/leader 变更/网络抖动） | 降级标记 + 退避 1s→30s 重订阅；期间不应用任何失效；/readyz not-ready | 恢复时 `resubscribeAndReseed` → flush + revocation reseed → healthy |
| 重试（客户端重试 PUT） | 响应丢失后重放 | upsert 幂等 | 安全 |
| 重试（客户端重试 DELETE） | 响应丢失后重放 | 第二次 `404 not_found` | 效果幂等、响应非幂等（F4） |
| 重试（发布） | 发布失败 | 不重试、仅日志；写不回滚 | best-effort（与 `InvalidateConnectionCache` 一致） |
| 时钟回拨 | 副本时钟回拨 | `Evaluate` 纯函数无时钟依赖；`RenewExceeded`/`RenewAt` fail-safe（不可测 → false）；token exp 为绝对时间 | 不新增时钟假设；现有行为不变 |
| 时钟前跳 | 副本时钟前跳 | TTL 钳制为 duration 比较，与墙钟无关 | 无影响 |
| 陈旧缓存（单个 policy 事件丢失） | 投递丢失 | 快照过旧；仅同类事件/control-plane restore/重启刷新（其他 kind 不治愈） | 有界（下次事件）或重启收敛（F2） |
| 依赖故障（sqlite boot 后 down） | DB 文件不可读/锁死 | `Policies()` 走快照 → 签发正常；admin GET/PUT/DELETE `500` | fail open 评估（现状不变） |
| 依赖故障（sqlite boot 时 down/损坏） | open/ping/migrate 失败 | boot 响亮失败（配置错误） | 镜像 threat-policy sqlite |
| 依赖故障（总线 down） | 发布失败日志；订阅降级 | 写仍成功、快照仍新鲜（写者）；对端陈旧 | fail open + 恢复 reseed |
| 双副本并发写同一 name（近 split-brain） | 两 admin 同时 PUT 同 name | SQLite 单写者串行化；按 name LWW；各副本快照按自身事件刷新 | 无版本/乐观锁；LWW 文档化（与 threataction 一致） |
| 恢复（总线恢复） | 重订阅成功 | `resubscribeAndReseed` → `flushInvalidationCaches`（含新 policy 快照 Refresh）→ healthy；readiness 仅在 reseed 成功后转绿 | 恢复收敛；policy 刷新失败仅日志（fail open），revocation reseed 失败保持 degraded（fail closed）——不对称是刻意的 |
| 读己之写 | admin PUT 返回前 | 写者快照已同步刷新 | 写者立即一致 |
| 对端读取 | PUT 后对端 GET | 事件到达前可能返回旧集 | 最终一致，窗口 = 总线投递延迟 |
| 混合版本滚动（新→旧） | 新二进制发布 `KindTokenPolicyChange`，旧二进制接收 | 旧二进制 `default` 分支忽略（事件丢弃） | 旧副本陈旧至重启；无崩溃（`applyInvalidationSafe` recover 兜底） |
| 前向迁移（旧→新 DB） | 旧二进制 boot 于已迁移 DB | `CheckSQLiteSchema` 版本不符 → boot 响亮失败 | 非静默降级（决策 9 风险 9） |

## 声明性保证 / 不支持拓扑 / 验证测试 / 残余风险

### 声明性保证（stated guarantees）

1. **评估 fail open**（Verified，AGENTS.md §3）：store 错误永不阻断签发；`ClampingIssuer.Issue` 与 `enforceTokenPolicy` 已如此，sqlite 快照模型保持。
2. **只收紧不放宽**：`EffectiveTTL` 永不超过正 `RequestedTTL`；`RequestedTTL==0` 时永不超过 `DefaultTTL`——前提是 F1 的单一接线成立（Proposed + 回归测试）。
3. **写者 read-your-writes**（Proposed）：PUT/DELETE 返回前本副本快照已刷新。
4. **热路径零落盘**（Proposed）：`Policies()` 只服务快照；磁盘 I/O 仅在 admin 写、boot、总线事件时发生。
5. **总线 best-effort**（Verified 机制 + Proposed 新 arm）：事件丢失不回滚写、无顺序保证；恢复路径（`KindControlPlaneRestore` + 重订阅 reseed）收敛遗漏事件。
6. **按 name LWW/upsert 幂等**；seed 仅空表一次、绝不覆盖（Proposed 决策 11）。
7. **deny 结果与策略顺序无关**；reason 标签跨后端可漂移且仅进 audit/metric（Verified `Evaluate` 组合规则）。
8. **Oracle-safe wire**（Verified 既有 + Proposed 新端点）：decode 失败 `invalid_request`、语义失败 `invalid_policy` + description；deny reason 永不上线。

### 不支持拓扑（unsupported topologies）

- **per-replica sqlite DSN**（各副本独立文件）：静默分裂单一事实源，无检测机制——必须同一 POSIX 共享文件（F3）。
- **非 POSIX 共享存储**（S3/对象存储挂载）：SQLite 文件锁语义不成立。
- **无总线多副本 + sqlite**：对端仅靠重启收敛（单副本 sqlite 完全支持；bus 是可选接线）。
- **并发双写同一 name 的乐观锁期望**：无版本号、LWW（与 threataction 一致，文档化而非承诺）。
- **混合版本长期运行**：旧二进制忽略新 kind、新二进制读旧表——仅限滚动窗口，前向迁移被 boot 校验响亮拒绝。

### 验证测试（validation tests）

- `test/`（`package ssotest`，Proposed）：双服务器共享一个 DB 文件——A 的 PUT 在失效刷新后对 B 可见；B 重启后规则存活（重启持久性 + 对端收敛的最短集成证明）。
- 总线（Proposed）：`KindTokenPolicyChange` 分发臂、`KindControlPlaneRestore` → `flushInvalidationCaches` 含 policy 刷新；混版本未知 kind 忽略（沿用现有 server_invalidation 测试模式）。
- sqlite（Proposed）：CRUD 往返；关重开持久化；双 `New` 迁移幂等；并发 Put/Policies `-race -count=10+`。
- 播种竞态（Proposed）：两个并发 `New`+seed 对同一空文件——收敛且无错误（busy_timeout 机制 Verified 于 migrate.go:197-200）。
- rootcov（Proposed 扩展 Verified 的 rootcov_admin_token_policies_test.go）：未接线时 GET/PUT/DELETE 均 404；无 bearer 401 `realm="admin"`；`invalid_request` vs `invalid_policy` 拆分。
- F1 回归闸门（Proposed）：非 1h `TokenTTL` 下默认客户端签发 TTL ≤ 配置值（rootcov 服务器级）。
- 契约门：`go build ./... && go vet ./...`、架构/可维护性测试、`make ci`（含 openapi 校验）。

### 残余风险（residual risks）

1. **F1 TTL 接线漂移**——唯一可让 min-clamp 放宽的通道；由单一接线点 + rootcov 回归测试缓解，仍是本设计头号残余风险。
2. **F2 无界陈旧窗口**（总线永久丢失时）——接受；无快照年龄 metric 是当前缺口，建议后续补 `last_refresh` gauge。
3. **快照与 DB 内容偏差无主动检测**——`Policies()` 永不落盘意味着偏差只能靠事件/重启自愈；与风险 2 同源。
4. **F4 DELETE 重试语义**——文档缓解。
5. **F5 种子竞态**——依赖"各副本种子配置一致"的运维不变量（config-digest 漂移检测仅报告）。
6. **迁移命名空间/表名冲突**——`token_policies` 表名与 `threat_policies` 等唯一（Verified）；`CheckSQLiteSchema` 前向校验缓解版本冲突。
