Spec written and verified: `docs/auto/domains-tokenpolicy-direction3-spec.md` (285 lines, mirrored location — `docs/auto` links to `docs/architect-analysis/auto`, matching the direction-2 spec convention). All cited symbols and line numbers verified against the tree.

## Summary of the specification

**Scope**: direction 3 from `docs/auto/domains-tokenpolicy-analysis.md` — upgrading the policy selector from client-only to tenant/subject-aware. Three evidence-backed improvements, each under a `##` heading with name, problem, evidence (file/symbol), proposed behavior, and acceptance check:

### ## Improvement 1: `TenantID` 选择器（治理单元升级到租户维度）
- **Evidence**: `Policy`/`PolicyInput` have no tenant field (`tokenpolicy.go:53-98,112-127`); `matches()` is exact client equality only (`evaluate.go:53-63`); platform precedent is per-tenant everywhere — `tenantTokenStrategies` key isolation (`server_helpers.go:39-40`), `Client.TenantID` (`shared/core/types.go:39-47`), `TenantScopedClientStore.ListByTenant` (`spi.go:93`).
- **Key design**: empty `tenant_id` = global rule; additive matching with existing strictest-wins combination, so tenant rules can only tighten global rules (never widen). Tenant threaded through all four seams (scope-combo gate, refresh-depth gate, session cap, and `ClampingIssuer` via a new mint-time `core.Subject.TenantID` stamped at the ~10 existing issue call sites, mirroring the `ServingRegion` precedent).

### ## Improvement 2: 主体感知选择器（Subject 精确/通配 + 租户角色）
- **Evidence**: `PolicyInput.Subject` is populated by `EnforceRefreshDepthPolicy` and `sessionPolicyCapExceeded` but never read by `matches()`; `TenantRole` closed set member/admin/guest + `TenantUserStore` single-source-of-truth (`tenant_user.go:9-26`); `s.tenantUserStore` usage precedent at `server_logout.go:322-330`.
- **Key design**: `Policy.Subject` (trailing-`*` wildcard, same semantics as `scopePresent`) + `Policy.SubjectRoles` closed set; role resolution at the session seam fails open (no roles ⇒ role selector doesn't match).

### ## Improvement 3: `ClientID` 通配匹配 + 新选择器字段严格 YAML 校验
- **Evidence**: `matches()` exact-only client equality vs the `scopePresent` wildcard precedent in the same file; non-strict `yaml.Unmarshal` in `tokenpolicy/yaml.go:19-24` vs conditionalaccess's `DisallowUnknownField` (`conditionalaccess/yaml.go:33`).
- **Key design**: the specific hazard is a misspelled `tenant_id` being silently dropped → a "tenant rule" quietly becomes a fleet-wide global rule (empty selector). Strict parse + a shared `Validate([]Policy) error` pure function (reject bare `*` wildcards, non-closed-set roles) so config and YAML fail loud.

Also includes a non-negotiable invariants section (oracle-safe wire unchanged, single-tenant byte-compatibility, fail-open preserved, domain stays pure, `server_helpers.go` 493/500-line budget respected via call-site threading) and the AGENTS.md §5.6 contract-updates table (`openapi.yaml:6836`, `config-reference.md:588`).
