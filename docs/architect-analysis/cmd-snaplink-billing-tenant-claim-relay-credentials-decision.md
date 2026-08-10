# Decision: §3.1 relay credential surface — single-tenant-per-deployment relay (branch A)

- Resolves: the open §3.1 decision blocking §6 step 3 (rollout Q3) of `docs/architect-analysis/cmd-snaplink-billing-tenant-claim-design.md`.
- Amends: design §1.1 (decision 3), §3.5 (README bullet), §4 (shared-client row), §6 step 3; hardening `cmd-snaplink-billing-tenant-claim-hardening.md` §3.1 (recommended resolution), §6 step 3, §8 delta 2. Supersedes the hardening doc's "recommended resolution, in order" list: the option ordering is now decided, not open.
- Status: decision (every claim re-verified against HEAD; file:line cited)

## 1. The question

B4-1 mints `tenant_id` = the IdP client's single `tenant_id` binding
(`internal/handler/tokengrant/token_client_credentials.go:52`; `config/config_client.go:24` — one
value per client, empty = no affinity). The billing quota relay, however, holds exactly one
credential pair: `quotaRelayConfig{ClientID, ClientSecret}` from
`SNAPLINK_BILLING_QUOTA_CLIENT_ID/SECRET` (`cmd/snaplink-billing/quota_relay.go:26,42-59`), built
into exactly one `OAuthTokenSource` (`buildQuotaTokenSource`, quota_relay.go:423-431) whose
singleflight key is the literal `"client"` (`infrastructure/auditgovernance/oauth_token_source.go:61,151`)
and whose cache is per-client, never per-tenant (:44-46). The relay claims the whole
`tenant_commerce_quota_outbox` with no tenant filter
(`infrastructure/postgres/tenantcommerce/outbox.go:304-330` — the claim SQL selects every
pending/leased row for the owner).

Consequence (design §1.1 decision 3, verified): under the T-8(e) cross-check (R3,
`verifyBearerTenant` in `interfaces/ssoclient/quotaprojection/http_client.go`), a shared relay
client can deliver for at most one tenant — the one its IdP binding names; a client with an
empty binding mints no claim and every delivery pauses (F3 class). "Register one relay client
per tenant" (design §4/§6 step 3) is **not expressible** in the current binary: the billing
deployment cannot mint as different clients per event, and no tenant filter or client map
exists in the relay. The two expressible futures are:

- **Branch A — single-tenant-per-deployment relay**: each billing deployment's quota relay
  serves exactly one tenant; the existing env pair's client is IdP-bound to that tenant.
  Zero code/config change.
- **Branch B — per-tenant credential surface**: the deployment holds one credential pair per
  served tenant and selects the client per outbox event. Requires new config surface.

## 2. Evaluation against the four gates

| Criterion | Branch A (single-tenant-per-deployment) | Branch B (per-tenant credential surface) |
|---|---|---|
| **Config-reference discipline** | Zero new keys, zero new rows, zero new files. The existing `SNAPLINK_BILLING_QUOTA_CLIENT_ID/SECRET` pair's **values** become per-deployment (the client the pair names is IdP-bound to the served tenant) — `docs/config-reference.md:835-851` rows stay accurate verbatim. `validateDisabled` (quota_relay.go:152, orphan-setting rejection) and `validateProjectionCredentialSeparation` (quota_relay.go:268-287, exactly three pairs: audit/quota/retention) untouched. | Violates the requirements' explicit non-goal — "No new config keys, `Err*`, endpoints, OpenAPI surface, or audit event types" (`cmd-snaplink-billing-tenant-claim-requirements.md:57`). Carriage options each break the strict model: per-tenant env keys `SNAPLINK_BILLING_QUOTA_TENANT_<T>_CLIENT_ID/SECRET` require an env-name schema over arbitrary tenant IDs plus `os.Environ` enumeration, which the getenv-driven `defaultsFromEnvironment` (config.go:89-131) cannot express; a tenant→credentials file would be the repository's first secret-bearing config file. `validateProjectionCredentialSeparation` and `validateDisabled` need restructuring for an open-ended pair count. New config-reference section required. |
| **Env-only secrets handling** | Unchanged. "PostgreSQL DSN 和 Audit OAuth client secret 只从环境变量读取" (`cmd/snaplink-billing/README.md:17-18`), "Secret 仅从环境读取；命令行没有 secret flag" (:199), `config.example.env` "Secret-bearing values are environment-only". The one pair stays in the two existing env keys. | The only discipline-compliant carriage is per-tenant env pairs keyed by tenant ID — not expressible (see above; tenant IDs are validated non-empty/whitespace-free by `ValidateQuotaTenantID` but otherwise arbitrary, so no bounded env-key schema exists). File carriage (the `source-bindings.example.json` strict-JSON precedent carries **no secrets** — `config.example.env` and README:17-18 make env-only a documented invariant) conflicts directly. Branch B needs a secrets-carriage design decision of its own before it can satisfy this gate. |
| **ADR-0009 module rules** | Coherent. The billing profile is "an independent `snaplink-billing` commerce and usage-metering process" whose composition is "embedded, restart-only `billing-runtime`" (ADR-0009 §3, §6); one deployment = one composition = one relay = one client is exactly that model. "Runtime configuration and backend topology decide which compiled capabilities are active" (ADR-0009 §3) — the single-tenant scoping is a topology decision, not a capability or module change. No manifest, profile, or registration delta; the audit relay's hot-activation lifecycle is untouched. | Technically still one cold module (per-tenant credentials remain cold — ADR-0009 §6: hot activation "不热换 OAuth 凭据"), but it invents the first tenant-keyed credential surface in the repository with no module-system counterpart: the `billing-runtime` composition has no per-tenant instantiation mechanism, and a tenant→client map is a new config class ADR-0009 neither describes nor constrains. No `plugin.Open`/registration concerns (it is plain config), but the precedent is a net-new contract that must be specified, documented, and validated (config-reference rows, startup validation, credential-separation checks per tenant). |
| **e2e fixture** | The fixture is already branch-A-shaped: one client `billing-relay`, one tenant `tenant-e2e`, one minted token (`test/quota_projection_e2e_test.go:59-60` registry source, `:85-87` mint). A7's `Subject.TenantID: "tenant-e2e"` keeps the positive path "delivers exactly as today" (design §7 A7), A8/A9 negative cases are unchanged, and the fixture remains representative of the recommended topology. No harness growth. | The fixture's single token source (`newQuotaProjectionE2EClient` mints one token) would need a per-tenant credential map to stay representative of the multi-tenant relay; the direction's A7 wording ("the positive path delivers exactly as today") would no longer describe the production shape, and the A7-A10 harness surface grows (per-client minting, per-tenant client selection in the authorizer). Contradicts the fixture's role as "the T-8(e) e2e exercises the production check" (requirements R3.2). |

**Net verdict.** Branch A satisfies all four gates with **zero code, config, module, or fixture
change**; it is the only branch consistent with the requirements' "no new config keys" non-goal
and the env-only secrets invariant. Branch B fails the config-reference and env-only gates
unless it carries its own requirements amendment and secrets-carriage design; it also
contradicts the direction's stated surface (requirements §3). The common case — a billing
deployment serving one commercial tenant, or serving several tenants of which only one has
entitlement traffic (only tenants with subscription/entitlement facts ever appear in the quota
outbox) — is served exactly by Branch A. The multi-tenant-per-deployment relay is a real but
secondary operational shape; it becomes a declared follow-up direction, not a silent extension
of this change.

## 3. Decision

**Adopt Branch A: the quota relay of a billing deployment serves exactly one tenant, named by
the relay client's IdP `tenant_id` binding.** Concretely, for every billing deployment whose
quota relay is enabled:

1. The deployment's `tenant_commerce_quota_outbox` may hold events for exactly one tenant.
   Detected with `SELECT COUNT(DISTINCT tenant_id) FROM tenant_commerce_quota_outbox;`
   (columns verified: `infrastructure/postgres/tenantcommerce/outbox.go:94-99`).
2. The IdP `clients[]` entry for `SNAPLINK_BILLING_QUOTA_CLIENT_ID` carries
   `tenant_id` = that tenant. Empty binding is not a valid steady state for an enabled relay:
   it mints no claim and every delivery pauses (F3, fail-closed on absence).
3. `projection_ingress.sources[]` for that client covers exactly that tenant's sources
   (the IdP registry's "a client may own many tenant sources" (`interfaces/sso/quota.go:27-29`)
   remains true, but the claim gate makes any other tenant's sources unreachable through this
   client — do not register them).
4. The audit governance relay is **not** subject to this constraint (no claim cross-check on
   that path; R3 touches only `quotaprojection/http_client.go`); the README's "相同 relay
   client 可以服务多个租户" sentence for the audit relay stays.

**Branch B (per-tenant credential surface) is deferred as a follow-up direction**, triggered
only by a demonstrated requirement: a deployment with `COUNT(DISTINCT tenant_id) > 1` in the
quota outbox that cannot be split. The follow-up must carry its own requirements change
(amending the "no new config keys" non-goal), a secrets-carriage design (env-pair naming
schema with validated tenant-ID charset, or an explicit env-only carve-out decision), new
config-reference rows, restructured credential-separation validation, and the e2e fixture
extension. It must not be smuggled into this change.

**Sequencing note (unchanged from the hardening doc):** the pre-flight is a documented
precondition, not a mechanical interlock; the step-2 deployment-blocking mint pin and the
post-deploy smoke (hardening §2.3) remain the enforcement. An un-migrated shared relay client
that ships R2/R3 fails visibly — `reasonAuthorization` pauses and `/readyz` degrades at
`SNAPLINK_BILLING_QUOTA_MAX_LAG` (default 5 m) — and recovers by either completing the split or
reverting (hardening §5).

## 4. §6 step-3 wording (replacement for design §6 step 3 and hardening §6 step 3)

> 3. **Operator pre-flight — single-tenant relay scoping (branch A, §3.1 decision)**:
>    the quota relay of a billing deployment serves exactly one tenant — the relay holds one
>    client credential pair and the mint-time `tenant_id` claim equals that client's IdP
>    binding, so a shared relay client can deliver for at most one tenant. For each billing
>    deployment, before deploying R2/R3:
>
>    a. **Detect**: `SELECT COUNT(DISTINCT tenant_id) FROM tenant_commerce_quota_outbox;`
>       on the deployment's PostgreSQL. 0 or 1 ⇒ single-tenant relay, proceed to (b).
>       More than 1 ⇒ the deployment runs a shared relay client: split the deployment so each
>       billing deployment's quota outbox holds one tenant, or register the multi-tenant relay
>       requirement as the follow-up per-tenant credential surface (branch B — separate
>       requirements change; not in this direction). R2/R3 must not ship against a shared
>       relay client.
>
>    b. **Bind**: set the IdP `clients[]` entry of `SNAPLINK_BILLING_QUOTA_CLIENT_ID` to
>       `tenant_id` = the served tenant (cold restart of the IdP fleet; an empty binding
>       pauses every delivery — F3 class); reconcile `projection_ingress.sources[]` so the
>       client's sources cover exactly that tenant's sources (SIGHUP revision; `tenant_id`
>       immutable per source, `docs/config-reference.md:856`).
>
>    c. **Verify** (hardening §3.4): per-client mint check (decoded JWS payload `tenant_id` ==
>       served tenant — the T-8(a) assertion per client, catching the cold-config typo before
>       it reaches the relay); one observed delivery (outbox drains, `delivered_revision`
>       advances); zero rows with `last_error = 'quota projection authorization rejected'`
>       after the F5 window; `/readyz` `tenant_quota_projection` green.
>
>    d. **Additive-only**: keep the shared client's credentials and registered sources intact
>       until the rollback window closes (hardening §5.2.1 — an unbound shared client is
>       harmless post-revert because the IdP-side handler never reads the claim,
>       `interfaces/sso/quota.go` non-goal).

The reference to "multi-tenant deployments register one relay client per tenant" in design §4
(compatibility table) and §3.5 (README bullet) is replaced by this branch-A statement: a quota
relay client's IdP tenant binding names the single tenant its deployment's relay serves;
multi-tenant deployments split or adopt the branch-B follow-up.

## 5. README quota-section update (R5.1, exact replacement)

The `cmd/snaplink-billing/README.md` quota section ("Entitlement 到 SSO 配额投影") currently
describes the pre-claim model at lines 186-190:

> 该 relay 使用单独的 client_credentials 客户端，只允许精确 scope
> `tenant-quota:projection:write` 和配置的唯一 SSO resource。每租户
> `source_system` 由 `snaplink-billing-quota` 前缀和租户 ID 的 SHA-256 稳定派生；SSO
> 仅依据验签后的 `client_id` 加 exact source binding 解析租户，请求 body 没有授权力。
> 用以下命令生成并预注册每个 source：

Replace with (branch A; keeps the style, the derivation command, and the body-no-authority
sentence; adds the single-tenant constraint):

> 该 relay 使用单独的 client_credentials 客户端，只允许精确 scope
> `tenant-quota:projection:write` 和配置的唯一 SSO resource。relay 客户端在 IdP 的
> `tenant_id` 绑定决定它可以为哪个租户投递：客户端凭据换取的令牌携带该绑定租户的
> `tenant_id` claim，billing 在每次投递前 fail-closed 校验 claim 与 outbox 事件租户一致
> （缺失或不一致一律折叠为既有 `insufficient_scope`/重试语义，原因不暴露）。因此一个
> billing 部署的 quota relay 只服务一个租户：部署的 `tenant_commerce_quota_outbox` 中
> 只能有一个租户的事件，且该租户必须等于 relay 客户端的 IdP 绑定；多租户部署需按租户
> 拆分（每个 billing 部署一个商业租户），或在后续方向中引入按租户凭据面（本变更不支持）。
> 该租户的 `source_system` 由 `snaplink-billing-quota` 前缀和租户 ID 的 SHA-256 稳定派生；
> SSO 仅依据验签后的 `client_id` 加 exact source binding 解析租户，请求 body 没有授权力。
> 用以下命令生成并预注册该租户的 source：

Two adjacent README changes stay as previously specified (unchanged by this decision):

- Lines 170-172 (Audit Governance section, R5.1 primary target): retire "当前 Snaplink
  client_credentials token 不携带 `tenant_id` claim" in favor of "当前 Snaplink
  client_credentials token 已携带 `tenant_id` claim（B4-1），但 Audit Governance relay 不消费
  该 claim"; the audit-relay sentences "相同 relay client 可以服务多个租户" and the
  per-source registration rule **stay** (audit path has no cross-check — hardening §8 delta 2).
- `docs/config-reference.md` "Standalone Billing Quota Projection Relay" closing paragraph
  (:853-857): add one sentence — the relay client's IdP `tenant_id` binding must equal the
  single commercial tenant the deployment's relay serves, and sources registered under the
  client belong to that tenant only; deployments serving more than one tenant must split
  before enabling the claim-gated relay. The env-var rows themselves are unchanged (branch A
  adds no keys).

## 6. Contract deltas introduced by this decision

1. `docs/architect-analysis/cmd-snaplink-billing-tenant-claim-design.md` — amend §1.1 decision 3
   (shared-client non-viability → resolved as branch A), §3.5 README bullet, §4
   "Shared multi-tenant quota relay client breaks" row, and §6 step 3 (text in §4 above).
2. `docs/architect-analysis/cmd-snaplink-billing-tenant-claim-hardening.md` — amend §3.1
   (option ordering superseded by this decision; detection/verification steps unchanged),
   §6 step 3 (replaced), §8 delta 2 (README quota-section text per §5 above).
3. `cmd/snaplink-billing/README.md` — quota section replacement (§5) + audit-section
   claim-verified retirement (R5.1, unchanged wording from the design) in the R2/R3+R4+R5
   commit.
4. `docs/config-reference.md` — one sentence in the quota-relay section (§5), same commit.
5. No `.go` changes, no config keys, no module/profile/manifest changes, no e2e fixture shape
   change beyond A7's `Subject.TenantID: "tenant-e2e"`.
