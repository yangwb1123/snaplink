The decision is resolved and documented at `docs/architect-analysis/cmd-snaplink-billing-tenant-claim-relay-credentials-decision.md` (doc-only deliverable; every citation re-verified against HEAD). Summary:

## Recommendation: Branch A — single-tenant-per-deployment relay

**Evaluation against the four gates:**

| Gate | Branch A (single-tenant relay) | Branch B (per-tenant credential surface) |
|---|---|---|
| Config-reference discipline | Zero new keys/rows/files; the existing `SNAPLINK_BILLING_QUOTA_CLIENT_ID/SECRET` pair's *values* become per-deployment. `validateDisabled` (quota_relay.go:152) and `validateProjectionCredentialSeparation` (exactly 3 pairs, :268-287) untouched | Violates the requirements' explicit non-goal "No new config keys" (requirements:57); per-tenant env keys need an env-name schema over arbitrary tenant IDs + `os.Environ` enumeration, which the getenv-driven `defaultsFromEnvironment` (config.go:89) cannot express; a tenant→credentials file would be the repo's first secret-bearing config file |
| Env-only secrets | Unchanged ("只从环境变量读取", README:17-18; "Secret 仅从环境读取", :199) | Only compliant carriage is per-tenant env pairs — not expressible; file carriage conflicts with the documented env-only invariant |
| ADR-0009 module rules | Exactly the "one restart-only `billing-runtime` composition per deployment" model; single-tenant scoping is a topology decision, not a module/capability change | Still one cold module, but invents the first tenant-keyed credential surface with no module-system counterpart — a net-new contract |
| e2e fixture | Fixture is already branch-A-shaped (one client `billing-relay` → one tenant `tenant-e2e`, e2e_test.go:59-60, 85-87); A7 keeps "delivers exactly as today", no harness growth | Fixture would need a per-tenant credential map, contradicting its role as "the e2e exercises the production check" |

**Decision:** the quota relay of a billing deployment serves exactly one tenant, named by the relay client's IdP `tenant_id` binding; the outbox may hold events for only that tenant (detectable via `SELECT COUNT(DISTINCT tenant_id) FROM tenant_commerce_quota_outbox`). Branch B is deferred as a follow-up direction triggered only by an unsplittable `COUNT > 1` deployment, requiring its own requirements amendment. The audit-governance relay is exempt (no cross-check on that path).

## §6 step-3 wording (defined in doc §4)

> 3. **Operator pre-flight — single-tenant relay scoping (branch A, §3.1 decision)**: ... a. **Detect** via the outbox tenant count; >1 ⇒ split the deployment or register branch B as a separate requirements change — R2/R3 must not ship against a shared relay client. b. **Bind**: IdP `clients[]` `tenant_id` = served tenant (cold; empty pauses everything, F3), reconcile `projection_ingress.sources[]` (SIGHUP). c. **Verify** per hardening §3.4: per-client mint check, one observed delivery, zero `reasonAuthorization` after the F5 window, `readyz` green. d. **Additive-only**: keep shared-client credentials until the rollback window closes.

## README quota-section update (doc §5, exact Chinese replacement)

Replaces the "每租户 `source_system` … 用以下命令生成并预注册每个 source" paragraph with the claim-verified description: the relay client's IdP `tenant_id` binding determines the single tenant it can deliver for; billing fails closed per delivery on claim-vs-event-tenant equality (causes hidden); one deployment = one relay tenant; multi-tenant deployments split or take the follow-up surface (unsupported in this change); per-tenant source derivation command retained. Also specified: the audit-section R5.1 retirement (keeping the "相同 relay client 可以服务多个租户" sentence — audit path has no cross-check) and a one-sentence `config-reference.md` delta (:853-857).

**Contract deltas** (§6): amend design §1.1/§3.5/§4/§6 step 3 and hardening §3.1/§6/§8 delta 2; README + config-reference edits land inside the R2+R3+R4+R5 commit. No `.go`, config, module, or fixture-shape changes.
