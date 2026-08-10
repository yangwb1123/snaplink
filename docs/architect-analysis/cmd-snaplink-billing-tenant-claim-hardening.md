# Hardening: migration plan (§6) and failure modes F1/F2/F5/F8 — consume the B4-1 mint-time tenant_id claim

- Parent: `docs/architect-analysis/cmd-snaplink-billing-tenant-claim-design.md` (status: design; this addendum amends §5/§6 of it)
- Scope: the five review questions on the mixed-fleet window (F1), gate sequencing (F1/F2), the per-tenant relay pre-flight (F3-adjacent, §6 step 3), monitoring/alerting (F4/F5), and rollback (§6 step 6).
- Method: every claim below re-verified against HEAD (file:line cited). Two findings are **new gaps** the parent design must resolve before §6 is executable; the rest are confirmations with concrete amendments.

## Verdict summary

| Q | Verdict | Required amendment |
|---|---|---|
| 1. Mixed-fleet TTL window | **Acceptable with ordering + one operational lever**; residual tail ≤ effective token TTL (default 1 h). No kill switch needed and none is compatible with the no-config-knob constraint. | §6 step 2 wording: "fleet at B4-1" must mean *all `/token` traffic*; add relay rolling restart; add explicit residual-window acceptance + monitoring discriminator. |
| 2. R2+R3 before G5 | Blast radius = whole bound-client machine plane + quota/retention relay, bounded by outbox retention (zero data loss). **Step 2's gate is process-only and cannot be proven by repo CI** — the e2e and pin mint in-process and are fleet-blind. | Make the live-fleet mint pin a deployment-blocking job; state CI-green ≠ mint-green explicitly; fix T-8(e) label collision. |
| 3. Per-tenant relay pre-flight | **New gap: the billing relay config holds exactly ONE client credential pair** — "register one relay client per tenant" (§4/§6 step 3) is not expressible without a new config surface, which contradicts the direction's "no new config keys" and the env-only secrets discipline. | Step 3 must branch on an explicit decision (single-tenant-per-deployment vs. follow-up credential-map direction); detection/verification steps below. |
| 4. Monitoring/alerting | Drift denials on HTTP routes are **deliberately unobservable as a class** (no-oracle); the durable outbox `last_error` + readyz + log rate are the available signals; TTL-duration is the F5-vs-F2/F3 discriminator. | New §6 step 5.5 + observability deltas; concrete rules below. |
| 5. Rollback step 6 | **Safe under the one-commit packaging**; the only hard hazard is operational (IdP credential deletion) and one ordering rule (billing gate reverts before any IdP rollback). | Step 6 rules below. |

---

## 1. Q1 — mixed-fleet window during a rolling IdP upgrade (F1)

### 1.1 Model and measured bounds

The mint stamps `TenantID` unconditionally with `omitempty` performing omission (`infrastructure/defaultimpl/issue_payload.go:42-47`; `defaultTokenTTL = time.Hour` at :17-19; per-client `access_token_ttl` override `shared/core/types.go:108-114` / `config/config_client.go:37`; `token_policies.max_ttl` clamps downward, `docs/config-reference.md:608`). During a rolling upgrade, `/token` is served by old (no claim) and new (claim) nodes until the roll completes. The gate is always-on with no kill switch (R2 constraint), so:

- **Direct API paths** (payment ingest/order-read, metering usage/reservation/entitlement, admin routes *for bound clients only*): a claim-less token minted by an old node is denied with the byte-identical 403 `insufficient_scope` until that token's expiry. Window per token ≤ its effective TTL.
- **Quota relay**: the token is held in the per-client cache until `expires_in − min(30s, lifetime/2)` (`infrastructure/auditgovernance/oauth_token_source.go` `cacheToken`), so the window is the same ≤ TTL bound, not larger. Denials surface as `reasonAuthorization` bounded retries with events retained in the durable outbox (`tenant_commerce_quota_outbox`, `last_error` persisted; `interfaces/ssoclient/quotaprojection/relay.go` `classifyPublishError`).
- **Audit governance relay is NOT in the window**: its path has no claim cross-check (R3 touches only `quotaprojection/http_client.go`; the audit relay mints through the same `OAuthTokenSource` but delivers via `interfaces/sso/quota.go`-independent audit endpoints). This asymmetry is load-bearing for the blast-radius statement in §2.

Worst case = the last claim-less mint before the last old node retires, denied for its full remaining TTL (default 1 h; a deployment that set longer per-client TTLs proportionally extends it). This is inherent: a signed JWT cannot be retro-stamped, and the no-config-knob constraint rules out a gate toggle.

### 1.2 Acceptability verdict

The window is **acceptable** — with four conditions, all satisfied by the amended §6:

1. **Ordering eliminates the mixed-fleet portion.** If the IdP roll completes and the mint pin is confirmed against the live fleet *before* the billing gates deploy, the only denials left are the natural TTL tail of tokens minted before the roll finished. The dangerous unbounded variant (gate live while the fleet is still pre-B4-1) is what step 2 must mechanically prevent — see §2.
2. **The denied surface is machine-only and self-healing.** Admin console is the carve-out (unbound → pass; only deployments that bound the console client in billing's store see admin 403s during the window). Payment/metering adapters retry or re-mint per their own policy; the relay retries with bounded backoff and delivers after refresh. No data loss anywhere (outbox retained; payment facts live in the adapters/PG).
3. **The window is bounded and measurable.** ≤ effective TTL, default 1 h, and the F1-vs-F2/F3 discriminator (episodes that clear within TTL + margin vs. persistent) is monitorable — §4.3.
4. **The stale-quota direction is fail-safe-stale, not wrong.** While deliveries pause, the IdP quota store serves the last-known-good projection. A paused *reduction* (hard-zero) can over-provision for ≤ the window; a paused *increase* under-provisions. Both are bounded by the same TTL.

### 1.3 Reduction levers short of a kill switch

| Lever | Mechanism | Verdict |
|---|---|---|
| **Deployment ordering** (§6 step 2, hardened) | Complete the IdP roll; verify the mint pin against the production LB token endpoint; only then deploy R2/R3. | Primary lever. Eliminates the mixed-fleet portion; residual = unavoidable TTL tail. |
| **Rolling restart of billing replicas after the IdP roll** | The token cache is in-process per client; a restart forces a fresh mint from B4-1 nodes, collapsing the relay path's residual window to ~0. Outbox is durable; leases fence (`SKIP LOCKED`, lease fencing — README quota section). | Cheapest operational lever for the relay path. No config, no gate change. |
| Pre-set short `access_token_ttl` on relay clients (existing IdP knob) | Tighter TTL → tighter window. | Existing config, but **cold** (restart) — only helps if set *before* the roll. Worth setting on newly registered per-tenant relay clients (Q3) from day one; not a mid-window lever. |
| Adapter re-mint on 403 | Adapters that already treat `insufficient_scope` as credential-invalid collapse their own exposure to one request. | **Do not rely on it.** The denial is byte-identical to a scope denial by design (no-oracle); adapters must not special-case it, so only their existing 403 behavior applies. Mentioned for completeness only. |
| Gate toggle / kill switch | — | **Rejected**: violates the no-config-knob constraint (R2) and would create an oracle-adjacent operational class. |

### 1.4 Residual-risk statement (to add to §5 F1)

"Tokens minted by pre-B4-1 nodes during the roll are denied for up to their remaining TTL (default 1 h) on bound-client machine routes; quota delivery pauses with `reasonAuthorization` and converges after token refresh. The window is bounded by TTL, self-healing, machine-surface-only, and — with §6 ordering — contains only the natural tail of the last pre-B4-1 mints; a relay rolling restart after the IdP roll closes the relay path immediately. During the window the IdP quota store serves the last-known-good projection (fail-safe-stale)."

---

## 2. Q2 — always-on gate sequencing: blast radius and whether step 2's gate prevents it

### 2.1 Blast radius if R2+R3 land before the mint pin is green

Two sub-cases: (a) fleet not yet at B4-1 → denials are **unbounded in time** (persist until the roll completes — this is the F1 precondition violation, not the TTL window); (b) fleet at B4-1 but pin unverified → behavior is correct but the deployment skipped its only fleet-level check. Case (a):

| Surface | Effect |
|---|---|
| Payment machine routes (`payment_ingest.go` gates) | Every bound-client 403 `insufficient_scope`; payment events stop being ingested (facts retained by adapters/PG) |
| Metering routes (`interfaces/metering/auth.go`) | Every bound-client 403; usage/reservation/entitlement reads stop |
| Admin routes | Unbound clients pass (carve-out); bound clients 403 |
| Quota relay | Every delivery pauses (`reasonAuthorization`); outbox backlog grows; retention projection stalls behind it (`entitlementProjectionClient.Publish` reaches retention only after quota succeeds — `quota_relay.go`) |
| `/readyz` | `tenant_quota_projection` degrades at `MaxLag` (default 5 m) → deployment marked unhealthy |
| IdP quota store | Serves last-known-good projection (stale, not wrong) |
| Audit governance relay | **Unaffected** — no claim cross-check on that path (see §1.1) |
| Data | Zero loss: outbox rows persist reason + retry time; recovery = complete the roll (or revert), then the existing backoff drains the backlog |

The blast radius is therefore "the entire bound-client machine plane + quota/retention delivery", bounded by outbox durability and reversible either direction (roll forward or revert). No kill switch is needed because the *recovery* is either of those two operations.

### 2.2 Does step 2's gate actually prevent it?

**Only by process, not by mechanism.** Step 2 ("Confirm mint prerequisite … lands in the G5 slot, never before") is a documented precondition plus a campaign slot — there is no mechanical interlock between the billing release and the fleet's mint state. The structural reason is that **repo CI is fleet-blind**:

- A7's e2e mints in-process via `defaultimpl.Ed25519JWTIssuer` (`test/quota_projection_e2e_test.go:84-92` — `Subject{ID, ClientID, Resources}`, no tenant today; A7 adds `TenantID: "tenant-e2e"`).
- R4's pin (`claims_pin_test.go`) mints through the same in-process issuer.

Both prove the *consumption* path against the *same codebase's* mint — they go green even when the production fleet has never seen B4-1. The only check that observes the production mint is the campaign's T-8(a) pin against the deployed `/token` (`docs/campaigns/implementation-gate.md`, B4-1 row: `POST /token` → claims `{iss/aud/scope/client_id/tenant_id/roles}`). Green CI must never be read as "mint pin green" — the current step 2 wording invites exactly that misreading by listing campaign gates next to a repo merge.

### 2.3 Hardening

1. **Deployment-blocking pin job**: the billing R2/R3 artifact's deploy pipeline runs T-8(a) against the production LB token endpoint (a real client_credentials mint with a bound client, claim decoded and asserted) after the IdP roll completes; red pin aborts the deploy. This is the mechanical enforcement step 2 lacks — same shape as the campaign's G1 gate, executed at deploy time.
2. **Step 2 rewording**: "IdP fleet at B4-1" must be defined as *all `/token` traffic served by B4-1 nodes* (verified by the pin job), not "the merge is ordered after G1 in the campaign table".
3. **Post-deploy smoke (step 5, extended)**: immediately after R2/R3 lands, mint through the *configured* token URL (`SNAPLINK_BILLING_QUOTA_TOKEN_URL` / issuer `/token`) and decode the claim before trusting any machine-route 200s; the existing step-5 checks (machine routes 200, relay revision advances) already fail fast on the absence class — state that a 403/reasonAuthorization burst within the first TTL after deploy is the F1 signature.
4. **Footnote — label collision**: the campaign uses "T-8(e)" for an IdP endpoint-hardening acceptance (implementation-gate.md B4 row 4: "T-8(b)(c)(e)") while this direction reuses "T-8(e)" for quota-relay equality (requirements §7). The gate table defines only T-8(a) explicitly. Recommend renaming the direction's label (e.g., T-8(f)) to keep the gate table unambiguous.

---

## 3. Q3 — per-tenant relay client migration pre-flight (§6 step 3)

### 3.1 Finding: the step is not executable as written (new gap)

The design's §4/§6 step 3 says "multi-tenant deployments register one relay client per tenant". The billing relay, however, is built around **exactly one client credential pair**:

- `quotaRelayConfig{ClientID, ClientSecret}` from `SNAPLINK_BILLING_QUOTA_CLIENT_ID/SECRET` (`cmd/snaplink-billing/quota_relay.go` `quotaRelayDefaults`/`buildQuotaTokenSource`), validated as a single pair;
- `OAuthTokenSource` is constructed once with that fixed `clientID` and `AccessToken(ctx, binding)` only derives the *source* per tenant (`infrastructure/auditgovernance/oauth_token_source.go` `TenantSourceID` check) — never the client.

The claim is the **IdP client's** single `tenant_id` (`internal/handler/tokengrant/token_client_credentials.go:52` `TenantID: client.TenantID`; `config/config_client.go:24` `clients[].tenant_id`). Therefore "one relay client per tenant" is not expressible in the current binary: a multi-tenant billing deployment either (a) keeps the shared client — then at most one tenant's deliveries survive (the bound one) and the rest pause persistently (F2-class), or (b) runs one billing deployment per tenant (single-tenant relay), or (c) gains a per-tenant credential surface — a new config key/file, which contradicts the direction's "no new config keys" boundary **and** the env-only secrets discipline (README: "PostgreSQL DSN 和 Audit OAuth client secret 只从环境变量读取").

**This is the one place §6 must branch on an explicit decision before step 3 can be executed.** Recommended resolution, in order:

1. Preferred for the common case: **single-tenant relay per billing deployment** (per-tenant client + per-tenant env pair). This matches the e2e fixture shape (one client "billing-relay" → one tenant) and needs zero new surface.
2. If multi-tenant-per-deployment relay is a hard requirement, declare a **follow-up direction** for a bounded per-tenant credential surface (the `source-bindings.example.json` strict-JSON-file pattern is the precedent; secrets-in-file conflicts with the env-only discipline must be resolved there — e.g., per-tenant env pairs with a validated naming scheme). It cannot be smuggled into this change.
3. Update R5.1's quota-section wording accordingly: the current draft ("multi-tenant deployments register one relay client per tenant") is the unimplementable sentence and must be replaced by whichever of (1)/(2) is chosen.

### 3.2 Operator detection of affected shared relay clients

A deployment is affected iff its quota relay client serves more than one tenant, or its tenants differ from the client's IdP binding:

1. Identify the relay client: `SNAPLINK_BILLING_QUOTA_CLIENT_ID` (+ `SNAPLINK_BILLING_QUOTA_SOURCE_PREFIX`) per billing deployment.
2. Count served tenants from the durable outbox (root-module PG, shared pool):
   `SELECT COUNT(DISTINCT tenant_id) FROM tenant_commerce_quota_outbox;`
   (columns verified: `event_id, tenant_id, projection_revision, status, attempts, next_attempt_at_ns, last_error, delivered_revision, delivered_at_ns` — `infrastructure/postgres/tenantcommerce/outbox.go:94-99`).
   `> 1` ⇒ shared client at risk.
3. Read the client's IdP binding `clients[].tenant_id` (static config): empty ⇒ **all** deliveries pause post-R3 (F3 class); set ⇒ only that tenant survives; count mismatch ⇒ N−1 paused.
4. Cross-check the IdP-side projection registry (`tenant.resource_quota.projection_ingress.sources[]` — `cmd/sso-server/tenant_quota_projection.go:24,38,49-50`; "A client may own many tenant sources" `interfaces/sso/quota.go:27-29`): distinct source `tenant_id`s for the client `> 1` ⇒ shared. Note the registry itself stays valid post-R3 — the claim gate is what makes the extra tenants unreachable.

### 3.3 Config management path

| Layer | Change | Mechanism |
|---|---|---|
| IdP clients | Add per-tenant relay clients with `tenant_id` set (one per tenant, same scope `tenant-quota:projection:write` + resource) | `clients[]` static config — **cold** restart of the IdP fleet |
| IdP projection registry | Register each new client's tenant source(s) (`source_system` = `snaplink-billing-quota.<b64url(sha256(tenant))>` — README quota section) | `projection_ingress.sources[]` — **SIGHUP**-reloadable revision update; `tenant_id` immutable per source (`docs/config-reference.md:856`) |
| Billing | Per-tenant client selection — **the open decision from §3.1**; no change expressible today | — |
| Billing bindings store | Relay clients need no billing-side binding (they never call billing APIs); do not add mirror bindings unless a route family needs them | `SNAPLINK_BILLING_SOURCE_BINDINGS_FILE` untouched |

### 3.4 Verification steps (after registration)

1. **Per-client mint check**: for each new client, mint via its credentials and decode the JWS payload — `tenant_id == expected tenant`, `roles` present. This is the T-8(a) assertion, per client; catches the cold-config typo before it reaches the relay.
2. **Delivery check**: observe one entitlement publication per tenant — outbox drains, `delivered_revision` advances, IdP quota store revision advances (e2e A7 shape, production path).
3. **Pause check**: zero rows with `last_error = 'quota projection authorization rejected'` in `tenant_commerce_quota_outbox` after the F5 window (≤ TTL + backoff); no `tenant quota projection relay paused after error` log episodes.
4. **Readiness**: `/readyz` `tenant_quota_projection` green (its check = oldest unfinished fact vs `MaxLag`, default 5 m).
5. **Rollback hygiene**: keep the shared client active (bound or unbound — an unbound shared client is harmless post-revert because the IdP-side handler never reads the claim, `interfaces/sso/quota.go` non-goal) until the rollback window closes; never delete credentials first (§5).

---

## 4. Q4 — monitoring/alerting for the new failure classes

### 4.1 What is observable today — and the no-oracle tradeoff

The no-oracle pin (A3/A6/A12 byte-equality) makes HTTP drift denials **deliberately indistinguishable from scope denials on the wire**, and billing's `/metrics` is renewal-only (no HTTP counters — `cmd/snaplink-billing/renewal.go:191-231`; `docs/observability.md` "Standalone Billing Background Work"). So per-class HTTP counting is *impossible by construction*, and the honest signal set is:

1. The durable outbox reason column — the **only durable drift-class signal** (`tenant_commerce_quota_outbox.last_error = 'quota projection authorization rejected'`).
2. The worker log line `tenant quota projection relay paused after error: <err>` (`cmd/snaplink-billing/quota_relay.go` run loop) — fires for any error, but the error value distinguishes `ErrAuthorizationRejected`.
3. `/readyz` `tenant_quota_projection` (oldest unfinished fact > `MaxLag`, default 5 m).
4. Edge/access-log 403-rate deltas per route during deployment windows (payment/metering/admin HTTP drift denials are only visible as scope-denial-shaped 403s).
5. The new `admin tenant gate resolver error (fail open)` stderr line (A11's fail-open decision).

Alerting must therefore be **duration- and correlation-based**, not per-request — which is exactly what discriminates the failure classes.

### 4.2 adminGateLog fail-open occurrences (F4, design addition A11)

- **Signal**: the fixed stderr line `admin tenant gate resolver error (fail open)` (design §3.2.1). Add `client_id` to the line (bounded, operator-facing, no wire/audit impact; A11's test asserts the pass-through, not the line — `docs/observability.md` log discipline excludes tenant IDs and payloads, not client IDs).
- **Rule**: log-based (Loki/Vector/fluentd): `rate(… |~ "admin tenant gate resolver error") [5m] > 0` → **WARN**. Fail-open is availability-preserving by design (precedent: tenant-suspension lookup outage); the WARN means "the drift gate is blind".
- **Escalate**: PAGE only if sustained > 15 min (aligns with the readiness-tolerance philosophy — the observability doc's fixed 15-min pattern for renewals). While it fires, drift protection is off; the compensating control is the relay cross-check, which is unaffected.
- **Optional** (requires an observability-doc row, bounded no-label counter): `snaplink_billing_admin_gate_fail_open_total`. Default: skip — the log rate rule covers it and keeps "zero new surface" intact.

### 4.3 reasonAuthorization pause rate (F1/F2/F3/F5 share this class)

- **Primary (zero code, durable)**: SQL over the outbox:
  - WARN: any row with `last_error = 'quota projection authorization rejected' AND status = 'pending'` appearing within a 10-min window (fresh pause episode). Freshness is `next_attempt_at_ns` — it is written in the same `UPDATE` as `last_error` (`FailQuotaProjectionDelivery`), and `last_error` is never cleared on delivery, so the `status = 'pending'` filter is load-bearing.
  - PAGE: the **oldest unfinished** such row's age exceeds `effective client token TTL + refresh skew + maxBackoff + margin` (with defaults: 1 h + 30 s + 1 m + ~10 m ≈ 70-75 min; compute from the deployment's `access_token_ttl`). Row age must come from the joined `tenant_commerce_outbox.created_at_ns` — the quota outbox table has no creation timestamp, and `next_attempt_at_ns` is rewritten on every retry (bounded by `MaxBackoff`), so its age never grows and cannot discriminate F5 from F2/F3. This is the F5-vs-F2/F3 discriminator: F5 self-heals at cache refresh (bounded by `expires_in − 30 s + maxBackoff` ≈ 60.5 min with defaults — the refetch is lazy, so the first attempt after `refreshAt` adds one backoff; the 70-75 min ceiling keeps ~10-14 min cushion), F2/F3 persist.
  - Escalate: `/readyz` `tenant_quota_projection` error for ≥ 2 max-lag evaluation windows (the observability doc's existing directive: "Alert on sustained readiness failure for two max-lag evaluation windows and on repeated worker pauses").
- **Secondary**: log-rate on `tenant quota projection relay paused after error` where the error is `ErrAuthorizationRejected`, sustained without any `Delivered` progress (correlate with the durable quota outbox `delivered_at_ns` advancing — the in-process `RunResult` is not externally observable).
- **During the deployment window (§2.3)**: expect exactly one F1-shaped episode (≤ TTL) if ordering slipped; a second episode after TTL+margin is F2/F3 and pages — this is the tripwire that turns the sequencing mistake from silent into alertable.

### 4.4 F5 stale-cache window

- F5 needs **no operator action** and **no dedicated alert**: it is the same `reasonAuthorization` episode as F1/F2/F3, and the duration rule above classifies it automatically (clears ≤ TTL + backoff ⇒ F5, WARN-level only).
- **Correlation aid**: cross-reference pause episodes against IdP client re-bind times (configaudit/admin client-change events, `docs/config-reference.md` `config_audit.*`) to confirm F5 vs F2 without waiting for the TTL boundary.
- **Immediate remediation if the window matters**: rolling restart of the relay (in-process cache re-mint) — the same lever as §1.3.
- Note in the observability doc: an F5 episode is only reachable when an operator re-binds a relay client, so WARN-level alerting on any `reasonAuthorization` episode is the right baseline (zero false positives in steady state).

### 4.5 Optional metrics vs "zero new surface"

The design's zero-new-surface list covers config/`Err*`/endpoints/OpenAPI/audit — metrics are not on it, but each new metric is a documented observability-doc row with bounded labels (the renewal-worker precedent). Recommended minimal set **only if** log/SQL-based rules prove insufficient: `snaplink_billing_quota_outbox_oldest_age_seconds` and `snaplink_billing_quota_relay_pauses_total` (mirroring `snaplink_billing_renewal_backlog_oldest_age_seconds`). Default position: **no new metrics in this change**; the durable outbox + readyz + fixed log lines carry the full signal with zero code.

---

## 5. Q5 — rollback step 6 validation (revert R2/R3, R1 stays)

### 5.1 Commit topology makes the code revert atomic

Step 4 packages R2+R3+R4+R5 + the e2e fixture (T-8(e)) as **one commit**; step 6 reverts that commit. Verified consequences:

- **R1 merged earlier is unaffected**: the projection is additive (fields + `HasTenantID()`); billing compiles and behaves exactly as before without R2/R3; nothing in R1 depends on the gates. R4's pin test is the only consumer of the R1+R4 combination and reverts with the commit.
- **The e2e fixture reverts with the commit**: without the fixture, the mint returns to the no-tenant `Subject` (today's shape) and without the gate the positive path passes as today — consistent. The hazard is one-directional: if the fixture were **split out and left behind** after the revert, the e2e still passes (claim ignored — harmless but confusing); if the fixture were **reverted while R2/R3 stayed**, the e2e positive path fails (absence ⇒ denial) and CI forces the correct revert. Rule: keep the fixture in the R2/R3 commit.
- **Docs (R5) revert with the commit**: README/`oauth_token_source.go` comment/error-codes return to the pre-change state — consistent with reverted code. If R5 were split, the README would describe gates that no longer exist (drift). Rule: keep R5 in the same commit (the design already says so — preserve it).

### 5.2 Hazards that are NOT reverted by the code revert

1. **Operational state from step 3 (the real hazard).** IdP-side changes (per-tenant clients, binding edits) are additive and harmless if left. The **only hard hazard is deleting the shared relay client's credentials** (or its binding) during migration: after the revert the relay cannot mint → transport-class retries forever. Critically, an *unbound* shared client is perfectly functional post-revert, because the IdP-side projection handler never reads the claim (`interfaces/sso/quota.go` non-goal) — the claim gate is gone. Rule: **additive-only during the rollback window; disable/delete the shared client only after the window closes.**
2. **Simultaneous IdP rollback ordering.** If B4-1 itself must be rolled back (fleet reverts to no-claim mint), the billing gate must be reverted **first** — gate-without-mint is the unbounded F1 denial of §2.1. Rule: in any combined rollback, billing R2/R3 reverts before/with the IdP mint change, never after.
3. **Revert mechanics.** `git revert` of the one commit can conflict if unrelated changes land on `auth.go`/`app.go`/`http_client.go`/`quota_relay.go` in between (the `newAdminContractRouter` signature and the relay check are the collision points). The *operational* rollback is simpler: redeploy the previous billing artifact; the tree revert can follow at leisure. State both in step 6.
4. **Backlog convergence.** Events paused during the gate-live window resume automatically from their persisted `next_attempt_at_ns` retry schedules (`FailQuotaProjectionDelivery`); no replay or backfill — this is already in step 6 and holds (verified: the store persists reason + retry time). If the gate was live for a long time, per-tenant order is preserved (cursor completes in revision order), so no reordering hazard.

### 5.3 Rules for §6 step 6 (amended)

1. Revert = redeploy previous billing artifact + `git revert` of the single R2+R3+R4+R5+fixture commit; R1 stays.
2. Fixture and R5 docs stay inside that commit (never split).
3. Keep shared relay client credentials/binding intact during the rollback window; disable only after the window closes.
4. In any combined IdP rollback, billing reverts first.
5. No replay/backfill; observe the outbox draining on its own retry schedule.

---

## 6. Amended §6 migration steps (replacement)

| Step | Action | Hard gate / verification |
|---|---|---|
| 1 | Land R1 (rs projection + A1/A2) | Deployable alone; zero behavior change |
| 2 | **IdP mint prerequisite, mechanically enforced**: IdP fleet fully at B4-1 (all `/token` traffic); run T-8(a) mint pin **against the production LB token endpoint** as a deployment-blocking job | Pin green ⇒ deploy pipeline proceeds; red ⇒ abort. Repo CI green is explicitly **not** evidence (A7/R4 mint in-process, fleet-blind) |
| 3 | **Operator pre-flight (branch on the §3.1 decision)**: detect affected shared relay clients (§3.2); per-tenant clients per the chosen option (single-tenant-per-deployment, or the follow-up credential surface); IdP `clients[]` (cold) + `projection_ingress.sources[]` (SIGHUP); verify per §3.4; **additive-only — keep shared client credentials** | Per-client mint check (claim == tenant); delivery check; zero `reasonAuthorization` after F5 window; `readyz` green |
| 4 | Land R2+R3+R4+R5 + e2e fixture (T-8(e)) in one commit | CI: targeted suites + `go test ./test/ -run TestE2E -v` (A7-A10); gates: build/vet/architecture |
| 5 | Post-deploy verification: mint-through-configured-TokenURL claim decode; machine routes 200; relay revision advances; `readyz` green; **monitoring armed (§4)** — one F1-shaped episode ≤ TTL tolerated (WARN), anything beyond TTL+margin pages | Deployment-window error-rate baseline recorded for rollback comparison |
| 5.5 | **Monitoring activation (new)**: §4 rules live — admin fail-open log rule (WARN, PAGE at 15 min), outbox `reasonAuthorization` age rule (WARN fresh, PAGE > TTL+margin), readyz 2-window rule | Alert dry-run in staging before production deploy |
| 6 | **Rollback (§5)**: redeploy previous artifact + revert the one commit; R1 stays; shared client credentials kept until the window closes; combined IdP rollback ⇒ billing first; outbox drains on its own schedule — no replay | Post-revert: delivery resumes, no manual steps |

## 7. Amended failure-mode rows F1/F2/F5/F8

| # | Failure | Behavior | Recovery | Amendment |
|---|---|---|---|---|
| F1 | IdP fleet not yet at B4-1 / mixed fleet during roll | Bound machine routes 403 `insufficient_scope`; quota relay pauses (`reasonAuthorization`); audit relay **unaffected**; admin console unaffected (carve-out) | **TTL-bound for the mixed-fleet tail** (≤ effective TTL, default 1 h, §1); **unbounded until the roll completes** for the precondition violation — prevented by the §6 step-2 deployment-blocking pin (§2.3); relay rolling restart collapses the relay path immediately | Add the TTL-bound vs unbounded distinction; add the pin job; add §1.4 residual statement |
| F2 | IdP re-binds client to tenant B; billing store says A | Byte-identical 403; relay 0 delivered for A events, bounded retry | Operator reconciles bindings; relay converges after retry/refresh | Monitoring: persists beyond TTL+margin ⇒ PAGE (§4.3); correlation with IdP re-bind events (§4.4) |
| F5 | Cached relay token stale tenant_id (TTL window) | Cross-check rejects; `reasonAuthorization` retry; event retained | Automatic at cache refresh (≤ `expires_in − 30 s + maxBackoff` ≈ 60.5 min with defaults) | **No operator action, WARN-only** — classified by the duration rule; immediate remediation = relay restart (§4.4) |
| F8 | Concurrent relay replicas | Unchanged: claim/lease semantics govern; cross-check inside `Publish`, after claim | Existing | Confirm rollback convergence preserves per-tenant order (§5.2.4) |

## 8. Contract/doc deltas introduced by this hardening

1. `docs/architect-analysis/cmd-snaplink-billing-tenant-claim-design.md` — amend §4 (per-tenant relay constraint → branch on §3.1 decision), §5 F1 (TTL-bound vs unbounded; audit-relay exemption), §6 (steps 2/3/5/6 per §6 above), add §7 monitoring rules.
2. `cmd/snaplink-billing/README.md` quota section (R5.1) — replace "multi-tenant deployments register one relay client per tenant" with the chosen §3.1 option; the audit-relay "相同 relay client 可以服务多个租户" sentence stays (audit path has no cross-check).
3. `docs/campaigns/implementation-gate.md` — optional: disambiguate the direction's T-8(e) label (§2.4).
4. `docs/observability.md` — add the admin fail-open log rule and the outbox-duration alert rule to the billing section (no new metrics by default; §4.5 records the optional metric set).
5. No `.go` changes in this hardening; all amendments are plan/document-level. The §3.1 decision (single-tenant-per-deployment vs. follow-up credential surface) is the only open item blocking §6 step 3.
