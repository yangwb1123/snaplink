# Compliance Review — interfaces/admin Direction 1 (capability language, tenant dimension, delegation grading)

Reviewer role: compliance officer (`ai-dev/prompts/compliance_officer.md` + `ai-dev/prompts/README.md` baseline). Advisory only; no files modified. Every material claim was re-verified against the tree at commit `5ce7b81d` (dirty worktree; unrelated edits only). Labels: **Verified** (read in code/tests), **Partial**, **Proposed** (design commitment, not yet implemented), **Missing**, **Unknown** (not established by the input).

This review evaluates **controls and evidence**, not certification. The repository contains evidence-assembly tooling (SOC 2 report generator, GDPR Art. 30 data map, export/erasure engines); that tooling is not an attestation, and nothing in the tree claims a certification result. Implemented controls are not evidence of certification.

---

## 1. Applicable-scope statement and excluded/unknown frameworks

**Subsystem under review.** The admin control plane: `interfaces/admin` authorization gate (HTTP + gRPC), `domains/permissions` (RBAC matcher, role/assignment stores, resource catalog), `platform/lifecycle/admingovernance` (break-glass, change-approval workflow), the tenant-export path (`protocols/compliance.TenantExporter`), and the audit/evidence tooling that consumes admin events (`platform/audit`, `protocols/compliance/soc2.go`, `auditreport/control_areas.go`). The design under review is `docs/auto/interfaces-admin-direction1-design.md` (D1 capability codes, D2 tenant-scoped authorization, D3 graded delegation), plus the reviewer deliverables for it.

**Frameworks shown to apply** (established by the repository itself, not assumed):

| Framework | How shown | Engaged control areas |
|---|---|---|
| SOC 2 Trust Services Criteria | `protocols/compliance/soc2.go` names CC6.1 (access review), CC6.2/CC6.3 (access revocation / emergency access), CC8.1 (change management); `interfaces/admin/break_glass.go:405` ("SOC 2 evidence-chain metadata") | CC6.1, CC6.2, CC6.3, CC7.2/CC7.3 (monitoring), CC8.1 |
| GDPR | `protocols/compliance/` cites Art. 30 (`datamap.go`), Art. 15/20 (`export.go`), Art. 17 (`erasure.go`), Art. 6(1)(a) consent (`datamap.go:108`) | Art. 5(1)(e) storage limitation, Art. 15/17/20 data-subject rights, Art. 30 records of processing, Art. 32 security of processing |
| CCPA / PIPL | `protocols/compliance/erasure.go:2` ("GDPR Art. 17, CCPA, PIPL") | Erasure obligation |

**Excluded for this subsystem** (no evidence they apply): PCI DSS, HIPAA, FedRAMP, OIDF certification (the protocol review confirms no certifiable flow is touched).

**Unknown (not established by the input — no inference made):**
- **Jurisdiction** of the operator/deployment; which data-protection authority has competence.
- **Data classification** policy (the code labels tenant-export contents "PII" in comments — `interfaces/admin/tenants.go:221-231` — but no formal classification scheme is in scope).
- **ISO 27001 applicability** (no citation anywhere in the reviewed surface; not excluded, just unestablished).
- **Certification/attestation status** of the product or its operator (no attestation exists in the tree).
- **Vendor/subprocessor assessments** (SIEM fan-out exists — webhook/Kafka/CEF/OCSF/syslog, `docs/config-reference.md:393-462` — but no vendor due-diligence evidence is in the repo).

**Design-stage caveat.** D1–D3 are **Proposed**. Where this review cites design behavior as a control, it is a commitment, not a shipped control; the matrix states status per row.

---

## 2. Control matrix

Requirement → status (current / proposed) → repository evidence → process evidence → gap → owner → validation method.

| # | Requirement (framework) | Status | Repository evidence | Process evidence | Gap | Owner | Validation |
|---|---|---|---|---|---|---|---|
| 1 | **Least-privilege admin capability assignment** (CC6.1/6.2; GDPR Art. 32) | Current: method-default `admin:read`/`admin:write` only (**Verified** `middleware.go:24-30`, `governance.go:425-455`). Proposed D1: qualified `admin:<res>:<action>` codes with single fallback expansion point | `AdminRequirementFallbacks` design; `permissions.Matches` wildcard semantics (**Verified** `matcher.go:19-36`); two legacy `admin:read`-despite-POST overrides (**Verified** `build_app.go:301-304`) | None in tree (admin role assignment is operator procedure) | Fallback compatibility is deliberate non-widening (legacy `admin:write` keeps today's reach); **#1 regression risk is lockout, not escalation** — locked-out admins = change-management availability failure | Design owner | D1 middleware matrices (HTTP+gRPC), exhaustive fallback unit tests, seeded `sso-admin` E2E |
| 2 | **Sensitive-operation capability separation** (CC6.2 least privilege; key-management practice) | Proposed D1 sensitive-subset table: password reset → `admin:users:write`, key rotation → `admin:keys:write`, tenant export → `admin:tenants:write` (not `read` — **correct**: `read` would widen a POST-gated contract), device revoke, break-glass impersonate, approve | Design table; `EventAdminSigningKeyRotated` exists (**Verified** `event_types_admin.go:87-91`) | — | Export capability correctly stays write-gated; dedicated `admin:keys:write` is the right shape for key rotation | Design owner | Route-level tests pinning each entry; `:param` matching must be fixed first (see F1, architect H-1) |
| 3 | **Segregation of duties in change approval** (CC8.1; GDPR Art. 30 accountability) | Current: proposer≠approver invariant, store-authoritative transitions (**Verified** `approval.go:141-160`, sole caller `governance.go:157`). Proposed D3: capability-graded approval via `CapabilityChecker`, `RequiredCapability` carried at propose | Design D3; audit events Proposed/Approved/Rejected/Applied/ApplyFailed (**Verified** `control_areas.go:134-138`); legacy records with `""` stay approvable | Approval *procedure* (who may propose what) is operator policy — **Unknown** | Capability check is decision-time advisory (TOCTOU with grant revocation; architect L-2) — audit trail is the reconciliation record; document | Design owner + platform/audit owner | Approval-matrix tests; denial audit event with `OutcomeFailure`; legacy-pending approvability test |
| 4 | **Emergency access: authorized, audited, reviewed** (CC6.3) | Current: break-glass lifecycle events created/approved/revoked/expired/impersonation-started, each with actor, target, reason, actor IP (**Verified** `break_glass.go:405-425`; classified **Verified** `control_areas.go:127-131`). Proposed D3: strict-subset floor | Design D3; refusal path is generic 403 + log (**Verified** `break_glass_impersonate.go:76-92`) | **Post-hoc review of break-glass usage is a human procedure — no evidence in tree (Unknown)** | (a) Refusals are log-only, never audit events; (b) D3 makes mid-tier admin targets impersonatable (architect L-1) — a compatibility change needing an explicit owner call; (c) break-glass events absent from the SOC 2 evidence pack except `EventAdminBreakGlassRevoked` (**Verified** `soc2.go:46-53`) | Security owner + design owner | F5 remediations; audit event on refusal; evidence-pack row; review runbook |
| 5 | **Logical separation of customer/tenant data** (CC6.1; GDPR Art. 32 confidentiality) | Current: no tenant dimension at the admin gate; handler-side `tenantRequestMismatch` only on export (**Verified** `tenants.go:273-287`). Proposed D2: tenant-scoped grants | Design D2 (path → host → claim resolution; provider-authoritative; fail-open on unresolved tenant) | Multi-tenant operating procedures — **Unknown** | **Cross-tenant data paths remain as designed** (security F1/F2): no per-resource ownership assertion on `users/:id/password` etc.; tenant-tagged grants may carry platform-wide codes (`admin:keys:write`); stock binary ships **no** tenant check until `SetTenantResolver` is wired (architect I-2) | Security owner | D2 oracle byte-identity tests; tenant-eligible code allow-list in ConformanceSuite tenant section; E2E |
| 6 | **Access-review evidence** (CC6.1) | Current: `SOC2Reporter.AccessReview` = per-client `ListAssignments` (**Verified** `soc2.go:149-169`). Proposed D2: tenant-tagged assignments stored separately, base `ListAssignments` ignores them (**Verified** design D2 storage section) | `soc2.go:149-169`; design D2 | Access-review cadence/owner — **Unknown** | **Tenant-scoped admin grants will be invisible to the access-review evidence pack** — the single most consequential compliance gap of D2 | Platform/audit owner + design owner | Extend evidence pack with a tenant-assignments section or explicitly exclude with rationale; evidence-pack golden test |
| 7 | **Change-management evidence** (CC8.1) | Current: curated `changeManagementEventTypes` covers admin mutations but **omits all five `EventAdminChange*` events** (**Verified** `soc2.go:25-43`) | `soc2.go:25-43` vs `control_areas.go:134-138` | — | **Approval workflow decisions — the core CC8.1 evidence — are not surfaced by the SOC 2 pack**; D3's capability-refused approvals (reused `EventAdminChangeApproved`+`OutcomeFailure`) would also be absent | Platform/audit owner | Add the five events to the curated list (or document exclusion); evidence-pack test |
| 8 | **Audit-trail integrity / tamper evidence** (CC7.2/7.3; GDPR Art. 30) | Current: hash chain over events, resume-from-last-persisted across restarts (**Verified** `chainer.go`); documented limitation: tampering with the *last* event undetectable without external attestation | `chainer.go`; `docs/config-reference.md` (audit backends) | Head-hash external attestation (publish/sign) — **Unknown** | Chain breaks at retention-prune boundary are documented and accepted (`sqlite/maintenance.go:22-45`) — operators must choose and record a posture | Platform/audit owner | Operator attestation runbook; `VerifyChain` test at retention boundary |
| 9 | **Retention / storage limitation** (GDPR Art. 5(1)(e); CC7.3) | Current: sqlite `Prune` (external cron or `startAuditRetention`); memory ring capacity default 10 000; **Postgres retention unimplemented — `audit.retention.enabled` silently no-ops for `audit.backend: postgres`** (**Verified** `build_app_core.go:313-335`, db-review F3) | `platform/audit/sqlite/maintenance.go`; `cmd/sso-server/build_app_core.go:313-335` | Retention policy values and scheduling — **Unknown** | **Storage-limitation obligation not enforceable on the durable path**; unbounded `audit_events` growth on pg; SIEM query degradation | Platform/audit owner + ops | pg prune loop or fail-loud boot; retention config test per backend |
| 10 | **Failed-access-attempt monitoring** (CC7.2/7.3) | Current: gRPC denials audited (`EventAdminGRPCCalled`+`OutcomeFailure`, **Verified** `middleware.go:247-277`); **HTTP gate denials are not audited** (`SetAuditRecorder` is gRPC-only, **Verified** `middleware.go:137-142`; `authenticateHTTP` writes 401/403/500 with no audit, **Verified** `middleware.go:349-385`) | `middleware.go` | SIEM alerting rules — **Unknown** | D1/D2 add new HTTP denial classes (scope, tenant) that will inherit the silence — exactly the classes that indicate cross-tenant probing; the design's resolver-error fail-open already requires audit, but ordinary denials don't | Security owner + platform/audit owner | Audit event on HTTP gate denial (audit-internal details; oracle-safe — the response body stays constant) |
| 11 | **Pseudonymization not silently defeated** (GDPR Art. 32) | Current: enabling `pairwise_subjects` without a salt uses the public `DefaultPairwiseSalt` (**Verified** `shared/security/pairwise.go:136`; db-review F2) | `shared/security/pairwise.go:136`; `build_app_oidc.go:376-405` logs only "enabled" | — | Silent privacy regression: invertible pairwise `sub` in production | Design owner (boot guard) | Boot test: feature enabled + no salt → error/degraded |
| 12 | **Privacy: data export** (GDPR Art. 15/20) | Current: tenant export audited with non-PII summary metadata (**Verified** `tenants.go:287-297`, `EventAdminTenantExported`); D1 keeps export write-gated | `tenants.go:248-297`; `protocols/compliance/tenant_export*.go` | — | None identified — export is least-privileged and audited; PII never enters audit metadata | Design owner | Existing export tests + D1 matrix |
| 13 | **Privacy: erasure / retention endpoints** | Current: erasure and retention sweep endpoints exist and are admin-gated (`protocols/compliance/erasure.go`, `retention.go:307` admin:write) | `protocols/compliance/` | Erasure runbook (partial-failure handling) — **Unknown** | Unchanged by the design; out of scope | — | Existing tests |
| 14 | **Audit evidence continuity across DR** (CC7.3; Art. 30) | Current: snapshot/restore pipeline excludes audit and hot stores (**Verified** `interfaces/snapshot/snapshot.go`; db-review F7) | snapshot resources list | DR runbook RPO/RTO — **Unknown** (`dr-framework.md` claims not verified in this pass) | Audit continuity after restore depends on the durable audit backend itself; not covered by snapshot | Ops | DR runbook section stating audit RPO and signing-key re-adoption |
| 15 | **Governance workflow state durability** (CC8.1 evidence chain) | Current: approval store, break-glass sessions, notification prefs, write-quota are **memory-only** in the stock binary (**Verified** `build_stores.go:290,308`; `build_app.go:322`) | db-review F4 inventory | — | Approval records/emergency sessions vanish on restart; multi-replica compliance use unsupported; durable evidence rests solely on the audit backend (which must be configured durable — default is memory ring) | Ops + design owner | Deployment-guide limitation statement; optional sqlite backends |
| 16 | **Wire-contract stability for SIEM/consumers** (Art. 30; change discipline) | Current: `docs/error-codes.md:87` documents `tenant_mismatch`; spec acceptance line asserts it (**Verified**); design resolves to byte-identical `forbidden` at the middleware | design D2; `error-codes.md:87`; spec `:136-138` | SIEM parsing rules — **Unknown** | Doc/gate contradiction must be resolved in the **same change** as the D2 middleware (AGENTS.md §5.6); the AGENTS.md oracle-row amendment is a contract-level change needing maintainer authority | Maintainers + design owner | Docs + spec line amended in the D2 change; SIEM rule update note |

---

## 3. Findings

Sorted by severity. Regulatory risk is assessed against the frameworks in §1 only.

### High

**F1 — Tenant isolation as designed leaves cross-tenant data-access paths; logical separation is not yet a control.**
Evidence (**Verified**): design D2 resolves tenant from path param only on `/tenants/:id` routes, host, or claim; on `users/:id/password`, `devices/bulk-revoke`, `changes/:id/approve` the check validates grant-vs-request-tenant, never resource ownership (security-review F1); `AddTenantRole` has no code-space restriction, so a tenant-tagged grant can carry platform-wide codes such as `admin:keys:write` (security-review F2); the stock binary ships no tenant check until `SetTenantResolver` is wired (architect I-2); fail-open on unresolved tenant is documented and deliberate.
Business/regulatory risk: a tenant-scoped admin resetting another tenant's user password or rotating the platform signing key is a cross-tenant confidentiality/availability event (GDPR Art. 32; SOC 2 CC6.1, CC7.x) — the exact class of incident multi-tenant SaaS operators must exclude by design.
Remediation: (a) per-resource ownership assertion on non-tenant routes or an explicit v1 posture that excludes them from tenant scoping; (b) tenant-eligible code allow-list enforced in the `TenantPermissionsProvider` and its ConformanceSuite section; (c) state the stock default ("no tenant check until wired") in release notes.
Evidence needed for closure: D2 oracle byte-identity tests; allow-list conformance rows; a wiring smoke test; release-note posture statement.

**F2 — Evidence surfaces will not reflect the new authorization dimensions: tenant-scoped grants absent from access reviews; approval workflow absent from the change-management pack.**
Evidence (**Verified**): `SOC2Reporter.AccessReview` reads `Permissions.ListAssignments` (`soc2.go:149-169`), and design D2 states base `ListAssignments` ignores tenant-tagged data; `changeManagementEventTypes` (`soc2.go:25-43`) contains none of the five `EventAdminChange*` events that `auditreport` classifies (`control_areas.go:134-138`).
Business/regulatory risk: under SOC 2 CC6.1, the access-review evidence pack would not list tenant-scoped admins (the very population D2 creates); under CC8.1, approval decisions (approve/reject, approver identity, and D3's capability-refused outcomes) would not be surfaced in the change-management evidence. An auditor relying on the pack sees an incomplete control population.
Remediation: extend the evidence pack in the same change as D2/D3 — a tenant-assignments section (or documented exclusion) and the five change events added to the curated list; D3's denial records inherit the fix via the reuse decision.
Evidence needed for closure: evidence-pack golden test containing tenant-tagged assignments and an approval decision.

### Medium

**F3 — HTTP admin-gate denials are unaudited; the new D1/D2 denial classes inherit the silence.**
Evidence (**Verified**): `SetAuditRecorder` is gRPC-only (`middleware.go:137-142`); `authenticateHTTP` emits 401/403/500 with no audit event (`middleware.go:349-385`); gRPC denials are audited with `OutcomeFailure` (`middleware.go:247-277`).
Business/regulatory risk: failed-access-attempt evidence (CC7.2/CC7.3 monitoring) is absent on the HTTP surface; tenant denials — the primary signal for cross-tenant probing — would be invisible to SIEM.
Remediation: record HTTP gate denials as audit events with audit-internal detail; the response body stays the constant `forbidden` literal, so oracle safety is unaffected. Decide whether D2 resolver-error fail-open events are included (the design already requires audit there).

**F4 — Audit retention is not enforceable on the durable path.**
Evidence (**Verified**): `startAuditRetention` returns nil unless the primary is sqlite (`build_app_core.go:313-335`); no pg prune loop exists (db-review F3); sqlite retention is external-cron with documented chain-break posture (`sqlite/maintenance.go:22-45`); default audit backend is a 10 000-event memory ring.
Business/regulatory risk: GDPR Art. 5(1)(e) storage limitation cannot be met for a Postgres-backed audit trail; unbounded growth degrades the Art. 30/audit queries that the evidence pack depends on.
Remediation: pg prune (indexed `DELETE ... WHERE ts_unix_ns < ?`) or fail-loud boot when retention is requested for a backend that cannot honor it; document the chain-break posture choice.

**F5 — Emergency-access evidence and posture need completion.**
Evidence (**Verified**): refusals are log-only (`break_glass_impersonate.go:76-92` — `Logger().Error` + generic 403, no audit event); minting is audited with actor/target/reason/IP (`break_glass.go:405-425`); D3 lifts the blanket refusal for strictly-lower admin targets (architect L-1); break-glass lifecycle events are not in the SOC 2 pack except `EventAdminBreakGlassRevoked` (`soc2.go:46-53`).
Business/regulatory risk: CC6.3 emergency access — failed emergency attempts have no evidence, and the mid-tier impersonation widening (an `admin:*` holder acting with an `admin:write` holder's boundary) ships without a declared review procedure.
Remediation: audit refusals with a generic event; get an explicit owner decision on mid-tier impersonation; document the post-hoc break-glass review procedure (process evidence, not code); add break-glass events to the evidence pack.

**F6 — Pairwise pseudonymization is silently defeated by a public default salt.**
Evidence (**Verified**): `shared/security/pairwise.go:136`; `ResolvePairwiseSalt` returns the constant when salt and salt_file are empty; `wirePairwiseSubjects` logs only "enabled" (db-review F2).
Business/regulatory risk: an operator enabling `pairwise_subjects` without a salt gets invertible pairwise identifiers — a silent privacy regression against the GDPR Art. 32 measures the feature implies.
Remediation: boot error (or degraded mode + `logger.Error`) when enabled without a salt; document salt rotation.

### Low

**F7 — Governance workflow state is ephemeral in the stock binary.**
Evidence (**Verified**): approval store, break-glass sessions, notifications, write-quota are memory-only (`build_stores.go:290,308`; `build_app.go:322`). Durable evidence rests solely on the audit backend — which defaults to memory.
Remediation: state the limitation in the deployment guide; optionally add sqlite backends (patterns exist in `infrastructure/defaultimpl/sqlite`).

**F8 — Audit continuity across DR is undefined.**
Evidence (**Verified**): snapshot pipeline excludes audit and hot state (db-review F7); `dr-framework.md` targets not verified in this pass.
Remediation: DR runbook section covering audit RPO (durable audit backend required) and signing-key re-adoption after restore.

**F9 — Wire-contract change for tenant denials must move with the code.**
Evidence (**Verified**): `docs/error-codes.md:87` and the spec acceptance line assert `tenant_mismatch`; the design resolves to byte-identical `forbidden` at the middleware — the stricter, oracle-safe reading (principal review concurs).
Remediation: amend error-codes.md, the AGENTS.md oracle row (maintainer authority — a contract-level change), and the spec acceptance line in the same change as the D2 middleware; note SIEM rule updates.

### Verified positive controls (no action)

- Segregation of duties in change approval: proposer/approver differ and store-authoritative transitions preserved; capability refusal never transitions the record.
- Break-glass minting is non-bypass (sub=target, `act`=actor, TTL clamp, revocation cascade) and fully audited with reason — the D3 floor keeps equal-level refusal.
- The fallback design is non-widening for legacy grants: `admin:tenants:export → write` (not read), strict-subset floor, carried `RequiredCapability` with `""` = approvable (legacy-safe).
- Audit hash chain with restart-seam resume; SIEM fan-out (CEF/OCSF/syslog/webhook/Kafka) with PII redaction and HMAC-signed webhooks.
- Tenant export audited with non-PII summary metadata; `EventAdminSigningKeyRotated` exists for the key-rotation path D1 gives a dedicated capability.

---

## 4. Audit-readiness summary

**What exists in the repository (evidence-assembly tooling, all **Verified** present, none attesting):**
- SOC 2 evidence pack generator (`protocols/compliance/soc2.go` — CC6.1 access review, CC8.1 change management, CC6.2/6.3 access revocation; admin:read gated).
- GDPR tooling: Art. 30 data map, Art. 15/20 export, Art. 17 erasure, retention sweeps, consent records with legal-basis metadata.
- Audit hash chain, retention primitives (sqlite), SIEM export formats, event classification (`auditreport/control_areas.go`).

**Required documents/procedures not in the repository (process evidence — all **Unknown**, needed before any audit claim):**
1. Retention policy values and execution schedule per backend (including the pg gap, F4) and the chain-break posture choice.
2. Break-glass post-hoc review procedure (who reviews impersonation events, cadence, escalation).
3. Access-review cadence and owner for the CC6.1 evidence pack.
4. Incident-response runbook and SIEM alerting rules (including the HTTP-denial gap, F3).
5. DR runbook with audit RPO and signing-key re-adoption (F8).
6. Jurisdiction and data-classification determinations; vendor/subprocessor assessments; attestation/certification status.

**Next decisions (owner in parentheses):**
1. Tenant-isolation posture for v1: per-resource ownership assertions vs explicit exclusion of non-tenant routes; tenant-eligible code allow-list (security owner).
2. Evidence-pack extension for tenant-scoped assignments and `EventAdminChange*` events in the same change as D2/D3 (platform/audit owner, design owner).
3. HTTP denial audit on the admin gate (security owner).
4. Postgres audit retention: implement or fail-loud (platform/audit owner, ops).
5. Pairwise-salt boot guard (design owner).
6. Break-glass mid-tier impersonation: explicit owner call + release note (security owner, design owner).
7. AGENTS.md oracle-row amendment authority; `admin:changes:approve` declaration; spec acceptance-line amendment (maintainers, design owner).
8. Durable governance stores (approvals, break-glass) — deploy-guide limitation now, backends later (ops, design owner).

**Bottom line.** The design's direction is sound from a controls standpoint — it tightens least privilege (D1), adds a tenant dimension that must be completed to be a control (F1), and preserves SoD and emergency-access audit while grading delegation (D3). The distinctive compliance obligations this review adds beyond the engineering reviews are evidence-surface ones (F2: access-review and change-management packs will not reflect the new populations), monitoring evidence (F3), retention enforceability (F4), and the process evidence that no repository can supply (review procedures, retention policy, jurisdiction). None of this constitutes legal advice, a compliance opinion, or a certification claim.
