# Compliance Review — `domains/userlifecycle` direction 2 (erase-on-purge, INVITED provisioning, tombstone removal)

**Reviewer role:** compliance_officer (`ai-dev/prompts/compliance_officer.md` + `README.md` baseline rules).
**Inputs reviewed:** `docs/auto/domains-userlifecycle-direction2-design.md`, `...-direction2-spec.md`, `...-direction1-design.md`, and the working tree at this revision.
**Checks that actually ran:** source inspection only (`read`/`rg`/`sed` over every surface cited below). No `go build`, no `make ci`, no tests — this is an advisory design review, not a gate pass or certification evidence.
**Evidence labels:** Verified / Partial / Missing / Proposed / Unknown per the README standard. Framework applicability is judged strictly from what the tree itself claims; jurisdiction, data classification, and certification status are marked unknown where the input does not establish them.

**One correction to the security review's F1 evidence (recorded for the record):** `PasswordCredentialDeleter` does **not** have zero production callers. `internal/adminuser/service.go:276-295` (`deleteUserPasswordCredential`, called from `DeleteUser` at `:274`) type-asserts the SPI and deletes the hash best-effort on the admin user-delete path. The security finding's *conclusion* stands verified (the `compliance.Eraser` itself has no credential leg, so purge leaves the bcrypt hash alive), but the remediation is not only feasible — it is **precedented in-tree** on the very admin user-delete path direction 2's purge conceptually subsumes.

---

## 1. Applicable-scope statement and excluded/unknown frameworks

### Frameworks shown to apply (repository-established)

| Framework | How the tree establishes applicability | Status of direction 2 against it |
|---|---|---|
| GDPR (Art. 15/17/20/30) | `protocols/compliance/erasure.go` package doc ("regulations (GDPR Art. 17, CCPA, PIPL) require"); `docs/openapi.yaml:1792,2066,3982,4031,4851` (Art. 15/20 export, Art. 17 erase, Art. 30 data map); `protocols/compliance/datamap.go` (Art. 30 record) | **In scope — the central object of this review.** Erasure completeness (Art. 17), processing record (Art. 30), accountability (Art. 5(2)), security of processing (Art. 32) |
| CCPA (Cal. Civ. Code §1798.105 right to delete) | Same `erasure.go` package doc; erase endpoints serve the right to delete | In scope — same erasure-completeness analysis as Art. 17 |
| PIPL (Art. 47 deletion right) | Same `erasure.go` package doc | In scope — same analysis |
| SOC 2 (Trust Services Criteria CC6.1/CC6.2/CC6.3/CC6.6, CC8.1) | `platform/audit/auditreport/control_areas.go` (TSC evidence buckets), `cmd/sso-ctl/soc2report`, `docs/error-codes.md:394-400,519-520`, `docs/openapi.yaml:4803-4816,8785,14326` | In scope as **mechanical evidence-pack machinery** — with the package's own mandatory disclaimer: "ILLUSTRATIVE MECHANICAL cross-reference, NOT a vetted SOC2 control mapping" (`auditreport` control_areas.go comment). No SOC 2 report, audit, or certification is claimed or implied |
| PCI DSS 7.2, HIPAA §164.312(a) | Cited only as evidence-chain mappings for the break-glass surface (`docs/error-codes.md:519-520`, `docs/openapi.yaml:14326`) | **Limited scope** — those citations do not establish a PCI/HIPAA compliance program; they are per-surface evidence-chain notes. Direction 2 touches neither surface |

### Excluded and unknown

- **Excluded — ISO 27001, FedRAMP, DPDP, LGPD, NIST 800-53, etc.:** no canonical contract, config, test, or documentation in the tree establishes applicability. Mentions in `docs/tech-lead-analysis/*` and `docs/architect-analysis/*` are analysis prose, not contracts; per README rule 4 they do not establish scope.
- **Unknown — jurisdiction and applicable law:** the tree does not establish where data subjects reside or which regulator applies. GDPR/CCPA/PIPL citations are feature-justification, not a jurisdiction determination. Marked unknown; the operator/DPO owns this.
- **Unknown — data classification:** no classification scheme (PII/SPI/confidential tiers) exists in the tree for lifecycle records, audit metadata, or erasure reports. The review assumes lifecycle records and audit metadata are personal-data-bearing (they carry user_id, actor, reason free text, timestamps) — that is an assumption, not a tree-established fact.
- **Unknown — certification:** no SOC 2/ISO/GDPR certification, attestation, or audit result exists in the tree, and per my instructions implemented controls are not evidence of certification. The `auditreport` disclaimer explicitly disclaims a vetted mapping.
- **Excluded — contractual obligations:** no customer DPAs, processor agreements, or contractual control matrices exist in the tree. SDK embedders consume the library out of process; their obligations are out of scope and unverifiable here.
- **Out of scope — browser frontends, OpenResty/Envoy deployment assets:** no compliance-relevant input provided.

---

## 2. Control matrix

Legend: **V** = verified in tree; **P** = proposed (design-only); **Gap** = obligation with no adequate control (code or process). "Process evidence" distinguishes human procedures/external attestations from technical controls; where the tree has none, that is stated as a gap, not assumed.

| # | Obligation | Control (technical) | Status / repository evidence | Process evidence | Gap | Owner | Validation method |
|---|---|---|---|---|---|---|---|
| 1 | GDPR Art. 17 / CCPA / PIPL — complete erasure of the subject's data | `compliance.Eraser` legs: refresh tokens across clients, sessions, consent, MFA (incl. WebAuthn via adapter), reset/email-change tokens, notifications, user row. Credentials-first ordering (`EraseSubject`: refresh → sessions → consent → MFA → self-service → notifications → user) | **V** `protocols/compliance/erasure.go:23-53,60-95`; passkeys covered in stock wiring (`cmd/sso-server/build_app_selfservice.go:352` `NewMFAEnrollmentAdapter`); consent non-inheritance documented (`erasure.go:32-35`) | — | **Password verifier is NOT erased** (no credential leg); login history and device records are not erased (no legs at all). See Finding C-1 | Security eng. + compliance/DPO | ssotest resurrection test; wiring test; datamap update |
| 2 | GDPR Art. 17 — erasure is not merely claimed | Purge now runs the real eraser; fail-closed mode refuses the transition before `Append` on erasure failure (`500 internal_error`, `RecordTransitionFailure` audit); reaction mode surfaces the report in the response and audit meta | **P** design §1.3/§1.4; verified handler today only Appends + audits (`interfaces/admin/lifecycle.go:73-91` — the "dishonest state" the spec fixes) | — | Erasure evidence vanishes when `audit.enabled: false` (see row 8); partial-erasure visibility depends on the response+audit being retained | Security eng. | Fail-closed ssotest (500, state ARCHIVED, no PURGED history) |
| 3 | GDPR Art. 5(1)(e) storage limitation / retention | PURGED tombstone deleted after clean erasure (record does not outlive the erased account); history retained only in audit per `audit.retention.*` | **P** design Decision 3.2; **V** audit retention config exists (`docs/config-reference.md:387`) | — | Orphaned PURGED records after crash/Delete-failure accumulate unboundedly (`ListByState` has zero production consumers today — **V**); no reaper | DB eng. | Unit reaper test or documented non-goal (F2 db) |
| 4 | GDPR Art. 30 — records of processing activities | `GET /api/v1/admin/compliance/data-map` (admin:read), 6 categories, retention folded from config | **V** `protocols/compliance/datamap.go`, `interfaces/sso/server_backup.go:224-226`; `datamap_test.go` exists | — | **No lifecycle-record category; no password-credential category; no login-history/device category.** Design's Decision 8 contract-update table omits `datamap.go`. See Finding C-3 | Docs/DB eng. | Extend `BuildDataMap` + `datamap_test.go` in the same change |
| 5 | GDPR Art. 15/20 — subject access completeness | `compliance.Exporter` (Users, Sessions, + consent/MFA extras) | **V** `cmd/sso-server/compliance_routes.go:71-92` | — | Lifecycle history (state, actor, reason) not exported; direction 2 adds more subject-referencing history (seed reasons, accept events). Whether lifecycle history is in-scope Art. 15 data is a legal determination — must be made and documented, not assumed | Compliance/DPO + eng. | Documented decision + datamap entry; optionally extend exporter |
| 6 | GDPR Art. 5(1)(f)/Art. 32 — access control & integrity of processing | Lifecycle routes mount under `/api/v1/admin/` with default method-scope rule (GET=admin:read, else admin:write); SCIM mount admin-gated; oracle-safe failure shapes (generic `internal_error`) | **V** `interfaces/admin/middleware.go:73-74`; design §1.3/§5 | — | **INVITED state is per-process memory**: restart/rolling-restart silently resets every record to ACTIVE with no audit event (design's own invariant "no record = ACTIVE"). Once direction 1 gates login on it, a restart grants access to never-accepted accounts. See Finding C-2 | DB eng. + product | Restart-persistence acceptance test; durable store peer before direction-1 gate (recommended) |
| 7 | SOC 2 CC6.1/CC6.2 — access & revocation | Purge revokes refresh families across clients, destroys sessions, deletes user; admin actions stamped with actor; `admin_user_lifecycle_changed` in CC6.3 bucket | **V** erasure.go legs; `platform/audit/auditreport/control_areas.go:126`; bus wiring is admin-gated | — | Pre-purge stateless access tokens survive to TTL (inherited, documented as direction-1 mitigation); INVITED interim fail-open (Finding C-5) | Security eng. | ssotest purge revocation assertions; token-path gate test with direction 1 |
| 8 | GDPR Art. 5(2) accountability / SOC 2 CC8.1 — audit trail of erasure | `EventAdminUserLifecycleChanged` with erasure-report meta (single event, no double-count); `RecordTransitionFailure` on fail-closed refusals; no new event types (bounded cardinality, `auditreport` drift test untouched) | **P** design §1.3; **V** event consts `platform/audit/auditspi/event_types_admin.go:30,68` | — | (a) Purge erasures are counted only in the CC6.3 admin-actions bucket, never in the Privacy/DSR bucket (`EventAdminSubjectErased` deliberately not emitted) — SOC2 privacy counts and DSR dashboards undercount purge erasures; (b) `audit.enabled: false` → nil recorder → bus inert; erasure happens unrecorded (handler-side enforcement still runs — a genuine strength, but the *evidence* is gone). See Finding C-4 | Compliance/DPO + eng. | Meta-presence integration test; auditreport note; config-reference consequence note |
| 9 | GDPR Art. 6(1)(a) — consent evidence not inherited on re-registration | Consent grants revoked before user deletion (eraser ordering), documented for re-registration | **V** `erasure.go:32-35, eraseConsent` | — | — | — | Already covered by existing compliance tests; extend to purge path |
| 10 | Access-approval governance (INVITED = "not yet accepted") | Seed writers (admin form, SCIM create) + accept trigger on first login; `accept_on_first_login` default true | **P** design Decision 2 | — | **Interim fail-open:** with direction 1 unlanded, INVITED accounts authenticate indefinitely; `accept_on_first_login: false` (documented as "stays INVITED") is a no-op knob until the gate lands. Documented intent ≠ enforced control. See Finding C-5 | Product + eng. | Ordering acceptance test (both direction-1 orderings); interim denial or release coupling |
| 11 | Fail-closed configuration must not silently fail open | `purge_requires_erasure: true` + nil eraser → loud boot warning, knob inert | **P** design §1.4 | — | Precedent in tree is a **boot error**, not a warning: `cmd/sso-server/build_stores.go:330-338` raises when `auto_deprovision` is enabled without `user_lifecycle.enabled` ("must see the loud boot error, not a silent no-op"). A compliance assertion ("purges require erasure") that is warn-and-inert will be documented as enforced and is not. See Finding C-6 | Eng. | Wiring-test extension (boot-error decision) |
| 12 | Encryption / key management | Not materially touched by this design: no new durable storage (lifecycle store is memory-only, per-process); existing key-management controls unchanged | **V** `serverbuildplatform/build_userlifecycle.go` (memory store); design Decision 4 | — | Memory-only store means no at-rest exposure but also no durability — see row 6; durable peer's at-rest posture is a future decision | DB eng. | N/A at design stage |
| 13 | Incident response — purge as IR action | Fail-closed purge, audit trail, erasure report | **P** design §1.3 | **Gap:** no IR runbook in tree (who may purge, verification of admin identity, chain of custody for the erasure report) | F1 resurrection defeats purge-as-IR: leaked pre-purge password re-enters and, because MFA was erased, the resurrected account has no second factor | Security eng. + ops | Covered by Finding C-1 remediation |
| 14 | Vendor / third-party management | No new vendors; SDK embedders run out of process over typed protocols; nested modules own their builds | **V** AGENTS.md module rules | **Gap:** embedder-side erasure semantics (`EraseOnPurge` reference reaction; record deletion is handler-owned, bus reactions cannot see `Report.UserDeleted`) are contractual surface, not documented contract | Embedder who drives PURGED via the bus gets erasure but the tombstone persists until re-provisioning (protocol reviewer F2) | Protocol eng. | `EraseOnPurge` doc note + embedder-facing warning |
| 15 | Backup/restore vs. erasure | `backup.keep` retention config exists | **V** `docs/config-reference.md:554` | **Gap:** no procedure or documentation that restored backups (a) re-materialize erased data and (b) reset lifecycle records to zero → all accounts ACTIVE (database reviewer F-DB-1/restore note). GDPR Art. 17(3) cost-constraint analysis is a process decision | Ops + compliance/DPO | Backup/restore note in config-reference; restore drill evidence |
| 16 | Wire-contract accuracy (evidence value of responses) | Shared `ReportView`; `previous_state` omitted for seeds; fail-closed reuse of `internal_error`; no new error codes | **P** design §1.3/§2.2/§8 | — | `ReportView` must reproduce `eraseResponse` byte-for-byte including `dry_run` (design's sample PURGED JSON omits it — QA F7); omission of `previous_state` on seeds must be documented (protocol F4) | Eng. | Byte-parity test vs. `eraseResponse`; openapi conformance |
| 17 | Multi-tenant isolation (cross-tenant erasure) | Lifecycle store + Eraser keyed by userID only; fleet-wide admin | **V** erasure.go; design residual list | — | Safe only if user IDs are globally unique across tenants; purge is a **new destructive trigger** for an inherited assumption. Needs a residual note + tenant-scoping documentation | Eng. | Documented residual (security residual 5) |

---

## 3. Findings

Sorted by severity. "Evidence needed for closure" states what a future audit would need to see.

### C-1 — High: Purge leaves the password verifier alive; the deleted account re-authenticates and the tombstone deletion makes the resurrection invisible

**Verified evidence:** `compliance.Eraser` has no password-credential leg (`protocols/compliance/erasure.go:23-53` — legs are Users/Sessions/Refresh+Clients/Consent/MFAEnrollments/PasswordReset/EmailChange/Notifications; `EraseSubject` order at `:60-95`). The SPI exists (`shared/core/password_reset.go:106` `PasswordCredentialDeleter`) and is **used in production** on the admin user-delete path (`internal/adminuser/service.go:274-295` — best-effort hash deletion after `DeleteUser`) — so the mechanism is proven, the eraser simply does not compose it. Login with the surviving hash succeeds (`domains/authenticators/password.go` verifies purely against the verifier), the not-found user is treated active (`interfaces/sso/server_login_auth.go:144-153` `rejectDeactivatedUser`), and `upsertLoginUser` recreates the record (`interfaces/sso/server_login.go:476-500` `CreateOrUpdate`; same at `server_oauth.go:228` on the federated leg). Direction 2's delete rule removes the PURGED record exactly under `rep.Err()==nil && rep.UserDeleted` (design §3.2) — the precise condition under which re-login is possible — after which `Store.Get` reads ACTIVE ("no record = ACTIVE") and even direction 1's future gate would admit the login. Additionally, login history (IPs, user agents) and device records are erased by no leg at all — pre-existing, shared by every erasure surface.

**Business/regulatory risk:** GDPR Art. 17(1)(b)/(d) and CCPA §1798.105 erasure claims are incomplete (the verifier is subject data); a DSR "erasure completed" response is factually wrong. Purge as incident response fails: a leaked pre-purge password re-enters a "deleted" account whose MFA was itself erased by the purge. Because the tombstone is removed at the same moment, the resurrection is undetectable except by replaying the original purge audit event — a regulator would classify this as an account-takeover path on a deleted account.

**Remediation (required):** (1) add a password-credential leg to the lifecycle eraser via `PasswordCredentialDeleter`, ordered credentials-first (beside/after refresh+sessions, before `eraseUser`), with a missing store or missing extension recorded as a `Skipped` leg — never silent success; (2) amend the delete rule to require the credential leg completed (or refuse tombstone deletion when the leg was skipped), so the tombstone survives exactly when resurrection is possible; (3) retrofit the same leg to the existing self-service and admin GDPR erase endpoints (same defect, smaller blast radius); (4) state in `docs/feature-matrix.md` that federated re-provisioning is a deliberate fresh-provisioning semantic while the password path is denied.

**Evidence needed for closure:** ssotest resurrection test (seed account with live hash + session + refresh family; purge; `user_deleted:true`; then `POST /auth/login` with the old password → 401; `GET /admin/users/:id/lifecycle` → 404 with purge audit intact); negative wiring test (credential leg unwired → tombstone retained); datamap gains a `password_credentials` category.

### C-2 — High: The INVITED approval state is per-process memory; a restart silently converts INVITED → ACTIVE with no audit event

**Verified evidence:** `BuildUserLifecycle` hard-codes `userlifecyclememory.New()` (`cmd/sso-server/serverbuildplatform/build_userlifecycle.go:18-23`); no SQL peer under `infrastructure/` (grep-verified). Direction 2 makes INVITED production-reachable (design Decision 2); direction 1 (unlanded, verified absent) will make it an authentication decision. The design's own anchor is "no record = ACTIVE" (`userlifecycle.go` doc, `memory.Store.Get`), and `Delete`/restart both produce "no record".

**Business/regulatory risk:** INVITED is an access-approval control: "not yet accepted" is a governance decision. A restart, rolling deploy, or pod reschedule silently erases every approval decision, and once direction 1 lands, previously-denied accounts authenticate with no audit trail of the state loss — a control-effectiveness failure (Art. 5(1)(f), SOC 2 CC6.1) that is invisible in production monitoring. The reaction-mode crash window (Append before erase) additionally leaves no audit event at all, since `RecordTransition` runs after the erasure.

**Remediation (required before direction 1's gate ships):** durable `userlifecycle.Store` peer (the design already requires `Delete` of any future SQL peer — §3.1) selected by config mirroring `BuildUserProvider`; or, as an interim, a startup warning when `invite.enabled` is set with the memory store, plus a restart-persistence acceptance test. Record the restore-from-backup semantics (restore → zero records → all accounts ACTIVE) in `docs/config-reference.md` (database reviewer F-DB-1).

**Evidence needed for closure:** integration test proving state survives a simulated restart (rebuild server from same durable store); config-reference note; restore-drill evidence.

### C-3 — Medium: The GDPR Art. 30 data map is not updated — lifecycle records become a new personal-data category the record never inventories

**Verified evidence:** `BuildDataMap` enumerates exactly six categories — user_profile, sessions, consent_grants, mfa_enrollments, refresh_tokens, audit_log (`protocols/compliance/datamap.go:60-70`). No lifecycle category; no password-credential category; no login-history/device category. The design's contract-update table (Decision 8) lists error-codes, openapi, config-reference, feature-matrix — **not `datamap.go`**. Direction 2 adds a category of subject-referencing records (user_id, state, history of transitions with admin actor and free-text `reason` — note `reason` is unbounded free text, a personal-data surface) whose retention policy is now "deleted on completed purge; else per audit retention".

**Business/regulatory risk:** Art. 30 is a "records of processing activities" accountability artifact; a DPA or regulator reviewing the data map will find processing (lifecycle state machine, erasure-on-purge) with no inventory entry — a documentation failure that converts a technical control (erasure) into an unverifiable one.

**Remediation:** add a `lifecycle_records` category (store: `domains/userlifecycle`; fields: user_id, state, history entries with actor/reason/timestamp; legal basis: governance/legitimate interest; retention: until completed erasure, else audit-retention window) and a `password_credentials` category (verifier hash; retention: until account erasure — currently **not** enforced, tying back to C-1); update the `user_profile` retention text to name PURGED as an erasure trigger. Extend `datamap_test.go` (`TestBuildDataMap_CoreCategoriesPresent`) in the same change.

**Evidence needed for closure:** updated `BuildDataMap` + unit test; the generated data-map JSON reviewed by the DPO.

### C-4 — Medium: Erasure accountability is split across buckets and can be absent entirely — purge erasures never reach the Privacy/DSR audit bucket, and `audit.enabled: false` leaves no retained erasure evidence

**Verified evidence:** `EventAdminUserLifecycleChanged` is filed under CC6.3 admin actions (`platform/audit/auditreport/control_areas.go:126`); `EventAdminSubjectErased`/`EventSubjectSelfErased` are filed under Privacy/DSR (`:176`). The design deliberately does not emit `EventAdminSubjectErased` on purge (Decision 1.3 — "would double-count erasures in compliance queries"). When `audit.enabled: false` the recorder is nil and the bus is inert (design §1.4 warning; verified wiring pattern) — handler-side erasure still enforces, but nothing retains the fact.

**Business/regulatory risk:** SOC 2 privacy/DSR evidence counts and GDPR erasure-request accounting will undercount purge-driven erasures; an auditor querying "all erasure events" sees none of them. Conversely the design's anti-double-count reasoning is sound — the fix is queryability, not a second event.

**Remediation (recommended):** keep the single-event decision; make purge erasures discoverable by (a) documenting in `docs/error-codes.md` and the `auditreport` package comment that a `admin_user_lifecycle_changed` event whose meta carries `erasure_report` IS an erasure action for DSR accounting, and (b) adding the fixed meta key to the SOC2 report guidance or a documented filter. For `audit.enabled: false`, add the consequence to the boot-warning text ("purges proceed un-erased and unrecorded") — the design already warns the bus is inert; the warning should name the evidence loss.

**Evidence needed for closure:** integration test asserting the erasure meta key is present on purge; docs note; drift test untouched (no new event types — verified the `auditreport` one-bucket rule holds).

### C-5 — Medium: INVITED provisioning ships a control ("not yet accepted") whose denial half is deferred to an un-landed direction 1 — interim fail-open, and `accept_on_first_login: false` is a documented no-op until then

**Verified evidence:** no lifecycle state gates authentication anywhere in the tree (no `AllowsAuthentication`/`rejectLifecycleBlockedUser`; `docs/config-reference.md:695` states the store "NEVER gates authentication"); design §2.4 makes `accept_on_first_login` default true with `false` documented as "stays INVITED".

**Business/regulatory risk:** an operator who enables invites expecting "INVITED = not yet granted access" ships an accounts-granted-by-default posture; the config knob's documented semantics are unenforced for an unbounded interim. This is a control-documentation-vs-reality gap of the kind compliance reviews exist to catch — the design itself flags it, but does not elevate it to a release blocker.

**Remediation (required):** make direction 1's gate a release dependency of the seed writers (same change), or land the interim fail-closed rule now: when `invite.enabled && !accept_on_first_login`, deny INVITED at login in `authenticateUser`/`finalizeCallbackSession` (remove when direction 1 lands). Add the ordering acceptance test (architect F2) to the test plan.

**Evidence needed for closure:** ssotest — `accept_on_first_login: false` + INVITED + correct password → 403/401 (interim) and, after direction 1, the denial survives with accept-before-gate ordering intact (first login with `true` → ACTIVE + ActorSystem audit).

### C-6 — Medium: `purge_requires_erasure: true` with a nil eraser is warn-and-inert — a fail-closed compliance assertion that silently fails open

**Verified evidence:** design §1.4 chooses a boot warning + inert knob; the tree's precedent for the same config class is a **boot error** (`cmd/sso-server/build_stores.go:330-338` — auto_deprovision without user_lifecycle "must see the loud boot error ..., not a silent no-op").

**Business/regulatory risk:** an operator asserts "purges are refused unless erasure completes" in compliance documentation; the control is a log line. In regulated deployments this is exactly the class of finding auditors write up.

**Remediation (recommended):** fail the build (or refuse to serve PURGED transitions) when `purge_requires_erasure: true` and no eraser leg is constructible, at least in the stock server; document the deviation in `docs/config-reference.md`.

**Evidence needed for closure:** `userlifecycle_wiring_test.go` extension asserting the chosen boot behavior (per design §6.2 — note the test currently asserts `len(b.opts)` at **three** counts, 0/1/2 at lines 65/83/121, not two; the eraser option makes the third case 3).

### C-7 — Low/Medium: Art. 15/20 subject-access completeness for lifecycle history is undetermined

**Verified evidence:** `compliance.Exporter` exports Users + Sessions + consent/MFA extras (`compliance_routes.go:71-92`); no lifecycle data anywhere in the export. Direction 2 adds subject-referencing history (seed reason, accept events, admin actor).

**Business/regulatory risk:** whether internal governance notes are "personal data of the subject" for Art. 15 purposes is a legal determination (EU practice treats even internal annotations about the subject as in-scope data). The risk is not non-compliance per se but an *undocumented decision*.

**Remediation:** record the determination in the datamap entry (either "lifecycle history is exported on request" or "governance metadata excluded, with rationale"); optionally extend the exporter.

### C-8 — Low: Unbounded orphan PURGED records after crash windows (storage limitation)

**Verified evidence:** delete-rule repairs only fire on re-provisioning of the same id; SCIM always mints new ids (`protocols/scim/handler_users.go:23`), and the admin seed form 404s on a missing user (`interfaces/admin/lifecycle.go:28-31`) — so crash-window orphans accumulate in `ListByState(StatePurged)` with no production consumer. See security F2/database F-DB-2.

**Remediation:** admin-gated reaper deleting PURGED records whose `core.User` no longer exists (audited), or a documented non-goal with a hygiene note.

### C-9 — Low: Erasure-response wire drift risks (evidence value)

**Verified evidence:** `eraseResponse` carries `dry_run` and omits `NotificationsDeleted` (`compliance_routes.go:113-125`); the design's sample PURGED JSON omits `dry_run`; seed responses omit `previous_state`. QA F7 / protocol F4.

**Remediation:** byte-parity test of `ReportView` vs. `eraseResponse`; document `previous_state` omission in `openapi.yaml`. Evidence value: the admin response is the operator's DSR artifact.

### C-10 through C-12 — Info

- **C-10 (Info):** Backup/restore vs. erasure — restored backups re-materialize erased data and reset lifecycle records to zero (all ACTIVE). Process gap (Art. 17(3) cost analysis); document in config-reference and ops runbook.
- **C-11 (Info):** Dormant-retention sweep interaction — never-authenticated INVITED accounts are left alone (verified: `retention.go:45-46` — "no session history at all is left alone"), but an INVITED account that authenticated once under `accept_on_first_login: false` becomes a dormant-flag/auto-erase candidate, erased via the same Eraser (inheriting the C-1 gap). Document in config-reference.
- **C-12 (Info):** Cross-tenant userID-uniqueness assumption — purge is a new destructive trigger for an inherited Eraser property; add to the design's residual list with a tenant-scoping note.

---

## 4. Audit-readiness summary

### Current state

The design is **architecturally sound and wire-safe** (per the sibling reviews, all of whose verification claims I independently reproduced), and its failure-mode analysis is honest. From a compliance standpoint it is **not audit-ready as specified**: two High findings (C-1 erasure completeness, C-2 state durability) are required fixes; C-3 through C-6 are required documentation/ordering decisions. The repo's existing compliance machinery — Art. 30 data map, erasure engine, audit buckets, SOC2 evidence-pack tooling with its explicit disclaimers — is a genuine asset, but direction 2 currently extends the *processing* without extending the *record of processing*.

### Required documents (all in-repo, same change as the feature)

| Document | Content | Owner |
|---|---|---|
| `protocols/compliance/datamap.go` + test | New `lifecycle_records` and `password_credentials` categories; PURGED as an erasure trigger in `user_profile` retention; export-completeness determination (C-7) | Eng. + DPO |
| `docs/config-reference.md` | New knobs; state-machine rewrite; INVITED interim semantics (C-5); `audit.enabled:false` evidence-loss note (C-4); `purge_requires_erasure` boot-error decision (C-6); backup/restore semantics (C-2/C-10); dormant-sweep interaction (C-11); knob-interaction note | Eng. + docs |
| `docs/error-codes.md` | PURGED = terminal event + record removed; fail-closed refusal reuses `internal_error`; purge-with-erasure-meta is a DSR erasure for accounting (C-4); seed `from_state=""` encoding | Eng. |
| `docs/openapi.yaml` | Seed form, `erasure` block, `previous_state` omission, post-purge GET 404 | Eng. |
| `docs/feature-matrix.md` | Row 157: PURGED erasure wiring, INVITED provisioning, federated re-provisioning = fresh provisioning (C-1) | Eng. |
| Process (outside repo, flagged as gaps) | DSR handling runbook (identity verification, chain of custody for erasure reports), IR runbook for purge, backup-restore erasure procedure, jurisdiction/data-classification determination | Ops + DPO |

### Next decisions (owner: product/engineering + DPO)

1. **Password-credential leg scope** — add to the lifecycle eraser only, or retrofit the existing GDPR/self-service erase endpoints in the same change (C-1)? Recommended: all three, one change.
2. **Direction-1 landing order** — the INVITED gate must land with (or before) the seed writers; interim denial for `accept_on_first_login: false` if not (C-5). The M0 budget shuffle is order-independent and should land first (architect F1/F2 amendments).
3. **Durable lifecycle store** — before direction 1's gate ships, per C-2; confirm the product position that memory-only remains acceptable for the interim.
4. **`purge_requires_erasure` default** — boot error vs. warning (C-6); whether regulated deployments should default the knob to true.
5. **DSR accounting decision** — confirm the single-event model with meta-key discoverability (C-4) as the documented accounting rule.
6. **Certification posture** — remain unknown; no tree evidence supports any certification claim, and the `auditreport` disclaimer must be preserved verbatim in any future SOC2-facing documentation.

### Validation gate for the change (per AGENTS.md)

`go build ./... && go vet ./...` after every edit; `go test -run 'TestMaintainability_|TestArchitecture_' .`; before handoff `go test ./... -race`, `go test ./test/ -run TestE2E -v`, `make ci` — plus the compliance-specific evidence: ssotest resurrection test (C-1), restart-persistence test (C-2), datamap unit test (C-3), erasure-meta audit assertion (C-4), interim-denial ordering test (C-5), wiring boot-error test (C-6), `ReportView` byte-parity test (C-9).

---

*This review is advisory analysis based on repository evidence at this revision. It is not legal advice, and no repository evidence constitutes compliance or certification. Jurisdiction, data classification, contractual obligations, and certification status remain unknown and are the operator's/DPO's determinations.*
