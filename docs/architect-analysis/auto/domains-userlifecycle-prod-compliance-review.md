# Compliance Review — `domains/userlifecycle` production-hardening (prod design)

**Reviewer role:** compliance_officer (`ai-dev/prompts/compliance_officer.md` + `README.md` baseline rules).
**Inputs reviewed:** `docs/auto/domains-userlifecycle-prod-design.md` (the design under review), its spec (`...-prod-spec.md`), the sibling reviews for this revision (distributed-engineer `...-prod-ds-review.md`, database-architect `...-database-review.md`, QA lead), the prior compliance review for direction 2 (`...-direction2-compliance-review.md`), and the working tree at HEAD `0235cc47`.
**Checks that actually ran (this revision, by me):** `go build ./... && go vet ./...` — clean; `go test -run 'TestMaintainability_|TestArchitecture_' .` — ok; `go test ./protocols/compliance/ ./domains/userlifecycle/...` — ok; source inspection (`read`/`grep`) of every surface cited below. `make ci`, `-race`, and the DSN-gated PG arms were run by sibling reviewers at the same revision (reported in their deliverables), not by me.
**Evidence labels:** Verified / Partial / Missing / Proposed / Unknown per the README standard. Framework applicability is judged strictly from what the tree itself claims; jurisdiction, data classification, and certification status are marked unknown where the input does not establish them.

**Headline:** the design's three spec corrections are Verified sound (companion interfaces; rejection of `ListByState` enumeration; separate last-active table), and its engineering discipline is strong. From a compliance standpoint the design is **not audit-ready as specified**: it makes three new durable personal-data stores without updating the GDPR Art. 30 data map, it ships a durable terminal `PURGED` state whose "data erased" semantic is not implemented anywhere, and its automated sweep mislabels active users on at least one stock login path (sibling finding F6) while its own failure-mode text overclaims "never wrong-deprovisioning" (F-DS-2). None of these are new obligations; the design extends the *processing* without extending the *record of processing* and without correcting the *claims* the record makes.

---

## 1. Applicable-scope statement and excluded/unknown frameworks

### Frameworks shown to apply (repository-established)

| Framework | How the tree establishes applicability | Status of the prod design against it |
|---|---|---|
| GDPR (Art. 5(1)(d)/(e), 5(2), 17, 22, 30, 32) | `protocols/compliance/erasure.go` package doc ("regulations (GDPR Art. 17, CCPA, PIPL) require"); `protocols/compliance/datamap.go` (Art. 30 record); `docs/openapi.yaml` Art. 15/17/20/30 endpoints | **In scope — the central object of this review.** The design creates three durable personal-data stores (lifecycle, history, last-active) and an automated dormancy sweep; accuracy, storage limitation, erasure completeness, accountability, automated-decision transparency, and Art. 30 record-keeping all apply |
| CCPA (Cal. Civ. Code §1798.105 right to delete) | Same `erasure.go` package doc | In scope — same erasure-completeness analysis as Art. 17 |
| PIPL (Art. 47 deletion right) | Same `erasure.go` package doc | In scope — same analysis |
| SOC 2 (TSC CC6.1/CC6.3/CC8.1) | `platform/audit/auditreport/control_areas.go` (TSC evidence buckets, `EventAdminUserLifecycleChanged` in the CC6.3 admin-actions bucket at `:126`), `cmd/sso-ctl/soc2report` | In scope as **mechanical evidence-pack machinery** — with the package's own mandatory disclaimer: "ILLUSTRATIVE MECHANICAL cross-reference, NOT a vetted SOC2 control mapping" (`auditreport` comment). No SOC 2 report, audit, or certification is claimed or implied |
| PCI DSS 7.2, HIPAA §164.312(a) | Cited only as evidence-chain mappings for an unrelated break-glass surface | **Excluded** — the citations do not establish a PCI/HIPAA compliance program and the prod design touches neither surface |

### Excluded and unknown

- **Excluded — ISO 27001, FedRAMP, DPDP, LGPD, NIST 800-53, etc.:** no canonical contract, config, test, or documentation in the tree establishes applicability. Analysis-prose mentions are not contracts (README rule 4).
- **Unknown — jurisdiction and applicable law:** the tree does not establish where data subjects reside or which regulator applies. GDPR/CCPA/PIPL citations are feature-justification. Marked unknown; the operator/DPO owns this.
- **Unknown — data classification:** no classification scheme exists in the tree. This review assumes lifecycle records, history, and last-active timestamps are personal-data-bearing (they carry user_id, actor, timestamps, and free-text reason) — an assumption, not a tree-established fact.
- **Unknown — certification:** no SOC 2/ISO/GDPR certification, attestation, or audit result exists in the tree; implemented controls are not evidence of certification (my instructions). The `auditreport` disclaimer must be preserved verbatim.
- **Excluded — contractual obligations:** no customer DPAs, processor agreements, or contractual control matrices exist in the tree. The design's companion-interface work touches SDK surface (`userlifecycle.Store` remains implementable by embedders), but embedder-side data-processing obligations are out of scope and unverifiable here.
- **Out of scope — browser frontends, OpenResty/Envoy deployment assets:** no compliance-relevant input provided.

---

## 2. Control matrix

Legend: **V** = verified in tree; **P** = proposed (design-only); **Gap** = obligation with no adequate control (code or process). "Process evidence" distinguishes human procedures/external attestations from technical controls; where the tree has none, that is stated as a gap, not assumed.

| # | Obligation | Control (technical) | Status / repository evidence | Process evidence | Gap | Owner | Validation method |
|---|---|---|---|---|---|---|---|
| 1 | GDPR Art. 30 — records of processing activities | `GET /api/v1/admin/compliance/data-map` (`admin:read`), 6 categories, retention folded from config | **V** `protocols/compliance/datamap.go` (`BuildDataMap`), `datamap_test.go:15` pins exactly the six core categories | — | **No `lifecycle_records` or `user_activity_signal` category.** The design's contract-update notes name only `docs/config-reference.md`; `datamap.go` is not in its update list. Three new durable personal-data tables ship un-inventoried. See **C-P3** | Eng. + DPO | Extend `BuildDataMap` + `datamap_test.go` in the same change as the wiring |
| 2 | GDPR Art. 17 / CCPA §1798.105 / PIPL — complete erasure | `compliance.Eraser` legs (Users, Sessions, Refresh, Consent, MFA, reset/email tokens, notifications, preferences) | **V** `protocols/compliance/erasure.go:29-53`; **zero lifecycle references** in `erasure.go`, `export.go`, or `retention.go` (grep-verified) | — | **Erasure never touches lifecycle/history/last-active rows.** The design ships a durable store for a state machine whose terminal state claims erasure. See **C-P1** | Security eng. + compliance/DPO | Erasure-completeness wiring test (see C-P1 closure evidence) |
| 3 | GDPR Art. 5(1)(e) — storage limitation / retention | Memory-only today (self-healing on restart); design: durable tables, unbounded history, orphan rows survive user deletion (no cascade), cleanup documented as non-goal | **V** `domains/userlifecycle/userlifecycle.go` (Store); design §1/§3 "History growth is unbounded ... future retention knob"; sibling F-DS-3/F-DB-4 | — | **Retention decision absent.** Deleted subjects' state/history/last-active retained indefinitely and durably; history grows without bound; no reaper. `protocols/compliance/retention.go` covers sessions only. See **C-P4** | DB eng. + DPO | Retention decision in config-reference; reaper or documented policy |
| 4 | GDPR Art. 5(1)(d) — accuracy of processing | Fail-safe dormancy (`IsDormant`: zero signal never dormant), monotone `TouchAt`, oracle-safe errors | **V** `domains/userlifecycle/dormancy.go:20-27`, `memory.go` `TouchAt`; **Partial** — see gaps | — | **Wrong-deprovisioning paths:** standalone WebAuthn ceremony bypasses both Touch anchors (sibling F6/F-DB-1); sweep starvation by no-op prefix (QA F2); clock-skew analysis covers the lease but not the dormancy cutoff, so the design's "never wrong-deprovisioning" is an overclaim (F-DS-2). See **C-P2** | Eng. | Ceremony-login E2E (LastActive readback); starvation test; claim text corrected |
| 5 | GDPR Art. 5(2) — accountability / audit trail | Every applied transition (admin- or sweep-driven) emits `admin_user_lifecycle_changed` with `target_user`/`from_state`/`to_state`/`reason` meta + actor; CC6.3 bucket | **V** `domains/userlifecycle/sweep.go` (`RecordTransition`, `ActorSystem`), `interfaces/admin/lifecycle.go`, `event_types_admin.go:30`, `control_areas.go:126` | — | Lost-lease tick is silent (QA F5 — design returns `(0,nil)` with no log; `RunUserAutoDeprovision` logs only errors, `options_admin.go:331-333`); per-user skip-and-log errors leave no audit event; `WithAuditRecorder` unwired ⇒ nil recorder ⇒ no evidence at all (inherited, direction-2 C-4). See **C-P6** | Eng. | Lost-lease log assertion; audit-enabled wiring test |
| 6 | GDPR Art. 32 — access control / integrity | Lifecycle routes under `/api/v1/admin/`; default method-scope rule (GET=`admin:read`, else `admin:write`) | **V** `interfaces/admin/middleware.go:71-74`; routes mount only when store AND `UserProvider` are wired (`docs/error-codes.md:677`) | — | New tables inherit the backing store's access posture (shared PG pool / sqlite DSN); no per-table ACL layer — same as all peers, but the sqlite peer used as a production backend would hold lifecycle PII in a file (see C-P8) | Eng. | Existing admin-scope tests; DSN-gated PG suite |
| 7 | GDPR Art. 32 — encryption / key management | No new key material; at-rest posture delegated to backing stores (PG/Cockroach deployment-owned; sqlite file) | **V** design §1 (peers: `invitation.go`, `defaultimpl/sqlite`) | **Gap:** no stated at-rest posture for the new tables anywhere in the design (consistent with peers, but the design is where a future auditor will look) | — | Eng. | Config-reference note |
| 8 | GDPR Art. 22 — automated decision-making | Sweep is threshold-based, config-gated, audited; `SweepOnce` fail-safe | **V** `sweep.go`, `options_admin.go:319-337` | — | **No subject notice, no review/override mechanism** on automated INACTIVE/ARCHIVED; today label-only (lifecycle "NEVER gates authentication", `config-reference.md:695`), but a future auth-gating direction would make these decisions significant. Position must be documented now. See **C-P5** | Product + compliance/DPO | Documented decision; notice/review requirement attached to any auth-gating change |
| 9 | SOC 2 CC6.1 — access & revocation; control effectiveness | Auto-deprovision advances dormant accounts to INACTIVE/ARCHIVED with `system` actor, audited | **V** `sweep.go`; `config-reference.md:695` ("GOVERNANCE metadata only") | **Gap:** the sweep does **not** revoke access (no session destruction, no token revocation, no user deletion; ARCHIVED's own doc says "no longer usable" — unenforced). An operator adopting "auto-deprovision" as an offboarding control gets a label, not a control. Must be stated in the feature docs. See **C-P2** | Product + eng. | Control-description note in feature-matrix/config-reference |
| 10 | Vendor / third-party management | No new vendors; PG/Cockroach/SQLite are existing backends; nested modules own their builds | **V** AGENTS.md module rules; design §1 | — | SQLite-as-production-backend decision (if ever) would put personal data in a file on the server host — vendor/encryption posture inherited from the deployment, not the repo | Eng. | N/A at design stage |
| 11 | Incident response — store outage, crash recovery | Lease TTL crash recovery; activity-write fail-open (login never blocked); sweep errors log-and-continue | **V** design §2/§3 failure modes; fail-open precedent in module | **Gap:** no IR runbook for lifecycle data in the tree (who restores, how PURGED/ARCHIVED labels are treated after restore — see C-P7); lost-lease silent (row 5) | Ops | Runbook; lost-lease log |
| 12 | Backup/restore vs. erasure/retention | `backup.keep` config exists; durable lifecycle tables join whatever backup/restore the deployment runs | **V** `docs/config-reference.md` backup section (prior review C-10) | **Gap:** no statement that restored backups re-materialize ARCHIVED/INACTIVE/PURGED labels and last-active data, and that PURGED labels in a backup do not imply erasure. See **C-P7** | Ops + DPO | Restore-drill note; config-reference note |
| 13 | Multi-tenant isolation | Lifecycle/last-active stores keyed by userID; fleet-wide admin | **V** design §1 schema | — | Safe only if user IDs are globally unique across tenants — inherited assumption; the durable store makes cross-tenant miskeying persistent. Add to the design's residual list (direction-2 C-12 carried forward) | Eng. | Documented residual |
| 14 | Data minimization | Last-active = `(user_id, last_active)`; `sweep_lease` = process identity (hostname+pid+nonce), not personal data; sweep reason is a fixed string | **V** design §3/§2; `sweep.go` `apply` | — | History `reason`/`actor` free text is a personal-data surface (admin-entered; pre-existing) — covered by datamap gap (row 1) | — | — |

---

## 3. Findings

Sorted by severity. "Evidence needed for closure" states what a future audit would need to see. Sibling findings are cross-referenced by their IDs (F-DS-*, F-DB-*, QA F*).

### C-P1 — High: The design makes a terminal "PURGED = data erased" claim durable while erasure has no lifecycle leg; Art. 17/CCPA/PIPL deletion claims remain false and now persistent

**Verified evidence:** `StatePurged` is documented "the terminal state: the account's data has been erased" (`domains/userlifecycle/userlifecycle.go:69-71`) and is a legal transition target from ARCHIVED (`transitions.go` table). The admin handler that applies it (`interfaces/admin/lifecycle.go` `HandleAdminTransitionUserLifecycle` → `applyLifecycleTransition`) only Appends to the store and audits — no `Eraser` run, no session/refresh revocation, no user deletion (grep-verified: zero `Eraser`/purge references in the handler and `cmd/sso-server`). The erasure engine itself has no lifecycle leg: `Eraser`'s legs are Users/Sessions/Refresh/Clients/Consent/MFA/PasswordReset/EmailChange/Notifications/Preferences (`protocols/compliance/erasure.go:29-53`), and `erasure.go`/`export.go`/`retention.go` contain zero lifecycle references. The direction-2 design (which proposed wiring erasure into PURGED, with the same C-1 password-credential gap) is **not landed** at this revision; the prod design does not reference or depend on it. Decision 1 of this design makes the `user_lifecycle`/`user_lifecycle_history` records durable, and decision 3 adds `user_lifecycle_last_active` — so the false "erased" claim is now permanently stored, backup-visible, and served by the admin API.

**Business/regulatory risk:** a DSR "erasure completed" claim is factually wrong for the lifecycle record, the last-active signal, and (per direction-2 C-1, still open) the password verifier. An auditor or data subject reading the state-machine documentation (`docs/error-codes.md:659-680`, `docs/feature-matrix.md:157`) sees "PURGED: terminal — data erased"; the durable store turns a transient per-process label into a persistent record of a deletion that never happened. This is an accountability artifact that documents the opposite of reality (Art. 5(2), Art. 17(1)(b)/(d)).

**Remediation (required before the durable store ships):** (a) scope PURGED explicitly: either land the direction-2 erasure wiring in the same change (making PURGED run the real `Eraser`, fail-closed when a required leg is missing — direction-2 C-6 pattern), or (b) ship the durable store with PURGED as a documented label-only state and correct the state docs ("PURGED is a governance label; erasure wiring is a separate change"), and make the admin response/audit event for PURGED carry a marker that no erasure ran. Add a wiring assertion: ARCHIVED→PURGED transition requires the eraser legs to be present, else refuse (500) — mirroring the tree's own loud-boot precedent (`build_stores.go:330-338`).

**Evidence needed for closure:** wiring test (PURGED without eraser legs → refused or labeled; with legs → `Eraser` report attached to the audit event); corrected `docs/error-codes.md`/`feature-matrix.md` wording; datamap entry reflecting the actual deletion semantics.

### C-P2 — High: "Auto-deprovision" automates labels, not access — and the sweep can mislabel active users, while the design's own failure-mode text overclaims safety

**Verified evidence:** (1) *No access effect:* lifecycle is "GOVERNANCE metadata only — it NEVER gates authentication" (`docs/config-reference.md:695`); no lifecycle-based auth gate exists anywhere (`rejectLifecycleBlockedUser`/`AllowsAuthentication` grep: zero hits outside the domain package); the sweep (`SweepOnce` → `apply`) only Appends + audits. Yet `StateArchived` is documented "no longer usable" (`userlifecycle.go`) — an unenforced claim. (2) *Wrong-deprovisioning paths:* the standalone WebAuthn ceremony (`cmd/sso-server/serverwebauthn/webauthn_handlers.go:120-158`, stock-wired at `build_http.go:263-295`) authenticates via `Helper.FinishLogin` and mints tokens without calling either Touch anchor (`authenticateUser` `server_login_auth.go:98`, `finalizeCallbackSession` `server_oauth.go:223`) — sibling findings F6 (QA, High) and F-DB-1 (database, High), both independently verified; the design's "ceremonies are covered transitively" claim is Partial at best. (3) *Overclaim:* the design's clock-skew analysis covers only the lease, but the dormancy cutoff `now(sweeper) − last_active(writer)` is the correctness-sensitive comparison; "never wrong-deprovisioning" is unproven (F-DS-2). (4) *Starvation:* the keyset cursor's no-op prefix (SUSPENDED/ARCHIVED/INVITED/PURGED users with oldest timestamps, and INACTIVE with `ArchiveAfter=0` — the default posture) can permanently starve actionable ACTIVE users behind it (QA F2, High) — the sweep silently stops working.

**Business/regulatory risk:** GDPR Art. 5(1)(d) accuracy: automated processing mislabels actively-used accounts as INACTIVE/ARCHIVED on a stock login path. Today the damage is label-level; the moment any future direction gates authentication on these states (direction 1), mislabeled users lose access with no notice and no self-healing (ARCHIVED is admin-reversible only — F-DB-2; login performs no reactivation). Separately, an operator who adopts "auto-deprovisioning" as an access-revocation/offboarding control — the name says so — receives no access revocation at all: a documented control that is not a control (SOC 2 CC6.1 effectiveness, Art. 5(1)(f) integrity).

**Remediation (required):** (1) fix the ceremony gap (third Touch anchor at the WebAuthn mint path, or an explicit scope-out with rationale — QA F6 acceptance); (2) fix the cursor starvation (QA F2 acceptance); (3) correct the design's "never wrong-deprovisioning" claim to "never wrong-deprovisions on positive evidence under a single replica's clock" and scope the clock-skew analysis to the dormancy cutoff; (4) document in `docs/config-reference.md` + `docs/feature-matrix.md` that the sweep changes governance labels only and does not revoke access, and that ARCHIVED "no longer usable" is enforced only by future auth-gating; (5) decide and document INACTIVE→ACTIVE reactivation on login (a legal edge today, `transitions.go`) as the self-healing mechanism for mislabeled users.

**Evidence needed for closure:** ceremony-login E2E asserting `LastActive(userID) == login time`; starvation test per QA F2; corrected claim text in the design; control-description note in config-reference.

### C-P3 — Medium: The GDPR Art. 30 data map is not updated; three new durable personal-data tables ship un-inventoried

**Verified evidence:** `BuildDataMap` enumerates exactly six categories — user_profile, sessions, consent_grants, mfa_enrollments, refresh_tokens, audit_log (`protocols/compliance/datamap.go:58-70`); `datamap_test.go:15` pins exactly those six. The design's contract-update obligations (decisions 1 and 3 "what could break the design") name `docs/config-reference.md` only; `datamap.go` is absent from its update list. Direction-2 C-3 flagged the same omission for the lifecycle category; it remains open and this design widens it with a fourth table (`sweep_lease` holds no personal data, but `user_lifecycle_last_active` does).

**Business/regulatory risk:** Art. 30 is the "records of processing activities" accountability artifact. A DPA or regulator reviewing the data map finds durable processing (lifecycle state machine, transition history with admin actor and free-text reason, per-login activity timestamps) with no inventory entry — a documentation failure that makes the technical controls unverifiable. The `reason` field is unbounded free text, a personal-data surface.

**Remediation (recommended):** add two categories in the same change as the wiring: `lifecycle_records` (store: `infrastructure/postgres` `user_lifecycle` + `user_lifecycle_history`, fields: user_id, state, from/to, reason, actor, at; legal basis: governance/legitimate interest; retention: must state the C-P4 decision) and `user_activity_signal` (`user_lifecycle_last_active`, fields: user_id, last_active; retention decision required). Extend `TestBuildDataMap_CoreCategoriesPresent` accordingly.

**Evidence needed for closure:** updated `BuildDataMap` + test; data-map JSON reviewed by the DPO.

### C-P4 — Medium: Retention gaps become durable — unbounded history, and deleted subjects' rows persist forever with no cascade and no cleanup

**Verified evidence:** the design concedes "History growth is unbounded (every transition appends forever ...) — flagged as a future retention knob, not part of this change"; deletion-time cleanup of `user_lifecycle*` rows is a documented non-goal (design §3). Sibling F-DS-3/F-DB-4 (both verified): no cascade from `UserProvider.Delete` into the lifecycle/last-active tables; the SQL peers make the poison **permanent** (the memory store used to self-heal on restart); ghost rows are re-scanned every tick (O(k) silently becomes O(k+orphans)); and the ghost guard passes for **re-created** user ids — a fresh SCIM account can be ARCHIVEd within one tick. `protocols/compliance/retention.go` covers sessions only.

**Business/regulatory risk:** GDPR Art. 5(1)(e) storage limitation. Deleted data subjects' state/history/last-active are retained indefinitely in a durable store; there is no retention policy, no reaper, and no owner. The re-created-id mislabeling is an accuracy defect (feeds C-P2) independent of retention.

**Remediation (recommended):** (1) adopt the O(1) epoch guard from F-DS-3 (skip when `user.UpdatedAt > record.UpdatedAt`) — correctness, not just hygiene; (2) either add deletion-time cleanup (cascade or a bus reaction on user deletion) or document an explicit retention decision with a reaper for orphaned rows; (3) record the decision in the datamap entries (C-P3) and config-reference.

**Evidence needed for closure:** re-created-id sweep test; cleanup or documented policy; datamap retention text.

### C-P5 — Medium: Automated dormancy decisions have no subject transparency, notice, or review path — the position must be documented now because direction 1 would make them access-affecting

**Verified evidence:** the sweep runs automatically on a config threshold (`RunUserAutoDeprovision` ticker, `interfaces/sso/options_admin.go:319-337`; `SweepOnce`); there is no subject-facing notification on INACTIVE/ARCHIVED, no operator review gate, and no override mechanism in the design. Today the states never gate authentication (`config-reference.md:695`), so the processing has no legal/significant effect on the subject and GDPR Art. 22 is not triggered. The design's own "refresh-only users" boundary is a deliberate, documented exclusion.

**Business/regulatory risk:** the Art. 22 analysis is currently favorable but **undocumented and unstable**: any future direction that gates authentication on INACTIVE/ARCHIVED (the direction-1 trajectory) converts threshold-based automatic deprovisioning into decisions with significant effects, requiring safeguards (notice, human review, contestability). An auditor will ask where that decision is recorded; today it is nowhere.

**Remediation (recommended):** record the position in the feature docs: "automated dormancy transitions are governance labels with no access effect (no Art. 22 trigger); any auth-gating direction must ship with subject notice, an operator override, and a documented Art. 22 assessment." Keep the sweep threshold configurable and audited (already true).

**Evidence needed for closure:** documented decision in `docs/feature-matrix.md`/config-reference; the notice/override requirement attached to any future auth-gating change.

### C-P6 — Low/Medium: Audit-completeness edges on the automated path — silent lost lease, log-only skipped transitions, and `audit.enabled: false` drops all evidence

**Verified evidence:** `RunUserAutoDeprovision` logs only on error (`options_admin.go:331-333`); the design's `SweepOnce` "returns `(0, nil)` on a lost lease" with no log (QA F5); per-user errors in `apply` are log-and-skip with no audit event (`sweep.go`); `RecordTransition` is a no-op when the recorder is nil, and the recorder is an option (`WithAuditRecorder`, `options_security.go:408-411`) — an unwired/unenabled audit means applied transitions leave no retained evidence (inherited from direction-2 C-4, still open).

**Business/regulatory risk:** accountability (Art. 5(2)) and SOC 2 CC8.1: an operator cannot reconstruct why the sweep under-applied (skipped tick, conflict, outage), and in audit-disabled builds there is no evidence that the automated deprovisioning ran at all.

**Remediation (recommended):** log lost leases (QA F5 acceptance); consider a per-run summary audit event (applied/skipped counts) on the durable path; add the `audit.enabled: false` evidence-loss consequence to the config-reference note for `auto_deprovision`.

**Evidence needed for closure:** lost-lease log assertion (memory sink); documented audit-disabled consequence.

### C-P7 — Low: Backup/restore semantics for the new durable tables are unstated

**Verified evidence:** the durable tables join the shared PG pool (and the sqlite peer), so they are captured by whatever backup/restore the deployment runs (`backup.keep` config exists — direction-2 C-10). A restore re-materializes ARCHIVED/INACTIVE/PURGED labels and last-active timestamps; because nothing cascades on user deletion (C-P4), restored backups can also re-materialize records of deleted subjects.

**Business/regulatory risk:** Art. 17(3) cost-constraint analysis and storage-limitation expectations: erasure-vs-backup semantics are a documented process decision; without it, a restored "PURGED" label (which already does not mean erasure — C-P1) is even more misleading.

**Remediation (recommended):** a config-reference/ops note: restored backups reset no lifecycle state and PURGED labels in a backup do not imply erasure; the sweep will re-evaluate restored accounts against dormancy thresholds (which, per F2, may act on restored stale signals — feed into C-P2's starvation/accuracy analysis).

**Evidence needed for closure:** restore-drill evidence or a documented procedure note.

### C-P8 — Info: Encryption/key-management posture is inherited and undeclared for the new tables

**Verified evidence:** the design adds tables to the existing PG pool and a sqlite peer (peer-store convention); no new key material; `sweep_lease.holder` is process identity (hostname+pid+nonce), not personal data. At-rest encryption for PG (TDE/disk) and SQLite (file) is deployment-owned, as for every existing peer. If the sqlite peer were ever selected as a production backend, lifecycle PII would sit in a file on the server host — the design correctly identifies sqlite as the in-gate conformance target; the production durable backend is PG (per the builder seam), which should be stated in config-reference.

### C-P9 — Info: Multi-tenant isolation inherits the userID-uniqueness assumption

**Verified evidence:** all new tables are keyed by userID; fleet-wide admin. Safe only if user IDs are globally unique across tenants — an inherited assumption the durable store makes persistent. Carry direction-2 C-12's residual note into this design's residual list.

---

## 4. Audit-readiness summary

### Current state

The design's engineering corrections are right and well-evidenced, and the baseline gates pass at this revision. From a compliance standpoint it is **not audit-ready as specified**: C-P1 (durable PURGED-without-erasure) and C-P2 (mislabeling + overclaimed safety + label-only "deprovisioning") are required fixes; C-P3 and C-P4 are required documentation/retention decisions. The repo's compliance machinery (Art. 30 data map, eraser, audit buckets with their disclaimers) is real, but this design extends the *processing* — three durable personal-data stores and an automated decision loop — without extending the *record of processing* or reconciling the *claims* the state machine makes.

### Required documents (all in-repo, same change as the feature)

| Document | Content | Owner |
|---|---|---|
| `protocols/compliance/datamap.go` + test | `lifecycle_records` and `user_activity_signal` categories with the C-P4 retention decision; PURGED deletion semantics stated truthfully (C-P1); export-completeness determination carried forward (direction-2 C-7) | Eng. + DPO |
| `docs/config-reference.md` | Backend naming + caveat removal (design's own note); sweep = governance-labeling-only statement (C-P2); retention/cleanup decision (C-P4); audit-disabled evidence-loss note (C-P6); backup/restore semantics (C-P7); sqlite-as-test-peer vs PG-as-production posture (C-P8) | Eng. + docs |
| `docs/error-codes.md` + `docs/feature-matrix.md` | PURGED wording corrected or scoped ("label; erasure wiring separate" or "runs the eraser") (C-P1); ARCHIVED "no longer usable" claim qualified (C-P2); Art. 22 position statement (C-P5) | Eng. |
| Design amendments | F1 lease schema fix, F2 starvation fix, F6 ceremony anchor — the sibling reviewers' required fixes are prerequisites for C-P2's accuracy finding to close | Eng. |
| Process (outside repo, flagged as gaps) | IR runbook for lifecycle data and restore semantics (C-P7); jurisdiction/data-classification determination; DSR handling runbook (carried forward from direction-2) | Ops + DPO |

### Next decisions (owner: product/engineering + DPO)

1. **PURGED semantics on the durable store (C-P1)** — ship label-only with corrected docs, or land direction-2's erasure wiring in the same change? Recommended: refuse the transition without eraser legs (loud-boot precedent), whatever the choice.
2. **Sweep safety (C-P2)** — land the F6 ceremony anchor and F2 starvation fix with the design (they are correctness fixes; the compliance finding is that the design must not ship its "never wrong-deprovisioning" claim without them).
3. **Retention decision (C-P4)** — reaper vs. documented policy; the datamap entries cannot be written without it.
4. **Art. 22 position (C-P5)** — record the label-only position now and attach notice/override requirements to any auth-gating direction.
5. **Certification posture** — remains unknown; no tree evidence supports any certification claim, and the `auditreport` disclaimer must be preserved verbatim in any SOC2-facing material.

### Validation gate for the change (per AGENTS.md)

`go build ./... && go vet ./...` after every edit; `go test -run 'TestMaintainability_|TestArchitecture_' .`; before handoff `go test ./... -race`, `go test ./test/ -run TestE2E -v`, `make ci` — plus the compliance-specific evidence: PURGED wiring test (C-P1), ceremony-login `LastActive` E2E + starvation test (C-P2), datamap unit test (C-P3), re-created-id/retention test (C-P4), lost-lease log assertion (C-P6).

---

*This review is advisory analysis based on repository evidence at this revision (HEAD `0235cc47`). It is not legal advice, and no repository evidence constitutes compliance or certification. Jurisdiction, data classification, contractual obligations, and certification status remain unknown and are the operator's/DPO's determinations. Sibling-review findings are cited by their IDs; their verification is reported in their own deliverables.*
