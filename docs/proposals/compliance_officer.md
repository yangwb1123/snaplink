Compliance review complete: `docs/auto/interfaces-admin-direction1-compliance-review.md` (no code modified; every claim re-verified against the tree at `5ce7b81d`).

## Applicable scope

**Frameworks shown to apply** — established by the repository itself, not assumed:
- **SOC 2 TSC** (CC6.1/6.2/6.3, CC7.2/7.3, CC8.1) — `protocols/compliance/soc2.go` names the criteria; `break_glass.go:405` "SOC 2 evidence-chain metadata"
- **GDPR** (Art. 5(1)(e), 15/17/20/30, 32) — `protocols/compliance/` cites Articles directly
- **CCPA / PIPL** — `erasure.go:2`

**Excluded:** PCI DSS, HIPAA, FedRAMP, OIDF certification (no certifiable flow touched). **Unknown:** jurisdiction, data classification, ISO 27001 applicability, attestation/certification status, vendor assessments. Tooling is evidence assembly, not certification — stated as such.

## Highest-severity findings

- **F1 (High)** — Tenant isolation as designed leaves cross-tenant paths: no per-resource ownership assertion on `users/:id/password` etc.; tenant-tagged grants can carry platform-wide codes (`admin:keys:write`); stock binary ships no tenant check until wired. GDPR Art. 32 / CC6.1 confidentiality exposure.
- **F2 (High)** — Evidence surfaces won't reflect the new dimensions (my distinctive finding): `SOC2Reporter.AccessReview` reads `ListAssignments`, which D2 defines as ignoring tenant-tagged data → **tenant admins invisible to access-review evidence**; the curated CC8.1 list omits all five `EventAdminChange*` events → approval decisions (including D3's denials) absent from the change-management pack.
- **F3 (Medium)** — HTTP gate denials are unaudited (`SetAuditRecorder` is gRPC-only, verified `middleware.go:137-142`); D1/D2's new denial classes — the cross-tenant probe signal — inherit the silence.
- **F4 (Medium)** — Postgres audit retention silently no-ops → Art. 5(1)(e) storage limitation unenforceable on the durable path.
- **F5 (Medium)** — Break-glass: refusals log-only; mid-tier impersonation widening ships without a review procedure; lifecycle events absent from the SOC 2 pack (only `Revoked`).
- **F6 (Medium)** — Public default pairwise salt silently defeats pseudonymization (Art. 32).

**Verified positives:** SoD proposer/approver preserved; break-glass minting audited with actor/target/reason; fallback design non-widening; export stays write-gated with non-PII audit; hash chain with restart-seam resume.

## Next decisions

Tenant-isolation posture (owner call), evidence-pack extension in the same change as D2/D3, HTTP denial audit, pg retention, pairwise salt guard, AGENTS.md oracle-row amendment authority, and the process evidence no repository can supply (review procedures, retention policy, jurisdiction, DR runbook).
