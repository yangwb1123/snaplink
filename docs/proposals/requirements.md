Spec written to `docs/auto/domains-userlifecycle-direction2-spec.md`, following the existing `direction1-spec.md` convention. All claims were verified against the code before writing.

## Summary

**Direction 2**: PURGED claims erasure without erasing; INVITED has no production entry. Three evidence-backed improvements:

**1. Erase on purge** — `StatePurged` is documented as "the account's data has been erased" (`domains/userlifecycle/userlifecycle.go`), but `applyLifecycleTransition` (`interfaces/admin/lifecycle.go:73-91`) only Appends + audits. `OnUserPurged` (`bus.go`) has zero production callers; `NewLifecycleEventBus` is constructed only in tests/doc examples; the production `compliance.Eraser` (built at `cmd/sso-server/compliance_routes.go:32-47`) is wired only to `/me/account/erase` and the admin GDPR endpoint. Proposed: `lifecyclereactions.EraseOnPurge` reference reaction, composition-root bus wiring, config-gated `purge_requires_erasure` fail-closed mode, erasure summary in the response/audit.

**2. INVITED provisioning entry** — The seed edge `StateNone→StateInvited` exists (`transitions.go:26`) and memory implements it (`memory/memory.go:52-55`), but the only production `Append` callers (`lifecycle.go:80` with `From=rec.State` — never `StateNone`; `sweep.go:144`) can't reach it; `StateInvited` appears nowhere in production outside the package (verified by grep). Proposed: SCIM/admin seed writer via `Append(From: StateNone)` + a first-login (or admin) `INVITED→ACTIVE` acceptance trigger, which direction 1's gate depends on.

**3. PURGED tombstone semantics** — The `Store` interface has no `Delete`; a PURGED record persists forever (`memory_test.go:88-89` proves the current behavior), is terminal (`transitions.go:33`), and orphans when the eraser deletes the user (admin handlers 404, `lifecycle.go:22-25`). The codebase explicitly anticipates same-id re-registration (`erasure.go:32-35`), but re-provisioning would inherit an inescapable PURGED record. Proposed: add idempotent `Store.Delete`, erase→audit→delete terminal sequence, and a crash-window repair in the provisioning path.

Each improvement carries concrete acceptance checks (unit + `ssotest` integration + fail-closed tests), and the "unwired = byte-identical" / "no record = ACTIVE" anchors from the analysis are preserved as non-negotiable invariants.
