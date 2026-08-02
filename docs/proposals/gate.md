# Gatekeeper Cross-Check: Review Findings vs. Design

I re-read the design (`docs/design/domains-region-policystore-spi.md`) and the requirements spec it implements, then mapped every material finding from the five reviews against the design text as written.

## Findings resolved or dismissed with adequate reasons

| Finding | Design response | Ruling |
|---|---|---|
| Arch F3 ≡ Sec F4 ≡ Prin M-5: `memory.Store.Set` signature under-specified | Design's `regiontest.Backend` pins exactly `Set(ctx, tenantID, p) error` / `Delete(ctx, tenantID) error`; risk #5 acknowledges compile-time break; in-repo churn is mechanical | Resolved in substance (conformance interface locks it) |
| Arch F5 ≡ Prin L-4: `wireRegion` ordering | Design states explicitly: store built before resolver-nil early return (boot-loud); option appended unconditionally, nil-safe | Resolved |
| DB L5 ≡ Prin L-2: `NewWithDB` error swallow | Design proposes no `NewWithDB` | Resolved by construction |
| Sec F6 ≡ Prin I-2 (serving-region config validation), Arch F6 ≡ I-1 (`PutTenant` validation) | Pre-existing / spec-scoped out; recorded as residual | Dismissed with reasons (follow-up scope) |
| Arch F7 ≡ Prin I-3 (boot-seed-only, no admin RPC) | Design risk #3 documents it plus the `InvalidateTenantResidencyCache` embedder obligation | Dismissed with reasons (scope decision) |
| Sec F5 ≡ Prin L-5 (`AllowedRegions` cardinality) | Optional, Low | Dismissed (non-blocking) |
| Arch F4 ≡ Prin L-3 (subdir count 1→2 vs 1→3) | Doc inconsistency only; no gate impact | Cosmetic, non-blocking |

## Findings unresolved or dismissed with inadequate reasons

**H-1 — Ladder order (`Tenants == nil` short-circuit) — UNRESOLVED, blocking.** Arch F1 ≡ Prin H-1 ≡ QA F3. The design's ladder step 1 still reads `deps.Tenants == nil → (zero, false, false)` *before* the store tier. With `tenant.enabled=false` (`BuildTenantStore` returns `(nil,nil)`, verified) or a store-only embedder, the store is never consulted — the exact configuration the SPI exists for. The spec mandates store-first ("when a store is wired → `store.GetPolicy`"); the design's own acceptance (1) fails in that config. The design contains this defect as written; no amendment was made.

**H-2 — Partial-policy authority — DISMISSED, but the dismissal is inadequate; blocking.** DB H1 ≡ Sec F1 ≡ Prin H-2 ≡ QA F2. The design keeps the authority predicate `HomeRegion != "" || len(AllowedRegions) > 0 || EnforceWrites`, `ValidatePolicy` stays format-only (skips empty `HomeRegion`), and the failure mode is documented as "authoritative by design; operator-owned". The dismissal argument (replace-not-merge preserves the single-source-of-truth property) addresses pin *replacement*, but three reviewers independently verified the actual effect is worse than documented: `{allowed_regions:[eu-west-1]}` is authoritative yet *inert* (`evaluateResidency` returns nil on empty `HomeRegion` — the entire gate disables, not just a pin drops), silently removing the tenant-row pin the spec's "can only ADD constraint, never silently REMOVE it" rationale promises. The design's own risk #4 admits the under-constraint migration scenario and defers the fix as a follow-up; the principal review made the dual fix (reject partial in `ValidatePolicy` + narrow authority predicate to `HomeRegion != ""`) a precondition. This contradicts the spec's own rationale — the dismissal does not hold.

## Unresolved, design silent (non-blocking alone, but required amendments)

- **DB M2 ≡ Prin M-3**: sqlite backend omits `MaxVersion()`/`CheckSQLiteSchema` and `AppendStorageHealthSource` — no mention in the design; "mirrors connections/sqlite" is precisely the wrong model here.
- **DB M3 ≡ Prin M-4**: no `SetMaxOpenConns(1)`/WAL/busy_timeout guidance for a writer-bearing store — absent.
- **Compliance F1 (High in its rubric)**: no audit events for policy-store `Set`/`Delete`; `config_audit` snapshot coverage of `region.policy_store` unstated — neither resolved nor dismissed.
- **Sec F2 ≡ Prin M-1**: admin tenant edits silently inert for store-backed tenants — no warning mechanism or write-through; needs at least the config-reference note and a product decision.
- **Sec F3 ≡ Prin M-2 ≡ QA F6**: `DeleteTenant` → store-row cleanup — documented as out-of-scope, but no locking test for either the documented or the remediated behavior.
- **QA F1/F2/F5/F7**: the four highest-value test locks (`cacheable=false` recovery, authority predicate, `Tenants==nil` ordering, boot-loud propagation, sqlite house patterns) are absent from the design's test plan.
- **DB L4 ≡ Prin L-1**: no `GetPolicy` latency bound; **QA §5**: `-run TestE2E` does not match the residency E2E tests (`TestResidency_*`).

## Verdict

The design is thorough and the placement/gate resolution is correct, but the two convergent High defects remain in the design **as written**: (1) the `Tenants == nil` short-circuit makes the store tier unreachable in the store-only configuration, and (2) the authority predicate + format-only `ValidatePolicy` accept a partial policy that silently disables the entire residency gate, violating the spec's own add-only rationale. Both are cheap, precisely specified fixes (ladder reorder; reject partial policies + narrow predicate) that the principal review designated as the gate between design and implementation. The design must be amended (or the deviations explicitly signed off with amended spec rationale) before implementation proceeds; the pattern-parity and audit/decision items (M2/M3, compliance F1, admin-inert warning, delete-cleanup, QA test locks) must be folded in or explicitly recorded.

VERDICT: FAIL - H-1 ladder short-circuits before the store tier when Tenants==nil (store unreachable in store-only config); H-2 partial-policy authority predicate makes a HomeRegion-less store policy authoritative-but-inert, silently disabling the gate and violating the spec's add-only guarantee — both unresolved in the design; plus unaddressed amendments: sqlite schema-safety/health/concurrency parity (M2/M3), audit events for policy-store writes (compliance F1), admin-edit inertness warning (Sec F2), delete-cleanup decision + tests (Sec F3/QA F6), and the QA F1/F2/F5 locking tests
