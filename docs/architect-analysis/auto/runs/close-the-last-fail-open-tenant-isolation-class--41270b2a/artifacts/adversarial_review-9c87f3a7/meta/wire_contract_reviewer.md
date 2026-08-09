All changes verified. The diff against HEAD shows my edits layered on the direction's pre-existing uncommitted partial landing (the machine-flow/scope-registry hunks predate this task); my additions are exactly the four absent-claim clauses.

## Result

**Verification (all four checked locations):** none makes a false claim that claim-less user tokens pass for bound tenants — but the `openapi.yaml` (adapter) descriptions at lines 20–29, 175, and 215–221 enumerate only three user-flow causes and are silent on the claim-less case, and `docs/error-codes.md` prose + row are likewise incomplete. `docs/config-reference.md` (888–918, env-var only) and `docs/feature-matrix.md` (row 73, endpoints only) make no claim-semantics statement → no edit.

**Minimal wording updates applied (AGENTS.md §5.6, same change):**

1. `docs/error-codes.md` — prose: `...contradicts the token's tenant_id claim — or a user token carrying no tenant_id claim — returns tenant_mismatch`; row: `..., or the token carries no tenant_id claim`. The 'Emitted when' cell now covers all four predicate causes: missing request tenant, unbound request tenant, claim contradiction, absent claim.
2. `cmd/snaplink-stripe-adapter/openapi.yaml` — POST description (25–29): `a contradiction — or a token carrying no tenant_id claim — returns tenant_mismatch`; `tenant_id` property (175): `contradicts the request tenant, or that carries no tenant_id claim`; Forbidden response (217–219): `— or that carries no tenant_id claim —`. Byte-identity promises (constant body, no `scope` attribute, causes indistinguishable) untouched.
3. `docs/stripe-payment-adapter.md` (41–42) — same-change consistency: `a contradiction, or a missing claim on a machine token` → `a contradiction or a missing claim` (machine-only implication would contradict the updated error-codes.md; this file is the trust-model doc referenced by config-reference.md:893).

**Validation:** `python cli.py adapters check` → `adapters-check: static contract OK` (kin-openapi validation of the adapter contract) + conformance matrix green; both `openapi.yaml` files re-parse.

**Report:** `docs/architect-analysis/auto/runs/close-the-last-fail-open-tenant-isolation-class--41270b2a/artifacts/contract-consistency-e32aeda0/task-2-contract-consistency.md` (verification table + before/after wording + validation). No production Go touched; the M2 code flip, A15 deletion, and A16 pin remain the implement stage's work.
