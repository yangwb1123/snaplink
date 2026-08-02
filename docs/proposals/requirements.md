Spec written to `docs/auto/domains-threataction-playbook-spec.md`. All evidence was verified against the code before writing:

**Verified evidence highlights**
- `threataction.go`: `Action` doc claims "Multiple actions can result from one Threat" while `ActionResult` carries a single action — and `RateLimitKey` is already per-action keyed (composition anticipated at the limiter, never the model).
- `policy.go`: `ThreatPolicy.Action Action` — single value field.
- `registry.go`: `Execute` early-returns after one handler; package doc's FAIL-OPEN promise ("one broken executor must not block ... acting on the SAME threat") is unfulfillable by construction.
- `memory/policy_store.go` and `sqlite/policy_store.go`: both `List` sort by `Name` — "first-match wins, ordered by name" is a lexicographic accident; name doubles as the CRUD path parameter.
- `admin.go`: `invalidPolicyReason` validates one action only; no ordering concept in the CRUD path.
- `build_governance.go` (~line 338): `WithDefaultAction` wired as zero-match fallback only — cannot stack.
- `docs/openapi.yaml` ThreatPolicy schema: documents "first-match in name order"; `required: [name, enabled, action]`.

**The 3 improvements** (ordered by dependency, each wire-compatible with existing single-`action` payloads):

1. **Ordered multi-action playbook per policy** — add `Actions []Action` (legacy `action` kept as shorthand); `Execute` iterates in order, reusing the existing per-action `RateLimitKey`/`allow()` and per-action `recordAudit`; returns `[]ActionResult`; per-action FAIL-OPEN makes the same-threat sibling guarantee real.
2. **Explicit `priority` replaces name ordering** — `(priority asc, name asc)` total order in both stores in lockstep; default 0 means existing deployments are byte-identical (regression-free); negative priority rejected at admin validation.
3. **Multi-policy accumulation** — `matchPolicies` returns all matches in priority order, flattened with per-action dedup (highest-priority policy owns rate-limit/audit attribution); `default_action` stays zero-match-only and is explicitly *not* changed to avoid altering fail-safe semantics — stacking is expressed via a low-priority catch-all policy.

Acceptance checks are concrete per improvement (audit-event counts, cross-policy sibling isolation, store-order parity, legacy-payload byte-identity, admin rejection of invalid priority).
