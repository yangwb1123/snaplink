All three R6 documentation edits are landed and validated. Summary:

## Edits made

**1. `docs/error-codes.md` — Stripe section prose rewrite + row** (lines ~1036-1047)
- **Prose** (the `insufficient_scope` cause, which lives in prose — confirmed, no row exists): now splits the flows. Machine flow: missing exact `billing:checkout:create` scope, no unique client binding, **or a `tenant_id` claim that is missing or contradicts the client's bound tenant** → `insufficient_scope` (403), binding/claim-consistency causes "stay indistinguishable" (mirrors the hidden-binding style at the commerce section, line ~1014). User flow: missing `admin:write` keeps `insufficient_scope`, while a request `tenant_id` that is missing, unbound, or contradicts the token's claim → `tenant_mismatch` (403) with **no `scope` attribute** — the exact R4.2 wire delta.
- **Row**: `tenant_mismatch | 403` added as the table's first data row (per requirements R6.2 and A14's "documents every wire code the adapter emits, including `tenant_mismatch`"), with the no-leak client guidance ("the response never discloses the token's or request's tenant").

**2. `cmd/snaplink-stripe-adapter/openapi.yaml` — Forbidden description enumeration** (the only file containing the "Missing exact scope, unbound tenant/client, or cross-tenant request" enumeration; `docs/openapi.yaml` has zero Stripe content)
- Keeps the original cause line, then enumerates the two new classes: user-flow tenant causes → `tenant_mismatch` with no `scope` attribute on the challenge; machine claim-consistency denials (missing or contradicting claim) **fold into the same `insufficient_scope` response**, indistinguishable. `WWW-Authenticate` example untouched (stays the `insufficient_scope` primary shape, per design §3.6).

**3. `docs/stripe-payment-adapter.md:38-41` — one-line enforcement delta**
- Extended the machine-token precondition sentence: both flows require the token's `tenant_id` claim to equal the tenant the request resolves to (bound tenant for machine, request `tenant_id` for user); a contradiction, or a missing claim on a machine token, rejects the request. Precondition-style only — no error-code claims altered, per the reviewer's note that the doc "stays factually true (preconditions, not error codes)".

## Validation

| Check | Result |
|---|---|
| `kin-openapi validate` on edited `cmd/snaplink-stripe-adapter/openapi.yaml` | ✅ exit 0 |
| `kin-openapi validate` on `docs/openapi.yaml` (make ci docs-validate target; untouched by me) | ✅ exit 0 |
| Byte-delta scope | ✅ diffs touch only: error-codes.md Stripe section (2 hunks total — hunk @295 is a pre-existing sibling change, preserved untouched), nested openapi Forbidden description (description-only, no schema/example/response-shape changes), stripe-payment-adapter.md precondition paragraph (one sentence) |
| Success-path / machine-flow changes | ✅ none — only reclassification of already-failing user-flow requests and the new machine claim-consistency class folded into the existing `insufficient_scope` bytes; both stated explicitly as cause-hidden |

The user-flow wire delta (missing/unbound input tenant: `insufficient_scope`+scope attr → `tenant_mismatch`, no scope attr) is documented on all three surfaces, and the machine class is consistently documented as folded/indistinguishable everywhere, matching the A5/A8 byte-equality pins.
