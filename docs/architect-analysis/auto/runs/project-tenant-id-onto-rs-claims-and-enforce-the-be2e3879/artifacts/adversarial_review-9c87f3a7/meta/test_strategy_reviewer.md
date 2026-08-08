All four audit points are now verified against the code. Findings:

## 1. D1 pin after R4 — **GAP CONFIRMED, no test pins it**

- Post-R4, `testAdapterHandlerSubject` (http_test.go:307-339) stamps `tenant_id: "tenant-one"` unconditionally, and every user-flow test mints through it: A4 (mismatch), A5 (three causes, *claiming* token), A6 (converted `TestCheckoutAuthorizesAdminUserForExplicitBoundTenant` — claim now present), A7 (wrong scope). The no-claim variant is assigned only to A9 (machine absent-claim negative).
- Today, `TestCheckoutAuthorizesAdminUserForExplicitBoundTenant` (http_test.go:109-118) **is** the de-facto D1 pin (no claim exists yet, bound input → 201). R4's fixture change converts it into A6, so the absent-claim user pass becomes unpinned. A regression that drops the `HasTenantID()` guard — D1's rejected alternative, plain `claims.TenantID != input.TenantID` — would fail-closed on every tenant-less/shared-console deployment and **no test would flip**.

**Missing test (spec):** new `TestCheckoutUserAcceptsTenantlessConsoleToken`, T-8(b) family, new A-row in §7 (or folded into A6):

1. Mint via the no-claim variant: `testAdapterHandlerSubjectWithoutTenantClaim(t, store, billing, stripe, "user-one", "console-client", scopeAdminWrite)`.
2. Input `{"tenant_id":"tenant-one", ...}` → **201**, and assert `billing.lastBinding.TenantID == "tenant-one"` (the gate actually selected the bound binding, not a short-circuit).
3. **Companion case, same token**: input `tenant-nowhere` → 403 with the *exact* challenge `Bearer realm="stripe-adapter", error="tenant_mismatch"` (equals, not Contains — construction is deterministic). This pins that absence waives only the claim comparison, never the `binding == nil` check; without it, a regression deleting `binding == nil` would pass case 2 while letting tenant-less consoles check out to unbound tenants — a new existence leak, exactly what D3 forbids.
4. Optional: byte-compare the 201 response with A6's claiming-token pass — absence is unobservable in the pass path.

Unit level is correct for this: the e2e cannot mint user-shaped tokens without the authcode dance (non-goal), and the user gate is unit-pinned anyway.

## 2. Byte-equality robustness and R4.2 — **sound, with two corrections**

- **Citation drift**: `writeCheckoutChallenge` is at **http.go:380-388**, not 241-250 (241-250 lands inside `validReturnURL`). The behavioral claim is correct: `Header().Set` (single value), fixed param order realm→error→scope, `scope=` appended only when non-empty, body via single-key `writeJSON` (`{"error":...}\n`). Deterministic bytes across calls with equal `(status, code, scope)`.
- **Header ordering**: `httptest.ResponseRecorder.Header()` is a `http.Header` map — `reflect.DeepEqual` on the maps is order-independent by construction; even serialized, Go's `Header.Write` key-sorts. No `Date`/`Content-Length` is added by the recorder. Robust — but the design should pin the mechanism in A5/A8: compare `Code`, `Body.Bytes()`, and `Header()` maps via DeepEqual (or exact challenge-string equality, which R2.2 already fully specifies). Avoid per-key `Get` on multi-value headers (not an issue here — `Set`, not `Add`).
- **R4.2 cause-independence**: genuinely independent. "Missing tenant" fires `binding == nil`; "unbound tenant" (post-fixture) fires the claim-mismatch branch; both flow through the **single shared writer call** with `(403, ErrTenantMismatch, "")` and a cause-agnostic assertion. The pin bytes are stable under either fixture variant (claim added or not, `tenant-other` added or not) — verified by tracing both branches. Note: post-R4 the "unbound tenant" case becomes a duplicate of A4's shape (its name is a misnomer; genuinely-unbound coverage moves to A5's `tenant-nowhere`) — acknowledged in the design, fine.

## 3. F1/F2/F3/F6 — behaviorally covered, but the ops-only acceptance is **implicit, not explicit**

| Failure | Enforcement branch | Pinned by | Reconciliation |
|---|---|---|---|
| F1 (pre-B4-1) machine | absent claim → 403 | A9 | ops sequencing (§6 step 2) |
| F1 user | absent claim → pass | **unpinned — the point-1 gap** | — |
| F2 (console rebind) | input A → `tenant_mismatch`; input B → pass | A4 / A6 | cold-restart reconcile — ops-only, untested, never declared |
| F3 (checkout rebind) | claim B vs binding A → 403 | A8 | cold-restart reconcile — ops-only, untested, never declared |
| F4 | absent-claim machine denial | A9 (same code path) | register IdP binding |
| F6 (pre-B4-1 tokens in wild) | identical to F1 code paths; TTL-bounded window | A9 + (new D1 test) | no automated test possible or needed |

The §5 table has no coverage column and §7 never cross-references F-rows, so "tested" is true but unstated. Fix: add a "Coverage" column to §5 annotating F1→A9(+D1 test), F2→A4/A6, F3→A8, F5→A5/A8, and mark F2/F3 reconciliation + F6 explicitly as **accepted ops-only scenarios with no automated test** (the failure behavior itself is what A4/A6/A8/A9 pin).

## 4. E2e substitution and A11 — **adequate, strengthened by an existing pin; A11 has an `aud`-shape bug**

- The design's substitution argument is sound and **understated**: `test/refresh_rotation_claims_test.go` `TestRefreshRotation_TenantIDPresentRolesAbsent` (135-184) already pins the authcode-code-exchange **and** refresh-rotation `tenant_id` wire claims in a real cross-server test (`exchangeCode` → payload assert, rotation → payload assert). The composition is complete: authcode/refresh mint→wire claim [existing test], cc mint→wire claim [A11], wire claim→rs projection [A1/A2 unit + A12], projection→user gate [A4-A7 unit], projection→machine gate [A8-A10 unit]. The design should cite this test in §3.5 — then "no authcode dance" rests on a tested pin, not code reading alone.
- **A11 correction**: `audClaim.MarshalJSON` (ed25519_types.go:141-148) emits a **compact string for a single audience** — `aud == "stripe-adapter"`, not `[stripe-adapter]`. As written, A11 would false-fail on a correct mint. The `tenant_id` assertion itself **fails loudly** on stamp regression: missing key → `"" != "tenant-e2e"`; malformed segment → decode error; non-200 mint → earlier assertion. Spec it as `got, ok := payload["tenant_id"].(string); ok && got == "tenant-e2e"` so absence fails with a clear message. (A12/A13 are unaffected: `audienceValues` in claims.go handles both string and array forms.)

**Net**: three concrete spec fixes (D1 test + `aud` shape + `writeCheckoutChallenge` citation) and two documentation hardening items (F-row coverage column, refresh_rotation citation). Everything else in the A1-A14 mapping holds under verification.
