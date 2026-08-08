All citations verified; design written. Summary:

## Verification verdict — all evidence claims confirmed

| Evidence claim | Verdict |
|---|---|
| `issue_payload.go:46` `TenantID: subject.TenantID` (unconditional, omitempty omission, ext-strip) | ✅ line-exact |
| `consts_wire.go:169` `KeyTenantID = "tenant_id"` | ✅ line-exact |
| `rs/claims.go:13-46` no TenantID field; wireClaims/parseClaims project nothing | ✅ exact |
| `http.go:200-235` trio never reads the claim (trio spans 198-236) | ✅ exact |
| `authz.go:23` `CheckScope` | ✅ line-exact |
| Mint chain (cc:52) + authcode:136 + refresh:292 all stamp `client.TenantID`; adapter JWT-mode only; `wireIntrospection` embeds `wireClaims`; introspection body doesn't echo tenant_id; srCC e2e harness; G5 gate slot | ✅ all confirmed |

## Nuances the spec glossed over (resolved in the design, §1.1)

1. **User-flow tokens carry the console *client's* binding** — authcode/refresh stamp the same `client.TenantID`. Consequence: the user gate is **inert pre-B4-1** (absent claim → D1 pass), the machine gate is **breaking pre-B4-1** (absent claim → fail-closed) — the rollout constraint is asymmetric.
2. **`authorizeUserCheckout` needs two rejection branches** — scope failure keeps `insufficient_scope`+scope attr (pinned), tenant causes become `tenant_mismatch`; a single OR cannot express the two codes.
3. **Unconditional fixture claim addition is safe for all existing tests** — unbound/wrong-scope cases short-circuit before any tenant check; the two changed pins are cause-independent.

## Deliverable

**`docs/architect-analysis/cmd-snaplink-stripe-adapter-tenant-claim-design.md`** (new, follows the billing design house template): API changes (R1: `Claims.TenantID` + wire tag + both decode paths + `HasTenantID()`, one constructor line in introspect.go; R2/R3 gate conditions with concrete code; R4: fixture/`ErrTenantMismatch` const; R6: openapi + error-codes), compatibility constraints (sequencing asymmetry, deliberate user-flow wire change, carve-outs, `resource`-required e2e), 8 failure modes (F1-F8), 6 migration steps (G5 slot, operator pre-flight, rollback), and the full A1-A14 acceptance mapping with campaign T-8(a)/T-8(b)/T-9 correspondence.

One contract note surfaced during verification: the adapter's nested `openapi.yaml` is *not* kin-openapi-validated by `make ci` (only `docs/openapi.yaml` is) — recorded in §8 so A14's enforcement claim is honest.
