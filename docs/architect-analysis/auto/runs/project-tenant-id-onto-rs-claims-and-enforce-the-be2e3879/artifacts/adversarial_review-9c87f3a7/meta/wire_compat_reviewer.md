Review complete. All four areas were verified against HEAD code, not just the design's citations.

# Wire/contract surface review

## 1. `TenantID` on `wireClaims` — no unintended emission; non-goal holds

**Verdict: confirmed, with the marshal audit now exhaustive.**

Complete inventory of every path touching `wireClaims`/`wireIntrospection`:

| Path | Nature | TenantID impact |
|---|---|---|
| `parseClaims` (claims.go:114) — JWT payload | `json.Unmarshal` only | decode widening only |
| `introspectCall` request (introspect.go:96-106) | `url.Values{"token": …}` form body | no claims marshal at all |
| `introspectCall` response (introspect.go:108) | `json.Unmarshal` into `wireIntrospection` | decode widening only |
| `interfaces/ssoclient/rs` `json.Marshal` call sites | **zero** (grep; only dpop.go:275 is a comment) | nothing can emit |
| `populateAccessIntrospectionBody` (introspect_body.go:65-135) | explicit-field copy (exp/iat/nbf/aud/client_id/scope/jti/auth_time/acr/amr/sid/cnf/serving_region) | no tenant key; zero `tenant` hits in file |
| `introspectRefresh` (handle_introspect.go:337-374) | explicit fields | no tenant |
| Batch + cache (`introspectOne`, introspect_cache.go:107; `CachedResult`) | same bodies | no tenant |
| RFC 9701 JWT-formatted introspection (writeIntrospectionResponse, handle_introspect.go:178-200) | signs the same `body` map | no tenant |
| `Claims.Raw` | already holds full claim doc pre-change; never re-marshaled anywhere | unchanged |
| Mesh `X-Auth-*` (mesh_authz.go:98-102) | explicit fields (Subject/ClientID/Scopes/ExpiresAt/Roles) | untouched |

`validateIntrospectedClaims` (introspect.go:154-180) reads only iss/aud/exp/serving_region — adding a field to the decode struct cannot alter it. **Behavior-identical confirmed.**

Two affirmations worth recording: (a) the design correctly identifies the manual constructor line in `ValidateTokenWithIntrospect` (introspect.go:78-93) as *required* — the embed alone decodes but the field-by-field literal silently drops it; omitting that line fails A2. (b) Decode-side consequence: if a future server version ever starts echoing `tenant_id`, every existing rs introspection consumer would silently see it populated — but no consumer gates on it (no `rs.Config` tenant gate), and the adapter is JWT-mode (http.go:93-98, no `IntrospectURL`), so nothing can flip semantics accidentally.

## 2. User-flow challenge change — acceptable; R6 has three concrete gaps

**Delta verified byte-for-byte** (only the missing/unbound input-tenant causes on the user flow):
- Body: `{"error":"insufficient_scope"}` → `{"error":"tenant_mismatch"}`
- Challenge: `…error="insufficient_scope", scope="admin:write"` → `…error="tenant_mismatch"` (no scope attr, by construction of writeCheckoutChallenge http.go:380-390)
- Unchanged: status 403, no-store headers, wrong-scope case, all machine-flow bytes, all success paths.

**Downstream impact**: no *successful* flow changes — only error classification of requests that already failed and were unfixable by scope escalation. Status-only clients see zero delta; scope-attr parsers lose advisory scope guidance on a class that was never scope-fixable; `tenant_mismatch` is already a platform-wide documented code (error-codes.md:87), so console-side mapping tables likely already contain it. Residual risk the design doesn't list: a client mapping unknown codes to generic failure sees a UX message change — worth one line in the compatibility table.

**R6 gaps** (design text vs actual docs):
1. "Adjust the `insufficient_scope` **row** wording" — there is **no `insufficient_scope` row** in the Stripe section; it lives only in the section prose (error-codes.md:1043-1044). The prose must be rewritten for the user-flow split *and* the new machine claim-consistency class.
2. The openapi `Forbidden` description enumerates causes ("Missing exact scope, unbound tenant/client, or cross-tenant request"); R6's planned edit adds the `tenant_mismatch` case but never states the machine claim-consistency class joins the `insufficient_scope` cause list — it's a new observable cause class (same bytes, but the description is a contract enumeration).
3. `docs/stripe-payment-adapter.md:38-41` describes the same authorization flow and is excluded from R6's "same change" scope. It stays factually true (preconditions, not error codes) but the enforcement description ("optional request `tenant_id` must match") is precisely where the delta lives — one line belongs there.

## 3. A14 pairing is **not enforced** — the design overstates it; recommend a concrete gate

Verified: `make docs-validate` runs kin-openapi on `docs/openapi.yaml` only (Makefile:189); `route-contract` and `adapters-check` (checks/route_contract.py:19, adapters_check.py) never touch nested openapi files; `checks/invariants.py` checks existence only. **`model.go`'s comment — "exported so the repository contract gate can prove every documented adapter response remains backed by executable code" — references a gate that does not exist.** The exported-constant/docs-row pairing is currently review-only; A14's "the constant backs the new docs row" claim overstates the mechanism.

Good news: the adapter's openapi.yaml **passes kin-openapi validation today** (verified: exit 0), so a gate is safe to add with no pre-existing failure.

Concrete recommendation (matches repo check style, no go.mod change — kin-openapi is not a module dependency):
1. Extend `checks/adapters_check.py` (already in `make ci`) with two static scans: (a) run the same `kin-openapi validate` invocation over `cmd/*/openapi.yaml` (currently exactly one file); (b) parse the exported wire-code const block in `cmd/snaplink-stripe-adapter/model.go` and assert each value appears as a `` | `code` | `` **row** in the error-codes.md Stripe section. The row-level assertion would have caught gap 2.1 (row vs prose) at review time — that's the strongest argument it's worth building.
2. A14 then means: gate green + constant exists + row exists — machine-enforced, not aspirational.

## 4. Sequencing constraint — valid; three refinements for rolling-upgrade reality

Verified: G5 row (implementation-gate.md:77) = T-2/T-8(b–e)/T-9; B4-1 mint row (line 11) = T-8(a) `{iss/aud/scope/client_id/tenant_id/roles}`; requirements §7 mapping matches the design's §7. The asymmetry analysis is sound, and note the mint is **already in this repo's HEAD** (issue_payload.go:46) — "pre-B4-1" is a *deployed-fleet* state, not a code state.

Refinements:
1. **The bound is `max(AccessTokenTTL)`, not "short TTL"** (default 1h, issue_payload.go:36; per-client override token_client_credentials.go:53). A checkout client with a long override extends the F6 denial window to a day+. F6's "no operator action" is only true for default-TTL deployments — migration step 3 should add "record each checkout client's AccessTokenTTL and plan the window."
2. **"Or same window" is the risky option.** Deploying the gate mid-IdP-upgrade fails closed (safe) but the impact is *invisible*: denials increment no metric and no audit path exists (by design, §2). The only signal is a checkout 403-rate change. The pre-flight should say: deploy the adapter gate after full IdP drain, or accept the bounded window with a monitored 403 rate.
3. **State rollback ordering explicitly**: reverting the adapter gate first restores today's behavior (including the cross-tenant hole); reverting the IdP mint first while the gate lives re-creates F1 (safe, fail-closed). An operator un-reverting in the wrong order must know the intermediate state is still safe.

**Bottom line**: the design is wire-sound (points 1, 4 hold; point 2's delta is acceptable); the two real defects are documentation-mechanism overstatements — R6's "row" edits (2.1/2.2) and A14's unenforced pairing (point 3). Both are cheap to fix: one prose correction in the design, one concrete check wired into `make ci`.
