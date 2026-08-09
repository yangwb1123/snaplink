Verification complete. Working tree restored byte-exactly (sha256 match, diff unchanged, module suite green again). Here is the independent verification report.

---

# Verification: fail-closed flip at `cmd/snaplink-stripe-adapter/http.go:241`

**Method**: full-module read-through (all 10 non-test files), module-wide claim-usage sweep, contract cross-check (openapi.yaml / error-codes.md / stripe-payment-adapter.md / adapters_check.py), plus an *empirical* run: the flip was applied temporarily (backup-protected, restored byte-exactly — sha256 `91d2fec7…` matched before/after, `git diff` unchanged), with a scratch byte-identity test exercising all four causes through the real HTTP stack (rs middleware + handler).

## 1. No other handler consults `rs.Claims` or permits claim-less tenant access — CONFIRMED

Sweep of every non-test file: `rs.Claims`, `ClaimsFromContext`, `HasTenantID`, `CheckScope` appear **only in http.go** (middleware mount at :59 wraps only `pathCheckout`; consumption at :201–209, :213–252). Per path:

| Path | Auth surface | Tenant source | Claims? |
|---|---|---|---|
| webhook (`webhook.go`, `http.go:93–130`) | Stripe HMAC + ±5 min window + live/account/api-version binding | Stripe metadata → mapping lookup (`store.go:248–254`), validated against the billing order's tenant | none |
| worker (`worker.go`) | none (internal) | `w.bindings[delivery.TenantID]` — store mapping; unknown tenant → quarantine, never pass | none |
| billing (`billing.go`) | client-credentials tokens for `binding.BillingClientID/Secret` | binding from config; `validOrderIdentity` forces `order.TenantID == binding.TenantID` | none |
| store (`store.go`, `store_errors.go`) | — | keys `(order.TenantID, order.ID)`; `ReserveCheckout` stamps from the **billing-validated order**, not request input | none |
| live/ready/metrics | unauthenticated probes | — | none |

The checkout mapping, Stripe metadata (`stripe.go:92–94`), and reservations are all stamped with `order.TenantID`, which `GetOrder` proves equals `binding.TenantID`. `authorizeCheckout` is therefore the **single caller-influenced tenant-selection surface**, and the user-path claim-less carve-out was the last fail-open class on it (the machine class at :224–226 already landed fail-closed).

## 2. Byte-identical oracle across all four causes + empty-input edge — CONFIRMED EMPIRICALLY

With the flip applied (`binding == nil || claims.TenantID != input.TenantID`), a scratch test through the full stack asserted byte-equality (status, body, **full header map**):

- Four user-path causes — missing input tenant, unbound input tenant (`tenant-nowhere`), bound-other claim mismatch (`tenant-other`), claim-less token + bound input — all produce byte-identical `403`, body `{"error":"tenant_mismatch"}\n`, `WWW-Authenticate: Bearer realm="stripe-adapter", error="tenant_mismatch"` (no scope attribute), `Cache-Control: no-store`, `Pragma: no-cache`. ✅
- Empty-input-tenant edge: claim-bearing and claim-less tokens with `tenant_id` omitted both land on the same `binding == nil` writer (`TenantBindings[""]` is unconstructible — `validIdentity` rejects `""` at `config.go:332`; `indexBindings` keys by the validated `binding.TenantID`) and are byte-identical to the four causes. ✅
- Controls: claim-bearing + bound → still 201; machine four causes (unbound client / input mismatch / claim-less / claim-less+missing-input) → byte-identical `403 insufficient_scope` with scope attribute (already-landed flip, ordering comment at :219–226 is accurate). ✅
- Full module suite with flip: **40 pass, exactly 1 fail — A15** (`TestCheckoutUserAcceptsTenantlessConsoleToken`), the carve-out pin the design deletes/replaces with A16. The flip's only wire delta is that previously-201 class → `403 tenant_mismatch`, matching the **already-landed** contract docs (openapi.yaml:20–31/175–176/214–225, error-codes.md:1047–1063, stripe-payment-adapter.md:38–46 — all written for the fail-closed behavior).

## 3. Post-deploy: pre-existing claim-less sessions and refresh-minted tokens

- **Mint is config-derived everywhere**: every grant mints `TenantID: client.TenantID` (authcode `token_authcode.go:136`, cc :52, device :99, ciba :124, jwt_bearer :112, saml2 :123, exchange `stages.go:399`, **refresh `token_refresh.go:292` via `refreshRotatedSubject`**). No path mints a claim-less token for a bound client, and none mints a claim-bearing token for an unbound one. So claim-less tokens exist only for unbound (console) clients — exactly the M1 bind-at-IdP population.
- **Refresh-minted tokens**: rotated tokens re-read `client.TenantID` from *current* config — a console client bound after original issuance picks up the claim on its next rotation; a client unbound (config regression) loses it and fails closed (safe direction). Post-flip, refreshes for bound clients are unaffected.
- **Pre-existing claim-less sessions**: reservations are keyed `(tenant, order)` from the billing order; webhook fulfillment (InsertInbox → ResolveClaim → worker) is claim-free, so in-flight Stripe sessions complete and deliver. Claim-less tokens can no longer reach ReserveCheckout/replay/rotate; expired sessions rotate on the next *claim-bearing* attempt for the same `(tenant, order)`, available ones replay 200 (the idempotency contract, same-tenant only). No data loss, no wedged orders, no new cross-tenant exposure. The flip is server-side, so claim-less tokens 403 from deploy instant — detect via `checkout_created` drop (design's failure-mode section is accurate).

## 4. One-line rollback: bounded and documented, with one doc-coupling caveat

- **One line**: verified both directions (removing/restoring `(claims.HasTenantID() && …)` at :241). The D1 carve-out comment (:243–248) remains in the tree, so the restored code matches its in-place rationale; M5 names the rollback.
- **Bounded**: reopens only the claim-less user class for bound input tenants (exact pre-change behavior); claim-bearing tokens are never affected; the machine flip is a separate line and survives a user-path rollback — **but a whole-commit revert would reopen both classes** (HEAD's machine path lacks the claim check), which operators must be told.
- **Caveat (the one gap found)**: the partial landing already moved the wire contracts to the fail-closed wording. A pure one-line code rollback therefore puts code *behind* the documented contract (the exact drift the flip resolves; AGENTS.md says satisfy the stricter contract). The rollback is **not doc-neutral**: M5 must also revert openapi.yaml / error-codes.md / stripe-payment-adapter.md edits, or accept a temporary code-vs-doc disagreement. Note the current pre-M2 tree already sits in that state (docs describe fail-closed; A15 pins the carve-out), so "rollback" returns to a state with precedent — bounded, reversible, and now explicitly documented by this report.

## Pre-existing gate failures (reported separately per AGENTS.md §5.7)

Identical before/after the flip (files untouched by it): `TestArchitecture_DirectoryDepth` and `TestArchitecture_DirectorySubdirFanout` (drift from `docs/architect-analysis/auto/runs/…` generated artifacts) and `TestMaintainability_FileSizeBudget` (`infrastructure/defaultimpl/ed25519_jwt_issuer.go`, 539 lines, committed). `adapters_check.py`, `go build/vet`, and `go test ./test/ -run TestStripeAdapter` are green.

**Verdict**: the design's claims hold. The flip closes the last fail-open tenant-isolation class; four-cause byte-identity (incl. empty-input edge) is real and pinned; post-deploy behavior is sound (webhook fulfillment keeps in-flight payments alive; refresh re-mints from current client binding); rollback is one line, bounded to the claim-less class, and documented — with the doc-coupling of the already-landed contract edits as the single refinement M5 needs.
