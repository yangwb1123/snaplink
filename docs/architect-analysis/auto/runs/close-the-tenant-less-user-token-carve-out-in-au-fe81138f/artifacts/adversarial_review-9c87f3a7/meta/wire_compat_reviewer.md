All validation complete. Here is the independent validation report.

---

# Validation report: byte-identity and wire-stability claims (B4-1 tenantless carve-out design)

**Verdict: all four wire-level claims hold as designed; the A5/A16 pin mechanics are sound; `make ci` validates structure, not wording (a nuance the design states correctly but should be read precisely). No observable cross-cause distinction exists post-change. Two flags and three nits below.**

## 1. Exact error body bytes — VERIFIED (empirically)

- All four causes converge on the single call `writeCheckoutChallenge(writer, 403, ErrTenantMismatch, "")` at `http.go:250` (line-verified: guard 241, comment 243-248, writer 250). `ErrTenantMismatch = "tenant_mismatch"` in model.go's anchored wire-code block (46-55).
- `writeJSON` → `json.NewEncoder.Encode(map[string]string{...})` → single-key map, no HTML-escapable chars.
- **Empirical dump** (temporary in-package test, deleted after): `BODY="{\"error\":\"tenant_mismatch\"}\n"` — exactly 13 bytes, newline-terminated. `Content-Type: application/json` (no charset).
- Key order is deterministic (one key); body cannot diverge between causes.

## 2. WWW-Authenticate challenge format — VERIFIED (empirically)

- `writeCheckoutChallenge` (401-411) appends `scope=` only when non-empty; all four causes pass `""`.
- `security.QuoteAuthParam` is RFC 7235 quoted-string; neither `stripe-adapter` nor `tenant_mismatch` needs escaping.
- **Empirical**: `WWW-Authenticate: Bearer realm="stripe-adapter", error="tenant_mismatch"` — no scope attribute, single value (`Set`, not `Add`).
- The scope class stays distinguishable only by code+scope-attribute (`insufficient_scope` + `scope="admin:write"`) — the pre-existing R2.3 split, unchanged.

## 3. No-store headers across all four causes — VERIFIED

- `handleCheckout` calls `privateNoStore` unconditionally at entry (before the method check), and `writeCheckoutChallenge` re-applies it. Every tenant-class cause passes both.
- **Empirical**: `Cache-Control: no-store`, `Pragma: no-cache` present on the 403.
- openapi.yaml `NoStore`/`NoCache` components use `const: no-store`/`const: no-cache` and are wired into 401/403 (and 200/201) — consistent with code.

## 4. A5/A16 reflect.DeepEqual pin soundness — VERIFIED

- **Recorder determinism**: `httptest.ResponseRecorder.Header()` contains exactly the handler-set map. **Empirically: no `Date`, no `Content-Length`** — the A5 comment's claim is accurate. Header map is exactly 5 keys, all cause-independent: `Cache-Control`, `Content-Type`, `Pragma`, `WWW-Authenticate`, `X-Content-Type-Options` (from `securityHeaders`; rs middleware and `TrustedProxies.Middleware` set no response headers on success — verified in `middleware.go` and `trusted_proxy.go`).
- **DeepEqual on `http.Header`** (a map) is insertion-order-independent; keys are canonicalized by `Set`. No fragility from set order.
- **Wire-order nuance**: at a real edge Go writes headers sorted (`Cache-Control, Content-Type, Pragma, WWW-Authenticate, X-Content-Type-Options`) — identical across causes. The real server's `Date` has 1-second granularity but is added identically regardless of cause; it can never discriminate causes (and the pins don't include it at all — strictly more robust than `Result()`).
- **Transitivity**: A5 pins bound-other == unbound == missing; A16 pins claim-less == claim-mismatch (bound-other). All four pairwise-connected → byte-identical. Sound. A16's two rows use separate handler instances (separate rstest issuers); irrelevant — the response depends only on the identical `runtimeConfig` literal and the token-claims → guard-outcome mapping.
- **Pipeline determinism proof**: the response is a function of (Subject, ClientID, scope, guard outcome) — the only claim read at the guard. Both rows produce `guard=true` via the same expression with different operands; every other pipeline stage (rs validation, scope check, writer) is operand-independent. Byte-equality holds by construction; the pin re-proves it.

## 5. `make ci` / docs validation semantics — VERIFIED, with a precise-reading nuance

`make ci`'s doc-relevant gates are `adapters-check` (`cli.py adapters`) and `docs-check`:

- **(g)** kin-openapi validate (pinned `@v0.146.0`) on `cmd/*/openapi.yaml` — **syntax/schema only; wording is not machine-checked**. A19's "make ci (OpenAPI validation) green" is accurate as *structural* validation. The R5 wording edits (block scalars gaining sentences) cannot break it if indentation stays valid.
- **(h)** one-directional pairing: every exported wire-code const in model.go's anchored block must have a `| code |` row in the `## Stripe payment adapter` section (heading verified at error-codes.md:1034; `tenant_mismatch` row at 1051). **The "Emitted when" wording is not checked**; the row keeps its backticked code, so the wording edit is gate-safe. Row-without-code is not checked.
- `route-contract` parses only `docs/openapi.yaml` (sso-server) — the adapter's nested contract is invisible to it. `docs-validate` (kin-openapi @latest) is **not** in `make ci`.
- Pre-change state: `python cli.py adapters` → green (static + behavioral), so the design's gate baseline is accurate.

**Precise reading to record**: "wording consistency under make ci validation" does not exist as a machine check — wording consistency is review-enforced; `make ci` enforces YAML validity + row presence. The design's own wording ("make ci (OpenAPI validation) green") is consistent with this.

## 6. Observable distinctions for a token holder — none new (two flags)

| Surface | Finding |
|---|---|
| Bytes | Identical (empirical). |
| Timing | All four causes run the identical expression sequence: one map lookup + one `!=`. Go compares string lengths first; claim-less (`""` vs `"tenant-one"`) and mismatch (`"tenant-one"` vs `"tenant-other"`) both take the O(1) length-difference fast path. The only delta — short-circuit causes 1/2 skip the string compare — is **pre-existing** (already true between causes 1/2 and 3 today) and sub-nanosecond. No data-dependent branching on server secrets; inputs are attacker-chosen and attacker-known. |
| Header order | Identical (Go sorts). |
| Audit | Zero audit calls in the adapter (grep-verified). rs is in-process validation, no audit events. |
| Metrics | `adapterMetrics` has **no tenant-mismatch counter at all**; the 403 path increments nothing; `/metrics` exposes only aggregate counters (webhook\*, checkoutCreated/Replay/Expired/Failed) — no per-cause breakdown even server-side. |
| Logs | No per-request logging in the HTTP path (logger only in main/worker for the relay loop). |

**Flag 1 (intended, not a leak)**: pre- vs post-change, the same claim-less request flips 201→403 and its latency collapses (no Billing/Stripe/store calls downstream). A token holder observing across the deployment window can detect *that the change happened* — that is the change, uniformly applied, and it matches the documented migration (step 5-6 of §7).

**Flag 2 (semantic clarity, not a flaw)**: a token holder can trivially distinguish "my token has no `tenant_id`" from "my token's `tenant_id` differs" by decoding their own JWT (signed, not encrypted). The oracle-safety property is narrower and holds exactly: the *server's response* reveals nothing about other tenants' bindings. Worth one sentence in the A16 comment so the claim is read correctly.

## 7. A17/A18 feasibility — VERIFIED (one assumption now proven)

- `MemoryClientStore.AddSeed` performs **no TenantID validation** (hashes secrets, stores) — the unbound `saLegacyClient` (`TenantID: ""`) seeds cleanly.
- Grant-agnostic mint confirmed on **both** paths: `token_client_credentials.go:52` and `token_authcode.go:136` both stamp `TenantID: client.TenantID` into the subject; `buildAccessPayload:46` copies unconditionally with `omitempty`. Unbound client → 200 with no claim (entitiescmd case 5 shape); bound → claim present. A18's "no `tenant_id` key" assertion is executable.

## 8. Nits (non-blocking)

1. Design §9 says "no audit path on this surface (**metrics only**)" — there is no tenant-mismatch metric either; the 403 increments nothing. Suggest "no audit/metric path on this surface".
2. openapi.yaml Forbidden `WWW-Authenticate` example shows the scope flavor (`scope="admin:write"`); the tenant-class flavor has none. The R5 wording could note this asymmetry (it already does in prose) — example is not gate-checked.
3. A16's baseline-first ordering warms the JWKS cache before the claim-less row — irrelevant to the byte pin (no timing comparison), but worth keeping the comment's claim limited to bytes/headers.

**Baseline green confirmed**: adapter checkout tests (A4-A10, A15), `test/` stripe e2e (A11-A13), rs tenant projection, `go build`/`go vet`, and `adapters-check` all pass at HEAD pre-change. No drift found in any design citation re-checked during this validation.
