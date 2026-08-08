Requirements spec complete: `docs/architect-analysis/cmd-snaplink-billing-tenant-claim-requirements.md`.

## Verification of every cited symbol (all confirmed)

| Evidence | Verdict |
|---|---|
| `issue_payload.go:46` `TenantID: subject.TenantID` (unconditional, omitempty — "single-tenant stays byte-identical" comment at 42-45); `:86-87` Roles guard+copy | Confirmed, line exact |
| `rs/claims.go:13` `Claims` — no TenantID/Roles; `wireClaims` (93-108) has no `tenant_id`/`roles` tags; `parseClaims` (113-136) no projection; only `Raw` exposes them | Confirmed (grep: zero fields) |
| `app.go:220-222` — `rs.Config{Issuer, JWKSCache, ExpectedAud}`, no tenant handling | Confirmed, line exact |
| `auth.go:159` `adminScopeGate` — scope-only; `writeScopeFailure` (180-193) already emits the byte-identical 403 `insufficient_scope` shape | Confirmed |
| `quota_relay.go:434-453` `quotaAuthorizer` — tenant from outbox row (`http_client.go:102`); the backstop at `http_client.go:143` only checks authorizer-return vs event tenant (equal by construction), never the token claim | Confirmed |
| `README.md:170-172` — "当前 Snaplink client_credentials token 不携带 `tenant_id` claim…" workaround | Confirmed, line exact |

**Additional load-bearing findings:** `serving_region` is the exact rs precedent to mirror (projection in both JWT + introspection modes, fail-closed gate runs last with no-probe-oracle ordering); `oauth_token_source.go:44-46` carries the same stale pre-B4 premise; the IdP-side projection handler (`interfaces/sso/quota.go`) never compares the claim (explicit non-goal — billing-side gate makes drifted deliveries undeliverable pre-PUT); payment and metering gates already hold the binding, so the drift condition is one added comparison per family.

## Spec decisions (the direction left these open)

- **Drift response shape**: emitted through the route's existing rejection writer with identical args → byte-identical 403 `insufficient_scope` by construction; no tenant value in body/headers/challenge; not distinguishable from a scope denial even in audit. Folds into the already-documented `insufficient_scope` row (error-codes.md:137,1014), no new `Err*`.
- **Absent-claim semantics (fail-closed spine)**: billing store resolves a binding ⇒ claim must be present and equal; missing claim = the "billing bound a client the IdP never bound" drift class = deny. No binding ⇒ no gate (single-tenant carve-out stays byte-identical).
- **T-8(e) placement**: cross-check in `quotaprojection.HTTPClient.authorization` (sole production consumer is billing) so the e2e exercises production code, not a test replica; mismatch/absence → existing `ErrAuthorizationRejected` bounded-retry class, event retained, no PUT leaves billing.
- **Budget gate caught**: `quota_relay.go` is 485/500 lines — the spec mandates the check NOT land there.

All four supplied acceptance checks preserved and made testable (A1–A10 mapping table in §7), with the campaign G1→G5 sequencing note (consumption must land after the T-8(a) mint pin). No Go files were touched, so no build gates were triggered.
