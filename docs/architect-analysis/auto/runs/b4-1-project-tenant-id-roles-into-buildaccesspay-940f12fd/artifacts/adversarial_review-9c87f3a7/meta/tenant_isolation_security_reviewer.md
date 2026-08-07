All load-bearing citations verified against the working tree. Here is the review.

---

# Review: B4-1 tenant-boundary design (tenant_id + roles contract pins)

**Verification basis:** design doc re-checked against HEAD; empirical Go check for the omitempty claim; all §1 evidence-table citations re-spotted (8 grant-path `TenantID: client.TenantID` stamps at authcode:136 / refresh:291 / cc:52 / device:99 / ciba:124 / jwt-bearer:112 / saml2:123 / exchange:399; SID-discipline comment at issue_payload.go:38-40; `resolveIssuer` at server_discovery.go:251; `WithIssuer` at options.go:350; `JWTAssertionValidator` zero concrete impls; grpcadmin:77/177/194/315; `body: "tenant"` at proto/admin/v1/tenants.proto:31,37; apiclient.go:27,30; 16 `cmd/sso-ctl` subdirs; 60 non-test files in `interfaces/sso`).

## Q1 — Unconditional TenantID stamp: CONFIRMED

Matches the R0 contract and the codebase's established discipline, and conditionality is correctly rejected:

- **The R0 contract** (requirements §5 R0.1) requires projection in `buildAccessPayload` from `subject.TenantID` with `omitempty` — the design pins the unconditional literal assignment beside `ServingRegion`, which is exactly the pattern the code already documents at issue_payload.go:38-40: *"Unconditional literal assignment (SID discipline): omitempty performs the omission, so no wire-visible guard is needed."*
- **The classification is real, not invented.** `applyOptionalClaims` (:90-124) is the documented home of wire-visible `if` guards ("Each `if` guard is wire-visible — it controls whether the claim is emitted"). TenantID belongs with ServingRegion in the base literal: same doc symmetry ("Empty = … byte-identical"), same mint-time-stamp semantics, both with omission delegated to the struct tag.
- **"Cannot be made conditional" is correct as a normative invariant, for a concrete safety reason:** a conditional guard is wire-invisible today (identical output) yet splits the omission decision across two sites (tag + guard). Any future policy edit to that guard — e.g., "stamp only for active tenants" — would silently drop `tenant_id` from bound clients' tokens, and resource servers keying isolation on the claim would downgrade them to unbound, while the tag still advertises the claim. The unconditional assignment makes omission a pure function of subject data (empty = genuinely single-tenant), the only legitimate omission. Cases 2 + 5 pin both directions, so a conditional adds test surface with zero functional benefit. Keep the pin as written.

## Q2 — nil-when-absent roles discipline: conclusion correct, RATIONALE FACTUALLY WRONG

This is the one material defect. The design states (§3.1 item 2, F3 row): *"omitempty omits only nil slices, not empty non-nil ones; the fail-open path must assign nil, never `[]string{}`, or a spurious `roles: []` claim leaks"* and *"(omitempty does not drop empty slices)"*. Empirically disproven on this repo's Go:

```
nil    -> {}                         // omitted
[]     -> {}                         // omitted  <-- design claims this leaks
["a"]  -> {"roles":["a"]}
```

`encoding/json`'s `omitempty` drops **any** zero-length slice — nil or empty non-nil — and `signCompactJWS` marshals via `encoding/json` (issue_payload.go). Consequences:

- The phantom failure mode (`roles: []` leaking) cannot occur under the pinned contract. The empty-slice-vs-absent ambiguity the review asks about is already fully resolved by `omitempty` itself: the wire carries either a non-empty `roles` array or no key. The decoded claim-map assertions (case 9-negative, case 10) hold even if R0 assigned `[]string{}`.
- The nil discipline is therefore a *sufficient-not-necessary* condition for byte-identity. It is still the right pin — it keeps the struct-level contract unambiguous (nil = no roles source vs. assigned-empty, which is a real distinction in `Subject.Roles`/memory-provider semantics), and it preserves byte-identity if the tag is ever touched — but it must be re-justified.
- **Why this matters for a contract-pinning doc:** the sibling R0 module implements from this document. The wrong rationale invites two failure directions: an implementer adding redundant machinery (custom marshaler, wire-visible guard) to "force" omission, or a later reviewer discovering the doc is wrong and "fixing" it by relaxing the discipline or dropping `omitempty` — which would then make nil-vs-empty wire-visible. Correct the doc to: *"omitempty omits both nil and empty slices; nil-when-absent is kept for struct-level determinism and tag-change robustness, not because omitempty would leak `roles: []`."* Fix in §3.1 item 2 and the F3 row. (Note: the pinned behavior is thus more robust than the doc claims — no security impact either way.)

## Q3 — F1 and F2: CONFIRMED, no cross-tenant leak, no isolation weakening

- **F1 (R0-absent red-split):** the harness mints from a real server where the claim is bound to the served client (verified: all 8 grant stamps), and asserts `tenant_id == CLI-created ID`. R0 pins projection of `TenantID` and optional `Roles` only — no tenant name/slug/status metadata is projected, so no tenant data flows into tokens. The split is loud, case-scoped, and explicitly reported; non-R0 assertions stay green, so the split cannot mask kid/scope/client_id regressions. The test never tolerates a missing or wrong claim for a bound client — it is the boundary pin, not a boundary relaxation.
- **F2 (fail-open roles):** the error path emits nothing (roles nil) — a failed lookup cannot project cross-tenant data; the lookup is subject+client-scoped (mesh_authz.go:326 precedent); roles are advisory and never gate issuance (AGENTS.md advisory-signal semantics). Case 10 pins the response byte-identical to the no-roles case, so assigned-none vs lookup-failed vs unwired are indistinguishable at the wire — exactly the fail-open-with-audit pattern the repo mandates for advisory signals; detail goes only to audit. This is the only issuance-outcome-affecting mode, and the pin is correct.
- One addition for the joint gate: the design says "detail only in audit" but never names the audit event. R0 must add one (classified per the `auditreport` discipline); the pin should reference it so the gate verifies the audit half of the fail-open, not just the response half.

## Q4 — Oracle safety across the 10 failure modes: CONFIRMED, no regression

Audited all 10 against the AGENTS.md oracle surfaces (`invalid_grant` / `invalid_request_uri` / `invalid_token` / `invalid_client` / register-401 / revoke-200 / `{"active":false}` / `unsupported_provider` / dummy bcrypt / 404 `session_invalid` / `mfa_invalid`):

| Mode | Oracle surface touched? |
|---|---|
| F1, F3, F5 | Claims-only, test-side or `iss` (RFC 9207 pin) — no error-path change |
| F2 | The only issuance-outcome mode — pinned byte-identical (no new distinguishable state) |
| F4 | Fixture bug; product treats nil validator as "grant not supported" (pre-existing), and the seam is already oracle-hardened ("Every failure collapses to the same opaque error", token_jwt_bearer.go:33) |
| F6, F7, F9, F10 | Env hygiene, CLI display, CI reporting, CLI exit codes — none are credential-endpoint surfaces |
| F8 | `authorization_pending` is a normal OAuth protocol state, not an internal-cause disclosure |

No mode adds an error response to a credential endpoint, changes distinguishability of an existing error, or alters introspection/revocation/register behavior; the harness asserts only 200-response claim sets and CLI exit codes. One minor gap: §3.2's in-test JWT-bearer validator should be pinned to collapse all assertion failures to a single opaque error, mirroring the seam's documented hardening — not a product risk, but the matrix row should genuinely exercise the oracle-hardened path.

## Verdict

Q1, Q3, Q4: **confirmed as designed**. Q2: the discipline survives, but the design's stated mechanism is empirically false and must be corrected in §3.1 item 2 and the F3 row before this document serves as the R0 contract pin (both corrections are rationale-only — no behavioral change). Plus the two small additions: name the F2 audit event, and pin the test validator's opaque-error collapse.

Want me to apply the two doc corrections and the two additions?
