All reviewer-cited sites verified exactly (`accessors_feature_gates.go:258–260` break-glass Subject with `TenantID: ""` and `core.BreakGlassImpersonationClientID`; silent-renewal Subject at `handle_silent_renewal.go:210` with `TenantID: client.TenantID`; agentidentity `grant.go:185`). The deliverable is complete.

## Deliverable

**`docs/architect-analysis/auto/runs/emit-tenant-id-roles-in-buildaccesspayload-via-s-eacdbc35/artifacts/design-a77de8a6/task-3-acceptance-mapping.md`** — the missing A1–A9 + A-new-1…6 acceptance mapping, closing the artifact-completeness gap both reviewers flagged.

**A1–A9** (ties T-2's five checks, T-8(a), fail-open variant, R4 mode-off, R5 goldens):
- **A1** `tenant_id == client.TenantID` → extend `ed25519_rfc9068_test.go:69` / `ecdsa_jwt_issuer_test.go:60` / `rsa_jwt_issuer_test.go:20` + `test/auth_code_test.go` (`jwtAllClaims:253`)
- **A2** roles wire-equality → new `domains/permissions/role_claim_wire_test.go` (mirror pin: `permissions.Role` ↔ `core.RoleClaim` identical JSON bytes, drift-impossibility) + issuer emission + E2E
- **A3** kid unchanged → `TestEd25519JWT_KidIsDeterministic:161` + A9 header goldens
- **A4** iss allowlist/unlisted Host → `rootcov_discovery_test.go:40`, `rootcov2_discovery_test.go:247`; 503/400 split per security §1.3(b)
- **A5** empty-case pre-change goldens (nil **and** empty-slice roles) → new `infrastructure/defaultimpl/claim_byte_identity_test.go` with capture procedure (§5: pre-change capture, `fixedClock`, jti-normalized payload skeleton, `-update` flag)
- **A6** T-8(a) `/token` six-claim contract → `test/auth_code_test.go` harness + segment-decode pattern (`introspection_jwt_test.go:107`)
- **A7** provider-outage wire-collapse + audit leg → new `domains/permissions/roles_for_subject_test.go` (`failingProvider:44` + `MemorySink` pattern)
- **A8** R4 mode-off differential → paired-server discovery comparison at `rootcov_discovery_test.go:40`
- **A9** R5 goldens across all three issuers (empty + new-shape cases)

**A-new-1…6** (task-2 §8): cap (unit + wire + E2E), code-length/empty omission, 16 KiB byte backstop, introspection echo (`handle_introspect_test.go:111`), fail-open metric (`metrics_e2e_test.go`), mesh `X-Auth-Roles` parity (`mesh_authorize_test.go` + `rootcov_misc_test.go:26`).

**Parity rows** (enumeration completeness): break-glass headline (P-BG → `break_glass_routes_test.go:269`), plus silent renewal, webauthn, agentidentity, kerberos; openapi.yaml:4807 doc-correction row.

## Verification

- **Every home exists** — all 18 homes confirmed with function names + line numbers (§6 table); the five reviewer-flagged issuance sites re-verified line-exact.
- **60-file ceiling respected** — `interfaces/sso` is at exactly **60 non-test files**; every mapped home there is an existing `_test.go` (110) or an extend-only file (`options.go:130` `WithMaxScopeCount` sibling). New files are `_test.go` only, which AGENTS.md exempts.
- **Other ceilings** — `domains/permissions` (10) and `internal/handler/tokengrant` (10) at ceiling: `RolesForSubject` extends existing files, no new non-test Go anywhere.

No `.go` edits were made, so no repo gates were triggered; the doc is pure mapping.
