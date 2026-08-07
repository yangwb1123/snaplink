Design complete. Summary of the work:

## Verification outcome

All evidence claims were re-checked against the working tree at HEAD (`go build`/`go vet` clean). **Every citation in the requirements spec confirmed**, including the less obvious ones: all 8 grant-path `TenantID: client.TenantID` stamps, the `Subject.TenantID` doc comment "NOT a token claim", `resolveIssuer`'s Host fallback at server_discovery.go:251-258, the absent `tenant_id` in `clients.proto` (zero refs) with the admin_clients.go:59 comment, `WithIssuer` wired at config_load.go:308, and both engineering ceilings (16/16 `cmd/sso-ctl` subdirs, 60 non-test files in `interfaces/sso`).

**One material gap found in the evidence** — the spec's claim that a jwt-bearer e2e driver exists is overstated:
- `test/jwt_client_assertion_test.go` tests **private_key_jwt client authentication** (`grant_type=client_credentials` + `client_assertion`), not the RFC 7523 JWT-bearer *grant*.
- `tokengrant.JWTAssertionValidator` has **zero concrete implementations** in the repo; no test anywhere drives `GrantJWTBearer`.
- Design consequence: the matrix's jwt-bearer row requires a real in-test Ed25519 validator wired via the existing `sso.WithJWTBearerGrant` seam (~40 lines more fixture than the other six grants).

## Deliverable

`docs/architect-analysis/cmd-sso-ctl-entitiescmd-b4-1-tenant-claims-design.md` contains:

- **API changes** — zero production API in this module (CLI byte-identity pinned, T-9); two test files; the R0 enabling-dependency contract pinned exactly (unconditional `TenantID: subject.TenantID` assignment beside `ServingRegion`, **nil-when-absent** roles discipline since `omitempty` doesn't drop empty slices, claim-map assertions so the harness compiles pre-R0).
- **Compatibility constraints** — no new package, no upward imports, env isolation via `t.Setenv`, no compile coupling to R0.
- **Failure modes** — 10 enumerated (F1 R0-absent red-split, F2 fail-open roles, F4 unwired JWT-bearer seam, F5 Host-derivation regression, F9 pre-existing Python fan-out failure, …).
- **Migration steps** — two-phase joint gate G1 sequencing with exact rollback (delete the two test files).
- **Acceptance mapping** — all 12 Given/When/Then cases mapped to named test functions with per-assertion R0-dependency flags (RED-pre-R0 / GREEN), including the corrected insight that the unbound-client case (case 5) is a GREEN-always regression guard for R0's `omitempty` behavior.
