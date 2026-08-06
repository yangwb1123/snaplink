Delivered: `docs/architect-analysis/auto/runs/b4-1-emit-tenant-id-roles-in-buildaccesspayload--7df5e5c3/artifacts/design-a77de8a6/task-1-named-test-plan.md`

All anchors were re-verified against HEAD `c676f974` (test homes, mint sites, line numbers). Each of the six asks is answered:

**1. Named tests with file targets, predicates, non-vacuity** — 21 entries across sections 1–4, each with exact assertion expressions and a pre-change failure proof (most are compile-gated: `core.Subject`/`core.Client` have no `Roles` field today; C4 is the one test that fails at runtime on HEAD — `issue_payload.go:36` copies `subject.Claims` into `ext` unscrubbed, so `ext.tenant_id == "evil"` is observable today).

**2. Count drift (3+1 vs 3+2)** — the unnamed second rootcov wire test is **R2, the refresh-mint claims test** (`TestRcov_RefreshGrant` extension). Rationale: the workstream pins roles at exactly two mint sites (`token_client_credentials.go:40-53`, `refreshRotatedSubject` at `token_refresh.go:273-291`), and the "roles only on cc+refresh" constraint is unprovable without a wire test at the second site; discovery-sweep (T-2's domain) and introspection no-echo (an absence pin) are ruled out.

**3. Handler plumbing test** — P1 `TestRcov_ClientRolesFlowThroughHandler` (rootcov): seeds roles/no-roles clients via `AddSeed`, asserts order-preserved roles, omitempty byte-identity for the nil-Roles client, and the login leg (tenant_id present, roles absent — cc+refresh confinement).

**4. Mint-gate negative** — M1 with four subtests: signer configured outside the allowlist → 500 `ErrNoTokenStrategy` shape with no token (fails on HEAD, which mints 200 with a rogue `iss`), namer-error fail-closed, allowlisted positive, and empty-allowlist no-gate (S4 matrix row).

**5. Trusted-proxy restatement** — T1–T3 table: all three issuer assertions invert to `issuer == sso.DefaultIssuer` (failing on HEAD), with the trust-gate coverage moved onto base-derived `authorization_endpoint` assertions (untrusted = base URL; unset-knob/trusted-edge = XFH-honored), per the F-4 requirement.

**6. Cross-repo B1-7/B1-8 landing** — K1 (in-repo `WithClientTenant` testkit option + fixture asserting top-level claims via HTTP Basic auth) plus a conjunctive landing predicate X1∧X2∧X3: mint-token script with `--assert-claims`, `AUDIT_ALLOW_DEV_AUTH=false` in the compose overlay, and a wire-level HTTP 422 on envelope/token tenant mismatch.

Also included: I4 identified with T1 (the never-Host proof), the D1 DCR self-assign exclusion pin (security S1 — must land in the same change as `Client.Roles`), per-signer ID-token absence folded into C1–C3, placement/budget notes (options.go 490 not options_security.go 500/500; sso.go +1 → 500; config key beside `config_load.go:184`), and the golden-then-claims-then-issuer ordering. No Go files touched, so no build gates apply.
