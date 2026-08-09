All verification is complete. Here is my independent design-gate assessment.

## Blocking finding: FM-2 leg / provisioner-client registration in compose (ops_deployment_reviewer, corroborated by security_engineer)

**I independently confirmed every leg of the finding against the repo at HEAD `6798eb2a`:**

1. **The bind-mount is a secret file, not a registration.** `compose.yaml:246-248` mounts `${AUDIT_PROVISIONER_SECRET_FILE:-./secrets/audit-provisioner-client-secret}` into `/run/secrets/audit-provisioner-client-secret` — the client *secret* only. Nothing registers the client `snaplink-audit-provisioner` on the server.

2. **Compose has zero out-of-band registration surfaces.** `ops/deploy/compose/config.yaml` (read in full) has no `admin:` block and no `client_registration:` block; server code confirms the consequences: `wireAdminMW` returns nil when `!cfg.Admin.Enabled` (build_app.go:292), and `newGRPCServer` skips `registerAdminGRPCServices` when `a.adminMW == nil` (main_servers.go:136-139); DCR is only wired when `cfg.ClientRegistration.Enabled` (build_app_oidc.go:72). etcd is a boot-time config overlay; the client store is in-memory, seeded from `clients:`. The config declares exactly three clients — none is the provisioner.

3. **The k8s comparison is real and the design's "same as the k8s overlay" is false.** `ops/deploy/k8s-distributed/config.yaml:59-65` enables `admin:` + `client_registration:` — actual operator-side registration paths — which the audit-provisioner overlay's README ("Grant exactly audit:platform:cross_tenant audit:policy:read audit:policy:write") relies on. Compose enables neither.

4. **The runbook-as-written fails with `401 invalid_client`, not FM-2's `400 invalid_scope`.** The compose README quickstart (lines 29-38) instructs only the secret-file install and `docker compose --profile audit-provisioning up`; no client-registration step exists, and no path can create the client. The `400 invalid_scope` mint leg is hypothetical in-repo (security_engineer: "the config-declared leg (FM-1) is the one measured live").

5. **Unresolved and not rejected with evidence.** The design still asserts the wrong claim in four places — §1 "Gap confirmation" ("registers out-of-band (as the k8s overlay directs)"), §4.3 ("compose registers it out-of-band via secret bind-mount at compose.yaml:248, same as the k8s overlay"), §6 FM-2 ("pre-change live gap in compose"), §7.4 ("this direction's compose registration is the reference for the G5 flip"). The requirements §3 non-goal is an explicit scope statement, but its premise ("compose registers the client the same way (secret bind-mounted at compose.yaml:248)") is measured false — an explicit rejection on false evidence is not an evidence-backed rejection. DECISIONS.md has no post-review adjudication; the design was only amended for the three minor nits.

**Consequence:** after R3 lands, the compose audit-provisioning profile still cannot run the provisioner (client absent, no path to register it), so the direction's T-8(d) end-to-end completion claim does not hold in the very tree it modifies, and §7.4's "reference for the G5 flip" is a reference that cannot mint. The ops reviewer's closure is minimal and measured gate-clean (client declared in compose `clients:` within R3 → `--validate-only` exit 0; one README quickstart step).

## Non-blocking findings — all resolved, verified in-place

- Command-path typo (`go test .` → `go test ./cmd/sso-server/`): fixed in requirements §6/§11; design §7/§8 already correct. ✓
- `srClientAny` citation: design §8 now cites lines 60-65 (verified against `test/scope_registry_test.go`). ✓
- Error-string drift: design §8 row 2 pins the verbatim first-token error (`audit:platform:cross_tenant`), matching the measured gate output. ✓
- File budget: R5 split into its own file; §9 table holds all files under 500 with margin. ✓
- Security invariants (byte-identical 400, default-off byte-compat, extras→registry-only, no new surface, R4 negative sound): all verified and consistent with my repo checks. ✓

VERDICT: FAIL - The blocking FM-2 finding is unresolved: the design's claim that compose registers the provisioner client out-of-band "via secret bind-mount at compose.yaml:248, same as the k8s overlay" is factually wrong (compose has no admin gRPC, no DCR, and no runtime client store; the bind-mount carries only the secret; k8s works only because k8s-distributed enables admin+client_registration), so the compose runbook fails with 401 invalid_client and no evidence-backed rejection exists — the design must either declare the provisioner client in compose `clients:` within R3 plus the README quickstart step (measured gate-clean), or document an evidence-based rejection.
