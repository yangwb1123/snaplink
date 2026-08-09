Verification complete. Report written to `docs/architect-analysis/auto/runs/register-the-provisioner-s-fixed-platform-contro-93270f5a/artifacts/adversarial_review-9c87f3a7/meta/deploy_tree_migration_verifier.md` (sibling of the security review that flagged FM-2).

## Verdict on the three legs

**1. FM-2 leg — the out-of-band provisioner-client registration path does NOT exist in the compose tree; it must be added.** The security review's caveat is confirmed, and the design's §4.3/§7.4 claim ("compose registers it out-of-band via secret bind-mount at compose.yaml:248, same as the k8s overlay") is factually wrong on both counts — the bind-mount carries the client *secret file*, not a registration, and the k8s overlay works only because `ops/deploy/k8s-distributed/config.yaml:59-65` enables `admin:` + `client_registration:` (real operator-side paths), which compose enables neither. Exhaustive surface check in the compose tree:
- **Admin gRPC `ClientAdminService`**: off — no `admin:` block → `wireAdminMW` nil (build_app.go:292) → `registerAdminGRPCServices` skipped (main_servers.go:136-139)
- **RFC 7591 DCR**: off — no `client_registration:` block → `/register` 501 (build_app_oidc.go:72)
- **etcd**: boot-time config overlay only (config/etcd/source.go) — an etcd-declared client hits the *same* boot-closed gate (FM-1 shape), never a runtime 400
- Client store is in-memory, seeded from config — no runtime store to register into

So the compose runbook-as-written fails with `401 invalid_client` (client absent), not FM-2's `400 invalid_scope`. No in-repo tree has both registry-enabled *and* an out-of-band path — FM-2 is hypothetical in-repo. **Closure (minimal)**: declare the provisioner client in compose `config.yaml` `clients:` as part of R3 — measured gate-clean, mirrors `settings.env` client id, and converts FM-2 into FM-1 (the only registration path in compose). The README quickstart (lines 29-38) also needs the registration step.

**2. G5 flip safe only after R3 — CONFIRMED empirically** (`bin/sso-server --validate-only` matrix on scratch copies):
| State | exit |
|---|---|
| R3 (+3 extras) | 0 |
| R3 + provisioner client declared | 0 |
| client declared, **no R3** | **1** — `client "snaplink-audit-provisioner" allowed_scopes "audit:platform:cross_tenant" is not registered by oauth.scope_registry (matrix + protocol scopes + extra_scopes)` |

The boot-closed membership gate (config_oauth2.go:58-63) makes "scopes → registry → client" the only safe order; R3 is precisely what turns the flip from exit-1 to exit-0.

**3. Rollback — CONFIRMED complete.** Removing the 3 tokens restores `config.yaml` byte-identical to HEAD (measured `True`) and `--validate-only` exits 0 (the 3 existing clients' scopes stay covered by the 8-row matrix + 2 extras); tests are additive/removable with R3; R5 is the intended drift canary.

**One extra drift found en route**: design §8 row 2's error-string example says `audit:policy:read`, but the gate reports the *first* unregistered token in `AllowedScopes` order — measured `audit:platform:cross_tenant` (the R2 subtest assertion should use that). Report lists it alongside the two known nits. No Go files touched; validation used scratch copies under `/tmp/fm2/`.
