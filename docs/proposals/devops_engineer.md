I have completed the verification pass. Here is the DevOps review.

---

# DevOps Review — grpcserver transport governance design + build/delivery/deployment automation

**Reviewed revision:** HEAD `453ae5fc` (2026-08-02, `[pi-batch] Stage: design`). Deployment assets are unmodified at HEAD; the design implementation itself is in-progress in the worktree (201 modified files, including `cmd/sso-server/serverbuildplatform/build_governance.go`). Design doc: `docs/auto/interfaces-grpcserver-transport-governance-design.md` (Verified present, 30 KB).

**Checks that actually ran for this revision (Verified):** full static read of `.github/workflows/*.yml` (ci, release, trivy, codeql, engineering, benchmark-gate), `.goreleaser.yaml`, `Dockerfile`, `Dockerfile.full`, `Makefile` release/deploy targets, `docs/RELEASE.md`, `docs/deployment.md`, `docs/dr-framework.md`, and every `ops/deploy/` asset (k8s, k8s-prod, kustomize base/dev/prod, k8s-admission, helm, terraform, compose, ha-test, baremetal-ha, openresty, grafana, benchgate). Executed: `go run ./cmd/sso-server --config=ops/deploy/baremetal-ha/sso/config.yaml --validate-only` (PASS), a synthetic unknown-key config `--validate-only` (**ACCEPTED** — drift gate gap), `./bin/sso-server version` (reports version/build time/git hash/dirty marker), `git remote -v` / `log` / `status` / `tag` (none), `.dockerignore` existence (absent), `grep ghp_` across tracked sources (clean — token lives only in `.git/config`).
**Not run:** `make ci`, `docker build`, `kustomize build`, `terraform validate`, `helm lint`, e2e, ha-test compose drill. Claims about those are labeled accordingly.

---

## 1. Supported deployment-path and artifact inventory

| Asset | Evidence | Status |
|---|---|---|
| Root `Dockerfile` (sso-server + sso-mcp) | Multi-stage, distroless/static:nonroot, `USER nonroot`, no baked config, optional FIPS arg, `-buildvcs=true` + ldflags provenance | **Verified** (read in full). Built in `ci.yml` docker job — smoke only, **no push, no scan** |
| `Dockerfile.full` (root + `ops/deploy/`) | `COPY dist/modules/full/snaplink` — profile-built binary image | **Partial**: `dist/modules/full/` exists locally (Verified via ls), but no CI build, no registry target, no scan; `python cli.py configure --profile full --version … --build` is the documented prerequisite (deployment.md §1) |
| GoReleaser binaries `sso-server`, `sso-ctl`, `sso-mcp` | 5-OS matrix, sha256 checksums, SPDX-JSON SBOMs, keyless cosign signs + docker_signs, dockers → `ghcr.io/snaplink/{sso-server,sso-mcp}` | **Verified config; Unknown target** — org existence never verified; see C1/H1 |
| `bin/{sso-server,sso-ctl}` | Local build Jul 30; `version` shows git hash + dirty marker | **Verified** local-only; not an artifact path |
| Kustomize `base` + `overlays/dev` | 1 replica, memory backends, probes on `/livez`/`/readyz` outside rate limit, configMapGenerator-hashed rollouts | **Verified**; rendered in CI (`ci.yml` kustomize job) |
| Kustomize `overlays/prod` (canonical) | 3 replicas, HPA, PDB, zone spread, 40 s drain, tolerant readiness, all hot state → Redis Cluster, durable → Postgres-wire, coordination/registry → etcd | **Verified** (read); rendered in CI, but not self-sufficient (F3) and `secretGenerator` ships `CHANGE_ME` literals |
| Legacy `k8s/`, `k8s-prod/` | README: deprecated, "do not apply as-is" | **Verified**; **not rendered in CI** |
| `k8s-admission/topology-policy.yaml` | ValidatingAdmissionPolicy + scale policy (CEL, failurePolicy Fail, Deny+Audit) | **Verified** (read in full); **not part of the prod overlay** — separate apply, only referenced in `kustomize/README.md:49` |
| Helm chart `ops/deploy/helm/sso-server` | Deployment/Service/Ingress/HPA/PDB/ConfigMap/SA; values.schema.json; probes on `/livez`,`/readyz` | **Verified** (values + deployment template read); **never linted/rendered in CI**; `image.tag: latest` default; no config-secret mechanism (only `imagePullSecrets`) |
| Terraform `ops/deploy/terraform` | VPC / EKS / RDS (multi-AZ, deletion protection, 7-day retention in prod) / ElastiCache modules; dev+prod tfvars; **remote state backend commented out** | **Verified** (main.tf/variables read); `terraform init -backend=false && validate` runs in CI; apply/plan never runs anywhere |
| Compose `ops/deploy/compose` | sso-server + etcd + optional prometheus/grafana; config.yaml in `config-validate-all` | **Verified** |
| `ha-test/` (new) | `compose.yaml` (redis 7 + postgres 16 + etcd v3.6.4) + `run.sh` → `test/ha` `TestRealMultiReplicaFailureRecovery` | **Verified** (files read; test not executed here — needs docker) |
| `baremetal-ha/` | HAProxy/Patroni/Redis Cluster/keepalived VM templates + RUNBOOK | **Verified**; README self-declares blockers (obsolete `server.addr`/`server.trusted_proxies` — confirmed still present at `sso/config.yaml:15,19`; `wget` healthcheck against a distroless image that has no `wget`; HAProxy `:443` stamps forwarded HTTPS without a cert; redacted smoke.sh) |
| OpenResty edge | Ed25519-only prototype verifier; README explicitly disclaims production use | **Verified** — non-goal for production |
| Observability | `/metrics` outside rate limit (observability.md:99-100); 11 Prometheus alerts in `grafana/alerts.yaml`; audit hash_chain | **Verified** |

---

## 2. Pipeline table

| Stage | Current evidence | Gap | Proposed gate | Owner |
|---|---|---|---|---|
| Source control | PR + main workflows; `engineering.yml` gates (filesize/complexity/architecture/invariants/exemptions/self-test/ADR/coverage) | **Live PAT in `git remote` URL (C1)**; no branch protection evidence | Revoke token; credential helper; protection on main + tags | Maintainer |
| Build | `ci.yml` test job: harness, gofmt, vet, build, modules check/smoke, race tests with Postgres service, config-validate-all; nested-module matrix; e2e covered via `go test ./...` | `sdk-surface-check`, `profiles-evidence`, `licenses-check` run **nowhere** (F4); `make ci` never run as a unit | Wire missing `make ci` members into workflows; add a "make ci in one shot" job | Maintainer |
| SAST/SCA | govulncheck (root+modules), gosec SARIF, CodeQL security-extended, trivy fs (vuln+secret+misconfig) | **All report-only** — nothing blocks on findings; trivy scans fs, **not the built image**; no `.dockerignore` (build context ships `.git` + ~700 MB) | `.dockerignore`; trivy secret scan hard; CRITICAL policy decision; `trivy image` in release | Maintainer |
| IaC | kustomize render dev+prod (+diff), terraform init/validate | Helm chart unvalidated; legacy `k8s/`+`k8s-prod/` and admission policy YAML unrendered; no `terraform plan`/apply; prod overlay not self-sufficient (F3) | helm lint/package in CI; render every overlay + admission policy; plan in CI with OIDC; preflight script | Maintainer |
| Release | `release.yml` on `v*` tag → goreleaser + cosign + SBOMs; `release-check`/`release-snapshot` in Makefile | **Config publishes while the workflow header claims dry-run (H1)**; no environment/approval/reviewers; no SLSA provenance (RELEASE.md explicit); per-profile artifacts unpublished | Resolve H1; environment protection; first deliberate release cut; decide SLSA | Maintainer |
| Deploy | Manual kubectl/helm/terraform; kustomize prod overlay; admission policy separate apply | No staging env (terraform + kustomize have dev/prod only); no promotion path; secrets are `CHANGE_ME` literals; image tags `prod`/`latest` nothing publishes | Staging overlay + smoke + approval; digest pinning; managed secrets (external-secrets/sealed-secrets) | Maintainer |
| Post-deploy | `/livez` always-200, `/readyz` aggregates redis/postgres/etcd/bus/signing-key-aggregation readiness (Verified call sites in `cmd/sso-server/build_app_*.go`); grafana alerts; `test/ha` recovery drill; `make dr-drill` | No automated post-deploy smoke in CI/CD; baremetal `smoke.sh` redacted; alert thresholds are starting points | Wire smoke into deploy pipeline; rehearse ha-test + dr-drill pre-release | Maintainer |

---

## 3. Findings (by severity)

### C1 — Critical · Live GitHub PAT embedded in git remote URL (pre-existing, unremediated)
- **Evidence:** `git remote -v` (ran this revision) shows `remote.github.url = https://yangwb1123:ghp_…@github.com/yangwb1123/snaplink.git`. Flagged as M2/F1b in prior reviews (`docs/architect-analysis/auto/interfaces-apidocs-devops-review.md:87`); grep of all tracked sources for `ghp_` is clean — the token lives only in `.git/config`, plus any process that reads it (hooks, logs, backups). No `.dockerignore` exists (Verified), so the Dockerfile's `COPY . .` carries `.git/config` into builder layers.
- **Impact:** any workspace reader extracts a likely write-scoped GitHub credential; it makes the H1 tag-push release path mechanically executable; it enters image build contexts/caches.
- **Remediation:** revoke the token in GitHub settings now; switch remotes to SSH or a credential helper; audit CI secrets for the same value; add `.dockerignore` (`.git`, `bin/`, `dist/`, `sso-server`, `sso-ctl`, `.venv`, `__pycache__`, `**/.env`) and pass `GIT_HASH` only via build-arg.
- **Validation:** `git remote -v` shows no `ghp_`; `docker build --no-cache` context size drops by ~700 MB; `git grep -c ghp_` on tracked sources stays 0.

### H1 — High · Release pipeline publishes but is documented as dry-run; no approval or protection
- **Evidence:** `.goreleaser.yaml` has `release.disable: false`, `dockers` → `ghcr.io/snaplink/sso-server[:version/:latest]` + `sso-mcp`, `signs` + `docker_signs` (cosign), and `release.yml` runs `goreleaser release --clean` on `on: push: tags: ["v*"]` with `contents: write`/`packages: write`. The workflow's own header comment still says "Today release.disable=true … exits without publishing" — **stale** (Verified both files in full). No `environments:` block, no required reviewers, no branch filter. Org `ghcr.io/snaplink` existence: **Unknown** (no tags exist locally; `git tag` empty).
- **Impact:** a single `v*` tag push (trivially possible given C1) publishes binaries + multi-arch images + cosign signatures to a registry target nobody has consciously approved.
- **Remediation:** decide dry-run vs live; if live: confirm/create the ghcr org, add environment protection with reviewers, fix the workflow header, and cut the first release deliberately with an `--snapshot` rehearsal.
- **Validation:** `make release-snapshot` local; then a test tag on a scratch remote; verify `cosign verify` output and the GitHub Release page before any real tag.

### H2 — High · No hard security gate in CI; no image scan; no `.dockerignore`
- **Evidence:** `ci.yml` govulncheck `continue-on-error: true`; gosec `-no-fail`; trivy `exit-code: "0"`; CodeQL non-gating; `docker` job builds without push; `trivy.yml` scans the filesystem, never the built image; `.dockerignore` absent (Verified).
- **Impact:** a CRITICAL CVE, a committed secret, or a misconfigured Dockerfile can merge and ship; the C1 credential rides in every build context.
- **Remediation:** (1) `.dockerignore`; (2) trivy `secret` scanner as a hard gate (deterministic, low-noise); (3) policy: govulncheck/gosec CRITICAL blocks; (4) `trivy image` on the release image (Makefile `docker-scan` already exists).
- **Validation:** introduce a test secret in a PR → CI must fail; `make docker-scan` on a release image shows HIGH/CRITICAL findings only from the documented backlog.

### M1 — Medium · `--validate-only` silently accepts unknown config keys; deploy assets drift under CI
- **Evidence:** **Executed this revision:** `go run ./cmd/sso-server --config=ops/deploy/baremetal-ha/sso/config.yaml --validate-only` → PASS, despite that file still using obsolete `server.addr`/`server.trusted_proxies` (lines 15/19) while the real keys are `server.listen` (`config/config_server.go:13`) and `security.trusted_proxies` (`config/config_metrics_security.go:33`). A synthetic config with a bogus top-level key also validated → **UNKNOWN KEY ACCEPTED**. So `make config-validate-all` (a CI member) does not catch renamed/misspelled keys — the exact drift class AGENTS.md calls out.
- **Impact:** a production config typo in a security-relevant key (e.g. `security.trusted_proxies`, rate-limit, backend selection) silently no-ops while CI stays green; baremetal-ha's declared trust boundary (`trusted_proxies`) is currently ignored by the running server.
- **Remediation:** strict unknown-key rejection (or warning + drift lint) in `--validate-only`; fix `baremetal-ha/sso/config.yaml` to `listen`/`security.trusted_proxies`; add a negative test asserting a bogus key fails.
- **Validation:** `--validate-only` with one bogus key must exit non-zero; re-run `make config-validate-all`.

### M2 — Medium · CI enforces a subset of `make ci`; helm/admission/legacy IaC unvalidated
- **Evidence:** grep of all workflows: `sdk-surface-check`, `profiles-evidence`, `licenses-check` run nowhere; no helm lint/package job; the kustomize job renders only `kustomize/overlays/{dev,prod}` — legacy `k8s/`, `k8s-prod/`, and `k8s-admission/topology-policy.yaml` are never rendered or CEL-checked; the admission policy is not included in the prod overlay's `resources` (separate apply per `kustomize/README.md:49`), so a prod rollout that skips it silently loses the multi-replica coherence guard. This matters directly for the design: D1/D2 changes ride `sdk-surface.json` + OpenAPI, which are validated by `route-contract`/`capabilities-check` in CI — but the same CI never runs the new gRPC governance surface against a built binary.
- **Impact:** gate drift goes unnoticed; the design's load-bearing rebalance lands with only local validation; admission policy and prod overlay can diverge.
- **Remediation:** wire the three missing `make ci` members into `ci.yml`; add helm lint + a render of every overlay including the admission policy; consider kubeconform/CEL unit checks; bundle the admission policy into the prod overlay (or a required second apply with a guard).
- **Validation:** a PR that breaks `sdk-surface.json` schema or the helm chart must go red.

### M3 — Medium · No staging environment or promotion path; release-to-prod is a manual leap
- **Evidence:** terraform `environments/` = dev, prod (Verified listing); kustomize overlays = dev, prod; no staging overlay, no promotion pipeline, no approval step between tag and prod; prod overlay image tags are `prod`/`latest` — nothing publishes them (H1/F3).
- **Impact:** the first production rollout will be unrehearsed end-to-end; no environment parity evidence exists.
- **Remediation (proportional):** a staging overlay with the same shared backends, a documented promote checklist (§4), and one rehearsed staging apply+smoke before the first prod cut.
- **Validation:** staging deploy + smoke + rollback drill recorded in CI artifacts.

### M4 — Medium · gRPC back-channel silently plaintext-capable; prod overlay configures no gRPC TLS
- **Evidence:** gRPC TLS is enabled only when cert/key config is set (`cmd/sso-server/main_servers.go:172`, `tlsCert != "" && tlsKey != ""` — Verified); the prod overlay's config and the helm chart expose 8081 with no TLS material. The design's D4 (`admin.grpc_tls: required|ephemeral|plaintext`, default `required` = startup refusal) is exactly the missing guard — currently **Proposed**, not implemented (no `grpc_tls` key in `docs/config-reference.md`).
- **Impact:** today, a config typo or omitted cert silently serves admin gRPC in plaintext on the cluster network; the arming guard the design proposes (`GRPCGovernanceArmed()` fail-closed on wiring drift) does not exist yet.
- **Remediation:** land D4; meanwhile, prod overlay must either configure gRPC TLS or explicitly document plaintext-on-trusted-network as an accepted posture; add a startup warning.
- **Validation:** boot with `admin.grpc_tls: required` and no cert → refuse to start; e2e gRPC test over TLS only.

### L1 — Low · Provenance is signatures+SBOMs, not SLSA; per-profile artifacts unpublished
- **Evidence:** `docs/RELEASE.md`: "The release pipeline does not currently produce a SLSA provenance statement. Do not describe signatures/SBOMs as provenance." `Dockerfile.full` (root + `ops/deploy/` copies) builds `dist/modules/full/snaplink` but no CI job, no registry path, no scan covers it; goreleaser publishes only the stock binary matrix.
- **Impact:** supply-chain claims must stay scoped; the "full profile" image is buildable but not distributable as-is.
- **Remediation:** decide whether profile images are release artifacts; if yes, add a goreleaser/docker entry + scan; consider SLSA provenance as a follow-up.
- **Validation:** release assets list shows either profile images with SBOMs or an explicit non-goal note.

### L2 — Low · Unpinned tooling and floating base images
- **Evidence:** `engineering.yml` hardcodes `go-version: '1.26'` (ci.yml uses `go-version-file`); helm `image.tag: latest`/`appVersion: latest`; kustomize base `:latest`; distroless base not digest-pinned; buf 1.69.0, golangci v2.1.0, kustomize v5.6.0 are pinned (good).
- **Remediation:** digest-pin base images; default helm tag to a semver; use `go-version-file` in engineering.yml.
- **Validation:** `docker build` twice yields identical digest for a pinned base; helm template shows a pinned tag.

### L3 — Low · baremetal-ha reference blockers (documented)
- **Evidence:** README lists them; verified: `server.addr`/`server.trusted_proxies` still present (M1), HAProxy `:443` without cert stamps forwarded HTTPS, `smoke.sh` redacted placeholders, keepalived not exercisable on single host. Bonus: the compose healthcheck uses `wget` against the distroless image, which has none — but the image ships `/healthcheck` (built in Dockerfile from `test/oidc-conformance/healthcheck`), so the fix is a one-liner.
- **Impact:** this path cannot support a production claim as-is; it is honestly labeled.
- **Remediation:** when this path is needed: swap healthcheck to `/healthcheck`, fix config keys, add a real TLS cert at the edge, un-redact smoke.sh with test-only credentials.
- **Validation:** `docker compose -f ops/deploy/baremetal-ha/docker-compose.yml up --wait` reaches healthy; `smoke.sh` passes end-to-end.

### I1 — Info · Multi-replica topology evidence is genuinely strong
- **Evidence:** shared-state model is the right call for the risk model (no canary/blue-green recommendation needed): everything hot on Redis Cluster (noeviction requirement documented), durable on Postgres-wire, coordination on etcd, `cross_replica_revocation: true` fails boot without a live bus (fail-closed, Verified in config + `WithReadyCheck` wiring); CEL admission policy (Verified read) denies multi-replica without topology=multi and authoritative env overrides; PDB minAvailable 2; HPA min 3; zone spread maxSkew 1; tolerant readiness (failureThreshold 4) so a backend blip doesn't drain the fleet; 40 s drain. New this revision: `ops/deploy/ha-test/` runs `TestRealMultiReplicaFailureRecovery` against real Redis+Postgres+etcd — the strongest available evidence short of a prod rehearsal.
- **Recommendation:** rehearse the ha-test drill and `make dr-drill` before the first prod release; record results.

### I2 — Info · Backup/restore and observability exist as documentation, not as operated services
- **Evidence:** `docs/dr-framework.md` (§3) specifies per-backend mechanisms (SQLite `VACUUM INTO` via `POST /api/v1/admin/backup`, Postgres PITR/streaming, Redis RDB/AOF, etcd `snapshot save`, plus the control-plane `SnapshotReplicator` with `sso-ctl snapshot verify`); terraform RDS sets `backup_retention_period = 7` and `deletion_protection = true` in prod. Grafana ships 11 alerts with tuned thresholds pending baselines.
- **Unknown:** ElastiCache backup/retention config (not read in the elasticache module); actual backup schedules, RPO/RTO targets, and restore drill cadence are operator decisions, not repo evidence.

---

## 4. Release and rollback procedure

**Preflight (blocking items first):** resolve C1 (token revoked) and H1 (dry-run vs live decision) before any tag push. Then: `make ci` green in one shot locally *and* in GitHub Actions (wire M2 members first); `make release-check` + `make release-snapshot`; render + diff all overlays; `make config-validate-all` (after M1 strictness); `make docker-scan` on the release image; `make dr-drill` and the ha-test recovery drill green; alert baseline review.

**Cut:** tag `vX.Y.Z` on main → `release.yml` → goreleaser matrix + SBOMs + cosign. Verify: `cosign verify` on archives and images, checksums, `sso-server version` inside the image reports the tag's git hash with no dirty marker.

**Migration ordering (this product's model is single-binary, migrations at boot — Verified in `infrastructure/postgres/migrate.go` and `cmd/sso-ctl/migratecmd`):** Postgres migrations run automatically per-store at construction, forward-only and idempotent, serialized across replicas via `pg_advisory_xact_lock` (CockroachDB: SERIALIZABLE + 40001 retry) — so the rolling upgrade (`maxUnavailable: 0`) needs no separate migration step and is safe for N replicas. Pre-deploy check: read `schema_migrations_<namespace>` tables (the offline `sso-ctl migrate status` is SQLite-only — a gap for Postgres pre-checks). Fail-closed direction: a newer schema + older binary refuses to boot (`ErrSchemaTooNew`), so rollback must be validated against the migrated schema. Release ordering invariant: deploy the new image to staging first; in prod, one replica at a time and watch `/readyz` and `/metrics` between steps.

**Rollback:** revert the deployment to the previous digest-pinned image (`helm rollback` / `kubectl rollout undo` — supported because the chart/deployment is stateless). Hot state survives (Redis sessions, refresh families, jti replay sets); signing-key rotation's deferred-retire window widens, never shortens, the verify window (fail-safe, per AGENTS.md). If the rollback target binary predates the schema, restore the DB from the pre-release backup (Postgres PITR / SQLite `backup.dir` output) — this is why backup-before-release is mandatory, not optional. etcd state rebuilds on reconnect.

**Post-deploy checks:** `/readyz` 200 on every replica (aggregates redis/postgres/etcd/invalidation-bus/signing-key-aggregation); discovery doc `issuer` equals the external URL; `/metrics` 5xx and p95 baselines vs the grafana alerts; an admin-gated call (e.g. `GET /api/v1/admin/endpoints` with `admin:read`) proving the governance gate from this design; a token round-trip through the edge (authorization-code + PKCE); log scan for `internal_error`/`server_misconfigured`. Record the run in the release notes.

---

## 5. Missing assets / operator decisions that block a production claim

1. **Release target decision (C1/H1)** — revoke the PAT; decide dry-run vs live; confirm/create the ghcr org; environment protection with reviewers; fix the stale workflow header. **Blocking.**
2. **Hard security gates (H2)** — `.dockerignore`; trivy secret scan hard; CRITICAL-block policy; image scan in the release job. **Blocking for a hardened claim.**
3. **Prod overlay self-sufficiency (F3/M2)** — provision etcd (terraform has no etcd module), Redis TLS CA and pgbouncer resources or document them as pre-existing; digest-pin images; replace `CHANGE_ME` secretGenerator literals with a managed secret source; bundle the admission policy into the overlay or gate its absence. **Blocking.**
4. **Strict config validation (M1)** — unknown-key rejection in `--validate-only`; fix the baremetal-ha config. **Blocking** for config-drift safety; cheap to do.
5. **Staging environment + promotion (M3)** — staging overlay, one rehearsed apply+smoke+rollback. **Blocking for a controlled-release claim.**
6. **gRPC TLS decision (M4)** — land the design's D4 `admin.grpc_tls` (or explicitly accept and document plaintext on a trusted network) before the first multi-replica prod deployment. **Blocking** for the design's own fail-closed TLS invariant.
7. **Backup/restore operations (I2)** — per-backend retention, RPO/RTO targets, restore drill cadence, and the Postgres offline migration-status gap. **Operator decision**, non-blocking for v1 but required for any DR claim.
8. **SLSA provenance + per-profile artifact publishing (L1)** — state whether profile images (`Dockerfile.full`) are distribution artifacts. **Non-blocking decision.**

**Net assessment:** the *engineering* side (tests, gates, HA topology controls, DR framework, honest READMEs) is unusually strong for this stage; the *delivery* side (release target, credentials, gate enforcement, self-sufficient IaC, staging) is not yet production-claimable. C1 and H1 must be resolved before the first tag push; M1–M4 are the next tier. No canary/blue-green complexity is warranted — the shared-state topology with rolling updates, PDB, tolerant readiness, and the recovery drill is the right risk model; adding more would be gold-plating.
