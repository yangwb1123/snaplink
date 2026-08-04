# DevOps Review — interfaces-apidocs design + build/delivery/deployment automation

**Reviewer role:** advisory (per `ai-dev/prompts/README.md`). No files modified.
**Revision reviewed:** `9b3b4966` (design stage — the apidocs feature is not yet implemented).

**Checks actually run for this revision:** `python cli.py check-routes` PASS (241 registered / 322 documented) · `python cli.py sdk-surface check` PASS (13 groups, 316 operations) · `python cli.py modules check` PASS (prototype / standard-kafka / standard profiles) · full static verification of `.github/workflows/*.yml`, `Makefile`, `.goreleaser.yaml`, `Dockerfile`, and every `ops/deploy/` asset listed below (path-level citations). `go build`/`go vet`/`go test ./...` were run green for this revision by the protocol review (same revision); `make ci` in one shot was **not** run and is not reproduced by any GitHub Actions job (see F4). The design/QA/security/arch reviews' executable claims were re-checked where they touch deployment (probes, admin gating, CI wiring).

Labels: **Verified / Partial / Missing / Proposed / Unknown**; observed facts are separated from inference.

---

## 1. Supported deployment-path and artifact inventory

### 1.1 Build artifacts

| Artifact | Status | Evidence |
|---|---|---|
| `sso-server` / `sso-ctl` binaries | **Verified** | `python cli.py build` → `bin/` (105 MB present); root-module builds; ldflags version/time/hash/modified via goreleaser + Dockerfile |
| Profile builds (`prototype` / `minimal` / `full`) | **Verified** | `python cli.py configure --profile … --build` → `dist/modules/<profile>/` (355 MB present); root `go.mod`/`go.sum` untouched (`AGENTS.md` §4) |
| `sso-mcp` (nested module) | **Verified** | own `go.mod`; built by Dockerfile target `sso-mcp` and goreleaser build id `sso-mcp` |
| goreleaser archives | **Verified** | `.goreleaser.yaml`: 3 binaries × (linux/darwin/windows × amd64/arm64, minus windows/arm64), tar.gz/zip, `checksums.txt` (sha256), SPDX-JSON SBOM per archive, cosign blob signatures |
| Container images | **Verified (config); Unknown (target)** | multi-stage `Dockerfile` → distroless/static:nonroot, `USER nonroot`, no config baked; goreleaser dockers publish to `ghcr.io/snaplink/sso-server` / `sso-mcp` — **org existence Unknown**, and the workflow's own comment says publishing is not yet intended (F1) |
| FIPS 140-3 build | **Verified** | `--build-arg GOFIPS140=…`, default `off` is byte-identical (Dockerfile comment); `docs/fips.md` |
| No committed binaries | **Verified** | `.gitignore` covers `/sso-server`, `/sso-ctl`, `/bin/`, `/dist/`; `git status` shows no binary additions |

### 1.2 Deployment paths

| Path | Status | Verdict |
|---|---|---|
| Compose `ops/deploy/compose/` | **Verified** | Dev-only: sso-server + etcd; **no container healthcheck** (distroless has no shell; comment at compose.yaml:59); observability behind `--profile` |
| K8s base `ops/deploy/k8s/` | **Verified** | 1 replica, memory stores, `:latest` image, `/livez`+`/readyz` probes outside rate-limit stack; quickstart only |
| Kustomize prod `ops/deploy/kustomize/overlays/prod/` | **Verified** | Canonical HA overlay (README): 3 replicas, HPA, PDB, zone spread, tolerant readiness, graceful drain (40 s), all hot state on Redis Cluster, durable on Postgres-wire, coordination + signing-key registry on etcd, `cross_replica_revocation: true` (**fails boot without live etcd** — intentional). **Not self-sufficient**: image `snaplink/sso-server:prod` (a tag nothing publishes), `CHANGE_ME` secret literals, no etcd/Redis-TLS-CA/pgbouncer resources in the overlay (F3) |
| k8s-prod `ops/deploy/k8s-prod/` | **Verified** | README: deprecated compatibility copy; "Do not apply this directory as-is" |
| Helm `ops/deploy/helm/sso-server/` | **Verified** | Deployment + probes + PDB + HPA + ServiceAccount + Ingress + `ha-coherence.yaml` template that **fails the chart** on multi-replica + memory/per-pod backends. Gaps: no Secret template (config is a plain ConfigMap; signing keys/redis password must arrive via `extraVolumes`/`env`), default `image.tag: latest` |
| baremetal-ha `ops/deploy/baremetal-ha/` | **Verified** | RUNBOOK self-declares **"validation draft, not an executable production runbook"** with concrete blockers: distroless `wget` healthchecks, `sso/config.yaml` fails schema validation (`server.addr`/`server.trusted_proxies` drift), HAProxy `:443` binds without TLS config, redacted `smoke.sh`, no systemd units. **Do not treat as deployable** |
| Terraform `ops/deploy/terraform/` | **Verified** | README: "starting scaffold, not a production-ready stack". VPC/EKS/RDS/ElastiCache modules only — no etcd, ingress/LB, certs, External Secrets, pgbouncer, DNS, frontends. **Remote state backend commented out** (no S3/DynamoDB lock); CI validates only; apply is manual. `prod` tfvars: EKS 1.28 / RDS 15.4 / Redis 7.0 (aging versions), redis auth via `TF_VAR_redis_auth_token` (no committed secrets — **Verified**) |
| OpenResty edge `ops/deploy/openresty/` | **Verified** | README: prototype, Ed25519-only verifier, "Do not use as the sole production authorization boundary". fullstack `k8s.yaml` uses `imagePullPolicy: Never` + local-only tag `snaplink/sso-gateway:full-b24b0b0-gw6` — prototype only |
| Verification tooling | **Verified** | `loadtest/` (k6 + baseline compare), `benchgate/` (weekly, non-blocking), `ha-test/`, `grafana/` (dashboards + alerts), `prometheus.yml` — none are deployment paths |

### 1.3 This design's deployment surface (interfaces-apidocs)

- Route paths unchanged (`pathAdminAPIDocs = /admin/docs`, `pathAdminAPIDocsSpec = /admin/docs/openapi.json` — `interfaces/sso/server_routes.go:249-257`), both admin-gated (`admin:read`), opt-in `WithAPIDocsUI`, no config keys, no persistent state, no migrations. **Verified**.
- CI additions: reverse route-contract + `checks/embed_consistency.py` + `check-embed` wired into the Makefile `route-contract` target → runs under `make ci` **and** under `make docs-validate`, which the GitHub Actions `openapi` job executes (`ci.yml` → `make docs-validate`) — so the design's new gates **do reach CI** without a new workflow. **Verified** (Makefile:185-187, ci.yml openapi job).
- `cmd/sdkdiff` (new root-module dev tool): not in goreleaser builds (only sso-server/sso-ctl/sso-mcp), advisory-only in CI — no release-surface impact. **Verified**.
- Design's embed-consistency check (`sha256(docs.OpenAPISpec)` vs committed `docs/openapi.yaml`) adds a new cross-repo constraint: any future change to the embedded spec source without regenerating the committed YAML fails CI. Intentional; release ordering must regenerate docs in the same commit. **Verified (design text)**.
- Security review's H1 (recorder must implement `GatedRegistrar`; wire-visible `X-Request-Id` fingerprint if gated mounts degrade to handler-wrapping) is observable at the deployment layer: response headers on gated-off routes would change, which canary/diff tooling would see. Not a build/release blocker, but it changes the wire fingerprint — flag for the implementation round. **Partial (transitive, from security review)**.

---

## 2. Pipeline table

| Stage | Current evidence | Gap | Proposed gate | Owner |
|---|---|---|---|---|
| Source control | `9b3b4966`; PR + main workflows | **Live PAT in `git remote` URL (F1)**; tags can be pushed to the GitHub remote | revoke token; credential helper | maintainer |
| Unit/integration | `ci.yml` test job: harness, gofmt, vet, build, `go test -race -count=1 ./...` with Postgres service, config-validate-all | — | existing | — |
| Engineering gates | `engineering.yml`: filesize/complexity/architecture/invariants/exemptions/self-test/adr-compliance/check-test + coverage + trend | — | existing | agent |
| Nested modules | `ci.yml` modules matrix (build + race, 13 modules, pkcs11 cgo) + golangci matrix | — | existing | — |
| Contract gates | `openapi` job = `make docs-validate` = route-contract + capabilities-check + kin-openapi validate | **design's check-embed + reverse check land here — must be added in the same commit as the code** | extend route-contract (design D3) | agent |
| Registry gates | `sdk-surface check` green locally | **not in any GH workflow** (`sdk-surface-check` absent from ci.yml/engineering.yml — verified by grep) | add to ci.yml | agent |
| Profile isolation | `profiles-evidence` in `make ci` | **not in any GH workflow** | add to ci.yml | agent |
| License gate | `licenses-check` target exists (GPL/AGPL/SSPL reject) | **not in any GH workflow** | add to ci.yml | maintainer |
| SAST/SCA | govulncheck (root+modules), gosec (SARIF), codeql, trivy fs (vuln+secret+misconfig, SARIF) | **all report-only — nothing blocks on findings (F2)**; trivy scans fs, not the built image | secret-scan hard gate; image scan; CRITICAL policy | maintainer |
| OpenAPI schema | `make docs-validate` in CI | kin-openapi validate is unpinned `go run @latest` (Makefile) | pin version (L2) | agent |
| Docker build | `ci.yml` docker job (buildx smoke, no push) | **no `.dockerignore` (F2)**; base tags float | add .dockerignore; pin base digests (L3) | maintainer |
| IaC | ci.yml: kustomize render (dev/prod + diff), terraform init+validate | apply/plan never runs in CI; prod overlay not self-sufficient (F3) | dry-run apply in CI; preflight script | maintainer |
| Load/perf | benchgate weekly (non-blocking), k6 loadtest manual | — | keep non-blocking; run pre-release | maintainer |
| E2E/chaos/DR | `test/` in the race sweep; chaos on main only; dr-drill manual | — | existing | — |
| Release | `release.yml` on `v*` tag → goreleaser + cosign | **workflow header says dry-run, config publishes (F1)**; no environment/approval; no staging promotion | resolve F1; add protection | maintainer |
| Deploy | manual kubectl/helm/terraform from kustomize/helm | no staging env; no promotion pipeline; secrets out-of-band | staging + smoke + approval (F5) | maintainer |
| Monitoring | `/metrics`, `/livez`, `/readyz` outside rate limit; prometheus + grafana + alerts | alert thresholds "tune against your traffic baseline" (grafana README) | baseline tuning | operator |
| Backup/DR | `docs/dr-framework.md` (RPO/RTO, replication per tier), `dr-drill` target, `sso-ctl snapshot`/`audit-verify` | drills not scheduled in CI | on-demand pre-release (existing) | operator |

---

## 3. Findings (by severity)

### F1 — High · Release pipeline is live-but-misdescribed; a `v*` tag push publishes

- **Location:** `.github/workflows/release.yml` header ("Today `release.disable=true` … exits without publishing") vs `.goreleaser.yaml:145-149` (`release.disable: false`, "Enabled") + `dockers` publishing `ghcr.io/snaplink/sso-server` / `sso-mcp` + cosign keyless `docker_signs`; workflow permissions `contents: write`, `id-token: write`, `packages: write`.
- **Evidence:** both files read in full (Verified). No `environments:` block, no required reviewers, no branch filter (`on: push: tags: ["v*"]` fires on any tag to the default branch). The GitHub remote is configured with a live PAT (F1b below), so pushing a `v*` tag to `github.com/yangwb1123/snaplink` is mechanically possible from this workspace.
- **Impact:** an operator following the stale header believes tag pushes are dry-runs; in fact a tag push uploads binary archives + SBOMs to GitHub Releases and publishes multi-arch images + cosign signatures to `ghcr.io/snaplink/*` (org existence **Unknown** — publish may fail or succeed into an unexpected org). No staging, canary, or approval exists anywhere between tag and publish.
- **Remediation:** decide the intended state explicitly. If dry-run: flip `release.disable: true` and keep the comment. If live: (a) fix the header comment, (b) confirm/create the ghcr org + repository names, (c) add a GitHub Environment with required reviewers to `release.yml`, (d) make the tag push gated (protected tag rule).
- **Validation:** `grep -n "disable" .goreleaser.yaml` vs the workflow header; push a tag on a throwaway fork repo and observe whether GH Releases/ghcr receive artifacts.

### F1b — High (pre-existing, unremediated) · Live GitHub PAT embedded in git remote URL

- **Location:** `.git/config` — `remote.github.url` contains `https://yangwb1123:ghp_…@github.com/yangwb1123/snaplink.git`. Flagged as M2 in the previous DevOps review (`docs/proposals/devops_engineer.md`); **still present** at this revision (grep count: 1). Not in any tracked file (grep across tracked sources: clean).
- **Impact:** any process or log with workspace read access (`git remote -v`, hooks, backups) extracts a live, likely write-scoped credential; it also enables the F1 tag-push path. Scope/validity Unknown.
- **Remediation:** revoke the token in GitHub now; strip it from the URL; use `gh auth login`/credential helper; audit workflow secrets for the same value.
- **Validation:** `git remote -v` shows no `ghp_`; revocation confirmed in GitHub settings.

### F2 — High · No hard security gate in CI; `.dockerignore` missing

- **Location:** `.github/workflows/{ci.yml,trivy.yml,codeql.yml}` + Makefile; repo root (no `.dockerignore`).
- **Evidence:** govulncheck `continue-on-error: true`; gosec `-no-fail`; trivy `exit-code: "0"` (report-only); codeql non-gating. `du -sh`: `.git` 70 MB, `bin` 105 MB, `dist` 355 MB, root binaries ~134 MB, `.venv` 3.3 MB — all become `docker build` context because `COPY . .` (Dockerfile) has no `.dockerignore`. The builder stage's `COPY . .` therefore carries `.git/config` (F1b's PAT), any future committed secret (e.g. a `terraform.tfvars` with credentials), and ~700 MB of noise into builder layers and any build cache that persists them; the `git rev-parse HEAD` fallback depends on `.git` being copied.
- **Impact:** for an SSO product, no CVE, committed-secret, or misconfiguration finding ever blocks a merge; the container build bakes the entire repository (including the credential-bearing `.git`) into a layer that CI caches and could push.
- **Remediation:** (1) add `.dockerignore` (`.git`, `bin/`, `dist/`, `/sso-server`, `/sso-ctl`, `/sso-minimal`, `.venv`, `__pycache__`, `test/oidc-conformance/results/`, `**/.env`) and pass `GIT_HASH` exclusively via build-arg; (2) make trivy's `secret` scanner a hard gate (deterministic, low-noise); (3) adopt a policy for when govulncheck CRITICAL / gosec findings block; (4) add an image scan (`make docker-scan` / trivy image) to the release job.
- **Validation:** `docker build` with `--no-cache` and measure context; `git grep -c ghp_ .` after `.dockerignore` lands still finds only `.git/config` until F1b is fixed.

### F3 — Medium · kustomize prod overlay is a reference, not an apply-able artifact

- **Location:** `ops/deploy/kustomize/overlays/prod/` (`kustomization.yaml`, `config.yaml`, `patch-deployment.yaml`).
- **Evidence:** image `newTag: prod` (no registry pipeline produces it — F1's release publishes `ghcr.io/snaplink/sso-server:<version>`/`latest`); `secretGenerator` literals `redis-password=CHANGE_ME`, `oauth-lookup-key=CHANGE_ME_32_BYTE_MINIMUM_LOOKUP_KEY` (with a comment "DELETE this and supply the secret out-of-band"); config requires `etcd-0..2:2379` for `cluster.bus` (boot-failing when absent), `cross_replica_revocation: true`, `keys.signing_key_registry: etcd`, Redis TLS `ca_file: /etc/redis-tls/ca.crt` (volume `optional: true` → silently absent), Postgres behind pgbouncer; the overlay contains **no** etcd/Redis/Postgres/pgbouncer resources and the Terraform explicitly does not provision them.
- **Impact:** a naive `kubectl apply -k` produces pods that fail readiness (no etcd) or boot with placeholder secrets; "prod" tag is unfindable. The topology itself is sound (shared stores, tolerant readiness, zone spread — Verified), the delivery chain around it is not.
- **Remediation:** (1) pin the image by digest in the overlay; (2) provision stores out-of-band and add a README dependency checklist (etcd cluster, Redis TLS CA, pgbouncer/Postgres, secret source); (3) supply secrets via External Secrets/SealedSecrets/Vault, never `CHANGE_ME` literals; (4) add a preflight gate (`sso-server --config … --validate-only` + etcd endpoint health) to the release procedure (see §4).
- **Validation:** on a scratch cluster with etcd absent, `kubectl apply -k …` then `kubectl wait --for=condition=Ready` must fail — then pass once etcd + secrets exist.

### F4 — Medium · `make ci` members that are not enforced in GitHub Actions

- **Location:** `.github/workflows/ci.yml`, `.github/workflows/engineering.yml`, `Makefile:244` (`ci: … sdk-surface-check profiles-evidence …`).
- **Evidence:** grep of all workflows shows `sdk-surface-check`, `profiles-evidence`, and `licenses-check` run **nowhere**; `make ci` as a single unit is never executed by any job (ci.yml runs discrete steps). This matters directly for the design: Decision 3 extends `ops/build/sdk-surface.json`'s schema and the QA review (F6) found `sdk_surface.py`'s `validate_schema` hard-requires `schema_version: const 1` — so the schema change plus the new `unmountedOperations` exceptions could land with only local validation, and the "registry drift" backstop would not fire in CI.
- **Impact:** declared handoff gate (`make ci`) ≠ enforced gate; schema/registry drift ships green.
- **Remediation:** add `make sdk-surface-check`, `make profiles-evidence`, `make licenses-check` steps to `ci.yml` (openapi or test job) in the same change as the design's Decision 3. The design's reverse check + `check-embed` need no new wiring (they ride `make docs-validate` — Verified).
- **Validation:** push a commit that edits `sdk-surface.schema.json` without updating `sdk-surface.json`; CI must go red.

### F5 — Medium · No staging/preprod environment or promotion path; release-to-prod is a manual leap

- **Location:** whole pipeline (workflows + ops/deploy); no `environments`, no stage deploy, no approval, no canary gate.
- **Evidence:** release.yml has no environment; the only deploy smoke is `ops/deploy/baremetal-ha/smoke.sh` (redacted, baremetal-only) and the helm/kustomize manifests are applied by hand; helm's RollingUpdate `maxUnavailable: 0` and the prod patch's tolerant readiness are the only built-in safety. `ha-test/` exercises HA in compose only.
- **Impact:** every production change is a manual apply with no rehearsed ordering; rollback quality depends on operator memory rather than a pipeline.
- **Remediation (proportional):** at minimum, a documented promote checklist (F3's preflight + §4's procedure); ideally a staging apply + smoke + approval step in CI before any prod tag is cut.
- **Validation:** walk the §4 procedure end-to-end on staging once before the first production claim.

### F6 — Low · Unpinned tooling and floating base images hurt reproducibility

- **Location:** Makefile `docs-validate` (`go run github.com/getkin/kin-openapi/cmd/validate@latest`), ci.yml (`go install gocyclo@latest`, `gocognit@latest`), gosec `@latest`; Dockerfile `golang:1.26-alpine`, `gcr.io/distroless/static:nonroot`; engineering.yml hardcodes `go-version: '1.26'` vs go.mod `1.26.1`.
- **Impact:** a tooling or base-image bump can flip CI or change image contents between otherwise identical commits; the design explicitly avoids adding new `@latest` tooling (goccy parser compiled from-tree, `go run` helper from-tree — Verified, good), which makes the pre-existing unpinned tools the odd ones out.
- **Remediation:** pin gocyclo/gocognit/gosec/kin-openapi versions (buf and golangci are already pinned — good precedent); pin `golang:1.26.1-alpine` and distroless by digest.
- **Validation:** `grep -n "@latest" Makefile .github/workflows/*.yml` shows zero in gate positions.

### F7 — Info · Helm chart secret story and image tag defaults

- **Location:** `ops/deploy/helm/sso-server/values.yaml` (`image.tag: latest`; no Secret template; config is a plain ConfigMap), `templates/deployment.yaml` (env passthrough only).
- **Impact:** chart is safe for a memory-backed single replica; for multi-replica the `ha-coherence.yaml` guard correctly refuses unsafe combinations (**Verified** — strong control), but signing-key material and backend passwords have no first-class delivery path in the chart.
- **Remediation:** document the out-of-band secret contract in the chart README (values.schema.json exists but does not cover secrets); consider a Secret template + `secretStore` pattern once a managed source is chosen.

### F8 — Info · Design's deployment footprint is nil — but the wire fingerprint changes matter to ops

- The apidocs design adds no config, state, migration, or route-path change (Verified: `mountAPIDocsUI` paths unchanged, admin-gated, opt-in). Release/rollback for it is a pure code revert. The one deployment-visible risk is the security review's H1: if the recording router fails to delegate `GatedRegistrar`, gated-off families change response headers (`X-Request-Id` presence) — an observable fingerprint in canary/diff monitoring. Track it in the implementation round.

---

## 4. Release and rollback procedure

For **this design** (interfaces-apidocs): no schema, no config keys, no state → migration matrix is empty by construction (**Verified** against the design's storage model). The procedure below is the general server procedure, with the design's deltas inline.

**Preflight (before tagging):**
1. `make ci` green in one shot locally **and** in GH Actions (F4 wiring first — the design's `check-embed` + reverse check ride `make docs-validate`; the 81-op exception bootstrap in `sdk-surface.json` must land in the **same commit** as the reverse check or CI goes red — design requirement, Verified in text).
2. `make config-validate-all` — validates all 7 deploy configs against the binary (also a ci.yml step).
3. `make release-check` + `make release-snapshot`; verify SBOM (SPDX-JSON) and checksums generated.
4. `make bench-gate` (pre-release, per its own contract) + `go test -tags chaos ./test/chaos/... -race -count=2` + `make dr-drill`.
5. Resolve F1 state (dry-run vs publish) and F1b (token) **before** the first tag push.
6. Image: build with pinned `GIT_HASH` build-arg (F2), scan with `make docker-scan`, verify cosign signature on the tag after publish.

**Migration / release ordering (general server):**
- Per-store migrations run **at store open, forward-only** (`infrastructure/postgres/*.go` — `NewAuditSink … migrates the schema`; `platform/migrate` runner with `ErrSchemaTooNew` guard: a binary older than the schema **refuses to boot** — Verified). Order: deploy new binary first (it migrates forward on boot), never run old binaries against the new schema without the rollback guard firing.
- This design adds zero migrations; ordering concern is only the docs-embed regeneration (commit docs + code atomically).

**Deploy (K8s, canonical path):**
1. Apply kustomize prod overlay with image pinned **by digest** (F3) and secrets supplied from the managed source.
2. Preflight on the cluster: etcd endpoints healthy, Redis TLS CA present, Postgres reachable, then `kubectl apply -k` (rolling update, `maxUnavailable: 0`).
3. Probes: `/livez` (process) + `/readyz` (aggregates Redis/Postgres/etcd/signing-key readiness — per k8s-prod README checklist); prod patch uses tolerant readiness (failureThreshold 4) so a backend blip drains one pod, not the fleet.
4. Post-deploy checks: `curl /readyz` across replicas; hit the admin surface (this design's `/api/v1/admin/docs` + `/openapi.json` require `admin:read` bearer — verify the projected spec lists exactly the mounted set and no 404-ing op per the acceptance); `curl /metrics` for error-rate baselines; run `ops/deploy/baremetal-ha/smoke.sh` only after its blockers are fixed (currently redacted — F3 of the RUNBOOK).

**Rollback:**
- Code-only (this design): revert the commit; the recorder wrapper and projection disappear with it; no data step.
- Server: re-pin previous image digest and `kubectl rollout undo` / `helm rollback --revision`; `/readyz`-gated rollout; if the schema moved forward, the old binary refuses to boot (`ErrSchemaTooNew`) — canary-rollback protection is built in; restore path is `sso-ctl snapshot` restore + audit-chain verify per `docs/dr-framework.md`.

---

## 5. Missing assets / operator decisions that block a production claim

1. **Release target decision (F1)** — is the release pipeline dry-run or live? If live: ghcr org/repo confirmation, environment protection with reviewers, and the stale workflow header fix. **Blocking.**
2. **Credential hygiene (F1b)** — revoke the PAT in `.git/config` and audit CI secrets for the same value. **Blocking (security).**
3. **`.dockerignore` + image scan (F2)** — the current build context ships `.git` (with the PAT) into builder layers and ~700 MB of noise; no image CVE scan runs in CI. **Blocking for a hardened claim.**
4. **Hard security gates (F2/F4)** — all SAST/SCA/secret scans are report-only; `sdk-surface-check`, `profiles-evidence`, `licenses-check` run nowhere in GH Actions. Decision needed: which findings block merges, and the CI wiring commit. **Blocking for "gates are enforced".**
5. **Prod overlay self-sufficiency (F3)** — etcd cluster, Redis TLS CA, Postgres/pgbouncer provisioning + digest pin + managed secrets; a preflight script. **Blocking for the kustomize prod path.**
6. **Staging environment + promotion (F5)** — no stage between tag and prod; document the promote checklist and rehearse it once. **Blocking for a controlled-release claim.**
7. **baremetal-ha (verified draft blockers)** — distroless wget healthchecks, config schema drift (`server.addr`/`trusted_proxies`), HAProxy `:443` without TLS, redacted smoke.sh, no systemd units. **Blocking only if that path is claimed.**
8. **Observability baselines** — grafana alert thresholds are starting points ("tune against your traffic baseline"); no SLOs/error budgets are defined anywhere (repo-wide). **Unknown/decision required.**
9. **Terraform state backend + apply pipeline** — commented-out S3/DynamoDB backend; apply is manual and unapproved. **Blocking for IaC-managed infrastructure.**
10. **Design-specific (non-blocking at design stage):** implement the `GatedRegistrar` delegation (security review H1) so gated-off routes keep their current wire fingerprint; land the 81-op sdk-surface.json bootstrap + reverse check atomically; pin the design's `go run` helpers from-tree (already the plan — keep it, unlike the existing `@latest` tools).

---

### Summary

The design itself has a minimal deployment footprint (no config/state/migration; CI gates reach GitHub Actions through the existing `docs-validate` job — a rare case where the CI wiring is already correct). The blockers for a production claim are all pre-existing delivery-chain issues, several flagged in the previous DevOps review and still open: the live PAT in the git remote, a release pipeline whose config and comments disagree (publish-enabled), no enforced security gates, no `.dockerignore`, and a kustomize prod overlay that requires out-of-band stores/secrets it neither provisions nor documents. None of these block the design stage; all block any "deployable in production" statement for the revision reviewed.
