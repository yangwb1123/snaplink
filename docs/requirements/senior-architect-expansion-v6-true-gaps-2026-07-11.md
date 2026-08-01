# Senior Architect Expansion Directions v6 — True Remaining Gaps (2026-07-11)

> **Analyst:** Architect Agent | **Method:** Exhaustive global scan (grep + read + file-tree walk) — every `.go` file, every `.md` doc, every `.yml`/`.yaml` workflow, every test file, every config. No assumptions; every claim below is grep-verified as **not yet implemented**.

## Preamble: This Codebase Is Exceptionally Mature

After a full global scan, I must begin with an observation: **this project has already closed nearly every gap identified across 5+ prior expansion-analysis rounds.** The following are all verified-done in tree:

- Consent store (SPI + memory + sqlite + postgres + redis + admin API + tests)
- Trusted proxies middleware (`WithTrustedProxies` + CIDR allowlist + hop count)
- Client secret hashing at rest (bcrypt in sqlite/postgres)
- Batch audit recording (`RecordBatch` with group-commit)
- Nested module CI matrix (all 12 `go.mod` files built + race-tested in CI)
- Govulncheck, CodeQL, Trivy in CI
- Dependabot covering all 12 modules
- 10+ fuzz tests across JWT/aud/federation/JAR/bind/DCR/end_session
- Full benchmark infrastructure (`make bench`, `make bench-gate`, baseline comparison)
- k6 load test suite with baseline regression detection
- pprof integration (separate listener, disabled by default)
- Admin Console SPA (`interfaces/web/admin`) with CRUD for clients/users/tenants/domains
- Self-service portal + Developer portal + Hosted Login SPA
- SAML 2.0 (SP + IdP + SLO, both sqlite backends)
- CAEP/SSF (transmitter + receiver, MQTT delivery, JWT-SET)
- Active ITDR / threat response (`domains/threataction` with executor + policy + registry + admin API)
- Enterprise Connections + Home Realm Discovery (`domains/connections/` Store + `/auth/home-realm` endpoint)
- ReBAC / Zanzibar-style relationship-based access control (`platform/lifecycle/rebac/`)
- Cross-protocol Session Hub (`platform/lifecycle/sessionhub`)
- OpenTelemetry tracing (OTLP exporter, span injection across audit/bus/migrate/kafka)
- Per-subject rate limiting (`KeyBySubject`)
- SIEM-ready audit events (CEF, OCSF, syslog, webhook sinks)
- Client secret rotation via admin API
- Schema version tracking (`migrate.CurrentVersion`)
- Coordinated signing-key rotation with deadline-based cutover
- KMS backends (AWS KMS, GCP KMS, Azure KeyVault, PKCS#11, Vault Transit)
- Workload identity federation (GCP, AWS, Azure)
- DCR approval workflow + developer portal
- Feature gate hot-reload (SIGHUP) for all 7 gate groups
- Bounded memory stores with background reaper
- DPoP + mTLS + JAR + JWE + PAR + RAR + CIBA + Transaction Tokens

**What remains** are not protocol gaps or foundational missing capabilities — those are fully addressed. What remains are **productization, operational hardening, and quality-assurance infrastructure** items that separate a best-in-class SDK/library from a **shippable enterprise identity platform**.

---

## Direction 1: Terraform Provider for SSO Resource Management — IaC Integration

**Status: NOT IMPLEMENTED** (grep for `terraform.*provider`, `hashicorp/terraform-plugin`, `resource_sso` — zero hits outside analysis docs and deployment infra scripts)

### Why Now

The project already exports a full admin REST API (gRPC-gateway at `/api/v1/admin/*`) covering clients, tenants, users, permissions, connections, sessions, audit, signing keys, and more. Every major competitor — Auth0, Okta, Keycloak, WorkOS, Ory — ships a Terraform Provider because **enterprise platform teams manage SSO configuration through IaC, not curl scripts or GUIs**.

Without a Terraform Provider:
- A new client registration requires a `curl` to `/register` OR a click in the Admin Console SPA
- A tenant configuration change cannot be code-reviewed via `terraform plan`
- There is no GitOps workflow for SSO configuration (no `terraform apply` in CI)
- The project is excluded from RFP shortlists that require IaC support

This is a **pure productization gap** with **zero core SDK changes** — the provider consumes the same admin REST API a human operator calls. It lives in a separate Go module (`go.hashicorp.com/terraform-plugin-framework`) with its own `go.mod`, zero dependency on `github.com/snaplink/sso`.

### Scope

| Deliverable | Description | Effort |
|---|---|---|
| Provider skeleton | `provider.go` with `ConfigureFunc` (bearer token from env/provider attr) | 1 day |
| `sso_client` resource | CRUD on `POST /api/v1/admin/clients`, mapping all ~25 relevant `core.Client` fields to Terraform schema attributes | 3 days |
| `sso_tenant` resource | CRUD on `POST /api/v1/admin/tenants` (slug, status, residency, branding, domains) | 2 days |
| `sso_connection` resource | CRUD on `POST /api/v1/admin/connections` (SAML/OIDC upstream configs per tenant) | 2 days |
| `sso_token_policy` resource | CRUD on token policy (token lifetime, signing alg constraints, claims projection) | 1 day |
| `sso_conditional_access_policy` resource | CRUD on conditional access policies (conditions, actions, priority) | 1 day |
| `sso_user` data source | Read-only lookup by email or user ID | 0.5 day |
| `sso_jwks` data source | Fetch current JWKS (for service mesh / sidecar bootstrap) | 0.5 day |
| Acceptance tests | `terraform-plugin-testing` with ephemeral test server | 2 days |
| Documentation | `docs/` subdirectory with examples for each resource | 1 day |
| CI integration | Separate `.github/workflows/terraform.yml` for lint + validate + test | 0.5 day |

**Total:** ~14 days / one sprint for a first cut with the 4 highest-value resources (client, tenant, connection, user data source).

### Edge Cases & Design Constraints

- **Secret never returned:** The `sso_client` resource's `client_secret` attribute is `Computed` + `Sensitive` + written only at create time (the admin API never returns secrets). Terraform's state will hold the create-time secret. On `plan` after `apply`, the secret shows as a diff (sensitive, not plaintext) — this is the same pattern Auth0's provider uses.
- **Import support:** `ImportState` + `Importer` for all resources so `terraform import sso_client.xyz <client_id>` works for existing resources.
- **Registration access token:** DCR-registered clients have a `registration_access_token` for self-management. The provider should handle this transparently (use it on reads from the `/register/:id` endpoint, rotate on conflict).
- **Tenant status transitions:** Suspend/Activate are separate RPCs from Update — the resource's `status` field must trigger the correct API call on update.
- **No core SDK dependency:** The provider imports only the admin REST API's response shapes (or uses raw JSON). No `go.mod` coupling to the server.
- **Plugin Framework (not SDK v2):** HashiCorp has deprecated SDK v2 for new providers. Plugin Framework is the correct choice.
- **Separate repository or directory:** Either `terraform/` in this monorepo or `github.com/snaplink/terraform-provider-sso` in a separate repo. If monorepo, the `Makefile` needs a `make terraform` target.

### Sequencing

Can be done in **parallel** with any other direction — zero dependencies on core SDK changes. Ideal for a dedicated engineer or as a onboarding project.

---

## Direction 2: OIDC Conformance Test Automation — Protocol Compliance Regression Gate

**Status: NOT INTEGRATED INTO CI** (conformance docker-compose exists at `test/oidc-conformance/docker-compose.yml` but is not wired into any CI workflow; no `make oidc-conformance` target calls it; the test must be run manually with a browser)

### Why Now

The project claims broad OIDC support (discovery, ID Token, userinfo, RP-Initiated Logout, session management, CIBA, JARM, FAPI, etc.) — but **none of it is verified against the OpenID Foundation's conformance test suite automatically**.

The risks are concrete:
- A refactor of the `/token` handler could break `at_hash` correctness and no CI would catch it
- A change to discovery document generation could drop `claims_parameter_supported` or `request_parameter_supported` and no CI would catch it
- A JOSE library upgrade could break JARM response serialization in ways unit tests don't cover (cryptographic edge cases are notoriously hard to test without a reference implementation)
- A deployment that passes `make ci` green could fail an OIDC conformance audit — a procurement blocker

The conformance suite docker-compose already exists. The gap is **automation**: wiring it into CI so every PR is tested against 10-20 relevant conformance profiles.

### Scope

| Deliverable | Description | Effort |
|---|---|---|
| CI workflow | `test/oidc-conformance/run.sh` that starts the suite, triggers tests via API (the conformance suite supports a headless REST API), waits for results, and exits with the pass/fail status | 2 days |
| Profile selection | Choose the 10-15 most relevant profiles (OIDC Basic, Implicit, Hybrid, Config, RP-Initiated Logout, Session Management, JARM, FAPI-RW, CIBA) — not all 80+ | 1 day |
| Test configuration per profile | Pre-computed test plan JSONs that set the right endpoints, client metadata, and expected behaviors for each profile | 2 days |
| Baseline recording | A one-time run that records the passing results as a CI baseline; subsequent runs fail only on deltas (new failures, not all failures — because some tests exercise optional features) | 0.5 day |
| Documentation | README in `test/oidc-conformance/` explaining how to add/update profiles, interpret results, and run manually | 0.5 day |
| Makefile integration | `make oidc-conformance` target | 0.5 day |

**Total:** ~6 days

### Edge Cases

- **Flaky tests:** The conformance suite can be flaky (network timeouts, docker-compose startup races). The CI workflow should retry failed tests once and report retry-success as pass.
- **Optional features:** Some profiles test optional features (e.g., `claims_parameter_supported`). A test failure for an optional feature that the server explicitly does not claim support is not a regression. The recording/baseline approach handles this naturally.
- **Resource requirements:** Running the conformance suite requires ~4GB RAM and 2 CPUs. The CI runner must be `ubuntu-latest` (not a smaller instance).
- **Not a replacement for unit tests:** This is a supplement, not a replacement. Unit tests catch logic errors; conformance tests catch protocol-level misalignment.

### Sequencing

Can proceed in parallel with Direction 1. The only coupling is that the conformance suite tests the live HTTP server's behavior, so the server build must be stable.

---

## Direction 3: MemoryLimiter Prune-Lock Self-DoS Hardening

**Status: IMPLEMENTED WITH KNOWN VULNERABILITY** (confirmed by reading `interfaces/ratelimit/ratelimit.go:132-145` — `Allow()` acquires a `sync.Mutex`, then in the critical section does a 1-in-64 sampled full-map scan `pruneLocked`)

### Why Now

`MemoryLimiter` sits in the middleware chain **before every credential endpoint** — it is the outermost defense against credential stuffing and DoS. Its current design creates a **performance amplifier for the very attack it is meant to stop**:

1. Attacker sends requests with many distinct IPs (or spoofed XFF values)
2. Each distinct IP creates a new bucket entry in the `map[string]*bucketEntry`
3. The 1-in-64 sampled `pruneLocked` call walks the **entire map** while holding the per-shard lock
4. Under attack, N (active keys) grows to tens or hundreds of thousands
5. Every 64th request is serialized behind an O(N) scan — legitimate user requests queue behind it

With 16 shards, the expected worst case for a 100k-entry map is 100k/16 = 6,250 entries scanned per prune. At `time.Now().Sub(e.lastSeen) > stalePruneAfter` per entry, this takes ~62.5µs on a modern CPU. The 1-in-64 sampling means at 10k req/s aggregate, ~156 req/s hit this slow path, serializing ALL traffic in that shard.

**The fix is well-understood and the pattern already exists in-tree** — the sqlite limiter (`interfaces/ratelimit/sqlite_limiter.go:204`) uses a background goroutine for pruning instead of inline sampling. The same fix should be applied to the memory limiter.

### Scope

| Deliverable | Description | Effort |
|---|---|---|
| Background pruner | Spawn a periodic goroutine at `NewMemoryLimiter` time that walks all shards outside `Allow()`'s path | 0.5 day |
| Remove inline prune | Delete the 1-in-64 sampling + `pruneLocked` call from `Allow()` | 0.25 day |
| Constructor option | `WithPruneInterval(d time.Duration)` — default to `stalePruneAfter / 2` | 0.25 day |
| Lifecycle management | `context.Context` cancellation stops the pruner (no goroutine leak on server shutdown) | 0.25 day |
| Race tests | `-race -count=10` to verify concurrent `Allow()` + prune safety | 0.5 day |
| Benchmarks | Before/after bench on the existing `BenchmarkMemoryLimiterAllowManyKeys` (which simulates high cardinality) | 0.5 day |

**Total:** ~2 days

### Edge Cases

- **Startup race:** The pruner goroutine may attempt to prune before any keys are inserted. This is safe (empty map, zero iterations) but should be explicitly tested.
- **Pruner vs. normal path ordering:** Normal `Allow()` does `lastSeen = time.Now()`. The pruner checks `time.Now().Sub(b.lastSeen) > stalePruneAfter`. There is a benign race: a bucket that's concurrently being accessed could be pruned. The next `Allow()` for that key re-creates it — correct, just resets its rate limit. This is the same behavior as the current 1-in-64 sampling.
- **Context cancellation:** The pruner must exit promptly on shutdown. Use `select` on `ctx.Done()`.
- **Churn amplification:** If the pruner runs too frequently (e.g., `stalePruneAfter = 1s`), it wastes CPU. Default to `stalePruneAfter / 2` as minimum, with a floor of 1 second.

### Sequencing

Can be done as a standalone sprint-filler. It touches exactly one file (`interfaces/ratelimit/ratelimit.go`) and its test file.

---

## Direction 4: Schema Version Fencing for Safe Rollback

**Status: NOT WIRED INTO BOOT (`migrate.CurrentVersion` exists at `platform/migrate/migrate.go:374` but has zero non-test callers in the server binary — confirmed by grep)`

### Why Now

Canary rollback is the most common recovery operation in production. Today, if an operator:
1. Deploys binary v2 which runs migration `migrate:002` (adds a NOT NULL column to `clients`)
2. Finds a regression in v2
3. Rollback to binary v1

**v1 will serve against a schema it does not understand** — and if the migration was additive (e.g., new column with a default), v1 silently ignores it. But if the migration was non-additive (e.g., renamed column, data type change), v1 crashes with opaque SQL errors.

The `migrate` package already has `CurrentVersion()` which computes the highest applied version across all migration namespaces. Each backend already exposes its maximum supported version (e.g., `defaultimpl/sqlite/maxversions.go`, `infrastructure/postgres/...`, `infrastructure/saml/idpsqlite/...`).

What's missing: the server binary's **boot sequence** compares `DB.CurrentVersion > binary.MaxSupportedVersion` and either hard-fails or soft-degrades (marks itself not-ready on `/readyz`).

### Scope

| Deliverable | Description | Effort |
|---|---|---|
| `MaxVersion()` per backend | Each sqlite/postgres backend exposes a `MaxVersion()` function returning the highest schema version it produces migrations for | 1 day |
| Boot-time check | In `cmd/sso-server`'s initialization, after all migrations run, call `CurrentVersion()` on each DB and compare against the backend's `MaxVersion()` | 0.5 day |
| Fail-closed vs fail-open | Additive migrations (new table, new nullable column) → fail-open (log warning, continue). Non-additive (column rename, data type change) → fail-closed (exit with clear error message) | 1 day |
| `/readyz` integration | When a non-additive version mismatch is detected, set readiness to false (the server stays up to serve `/livez` and existing connections but won't receive new traffic from the load balancer) | 0.5 day |
| Documentation | Updated `docs/deployment.md` with rollback compatibility policy — additive-only within a major version | 0.25 day |

**Total:** ~3 days

### Edge Cases

- **Multiple DBs:** The server connects to separate sqlite/postgres databases (oauth, audit, saml, permissions, etc.). Each has its own migration namespace and version. The check must be per-DB.
- **New binary, old DB:** v2 binary, v1 DB. Migrations run forward, `CurrentVersion` == `MaxVersion`. Normal — no guardrail triggered.
- **Old binary, new DB (rollback):** v1 binary, v2 DB. `CurrentVersion` > `MaxVersion` → guardrail triggered.
- **Additive-only promise:** The project should make an explicit compatibility promise: all migrations within a major version must be additive (new tables, new nullable columns, new indexes only). Non-additive migrations require a major version bump. This matches the existing practice (all migrations in tree are additive).
- **Skip-during-migration:** The guardrail must not fire during the migration itself (the binary that ran the migration is the same binary checking the version — it must pass). The check runs after all migrations complete.

### Sequencing

Direction 4 is the most **independent** and **highest safety-impact** item on this list. It is a pure hardening exercise with zero feature changes. Recommend it as the first item to implement.

---

## Direction 5: Automated Client Credential Rotation & Lifecycle Management

**Status: PARTIAL — manual rotation exists via admin API (`POST /api/v1/admin/clients/{id}/rotate-secret`) but no automated scheduling, expiry enforcement, or credential lifecycle policy**

### Why Now

The project already implements best practices for access tokens (rotation, family reuse detection, bounded lifetime) but **client credentials (the keys to the kingdom) have no automated lifecycle management**:

- A client secret today lives until explicitly rotated by an admin
- There is no configurable `client_secret_expires_at` field on `core.Client`
- There is no built-in mechanism to warn operators that a client secret is approaching expiry
- There is no automatic re-issuance of mTLS certificates for `tls_client_auth` clients
- The `client_secret` that IS rotated has no grace period (old secret + new secret both valid for a window) — rotation immediately invalidates the old one

For an enterprise SSO platform that stores credentials for hundreds or thousands of registered clients, manual secret rotation does not scale and is a security audit finding (SOC2, PCI-DSS, ISO 27001 all require periodic credential rotation).

### Scope

| Deliverable | Description | Effort |
|---|---|---|
| `client_secret_expires_at` field | New optional field on `core.Client`; set at creation/rotation; honored at `ValidateSecret` time (expired secret → `invalid_client` with description "client secret expired") | 1 day |
| Rotation grace window | When rotating a client secret, keep the previous hash valid for a configurable overlap window (default 24h). Two hashes stored: `secret` (current) and `previous_secret` (previous, with expiry) | 2 days |
| Expiry audit signal | A daily background sweep (or call at `/token` client auth time) that logs an `admin_client_secret_expiring_soon` audit event when `client_secret_expires_at` is within 30 days | 1 day |
| Admin API extension | `GET /api/v1/admin/clients/expiring?within=30d` — list all clients whose secret expires within the window | 0.5 day |
| Client bulk notification | Optional webhook or admin console banner when N clients have expiring secrets | 1 day |
| Certificate expiry + rotation | For clients using `tls_client_auth` or `self_signed_tls`, track `x509.Certificate.NotAfter` from the registered certificate, emit expiry warning at 30-day threshold | 1 day |

**Total:** ~6.5 days

### Edge Cases

- **Rotation grace window security:** Keeping the old hash valid creates a window where a stolen old secret works. Mitigations: the grace window is configurable (default 24h, minimum 1h); the old hash is stored salted separately so a DB breach doesn't reveal the new secret; an audit event is emitted on old-secret use during the grace window.
- **CRL/OCSP integration:** For certificate-based client auth, expiry tracking relies on the certificate's `NotAfter`, not on CRL/OCSP checks (which are already handled separately by `WithMTLSRevocationChecker`).
- **Public clients don't apply:** Clients with `token_endpoint_auth_method = none` (public clients like SPAs) have no secret to rotate. The field and checks are no-ops for them.
- **Migration:** Existing clients get a NULL `client_secret_expires_at` = never expires. Only newly created or explicitly rotated clients get an expiry. This avoids breaking existing deployments.
- **DCR self-managed clients:** Clients registered via DCR have their own registration management flow. The admin API expiry listing should include them (with a note that the developer can also rotate via `/register/:id`), but the server should not auto-expire them without developer notification.

### Sequencing

Direction 5 is the most **product-facing** of the 5 directions. It closes a gap that procurement security questionnaires regularly probe. Recommend after Direction 4 (safety) and in parallel with Direction 1 (productization).

---

## Priority Summary

| # | Direction | Effort | Risk | Value | Parallelizable |
|---|---|---|---|---|---|
| 1 | Terraform Provider | ~14 days | Very Low | **High** (IaC procurement gate) | ✅ Yes |
| 2 | OIDC Conformance CI | ~6 days | Low | **High** (protocol compliance gate) | ✅ Yes |
| 3 | MemoryLimiter Prune-Lock | ~2 days | Very Low | **Medium** (security hardening) | ✅ Yes |
| 4 | Schema Version Fencing | ~3 days | Very Low | **High** (operational safety) | ✅ Yes |
| 5 | Client Credential Lifecycle | ~6.5 days | Low | **High** (compliance/SOC2 gate) | ✅ Yes |

### Sequencing Recommendation

```
Sprint 1:       Direction 4 (safety, 3d) + Direction 3 (perf, 2d)
                → immediately hardened production surface
Sprint 2-3:     Direction 1 (productization, ~14d)
                → Terraform Provider as separate track, no SDK coupling
Sprint 2:       Direction 2 (quality, 6d)
                → parallel with Direction 1, teams can split
Sprint 3-4:     Direction 5 (compliance, ~6.5d)
                → completes the "rotation for all credentials" story
```

**All five directions are independent** — no direction blocks any other. They can be parallelized across 2-3 engineers for a total of ~4-5 sprints to close the remaining productization, safety, and compliance gaps.

---

## Appendix: Items Deliberately Not Included

The following were considered and rejected as already-implemented or out-of-scope:

| Candidate | Verdict | Evidence |
|---|---|---|
| Consent store | ✅ Done | SPI + memory + sqlite + postgres + redis + admin API + tests |
| Enterprise connections + HRD | ✅ Done | `domains/connections/` + `/auth/home-realm` + admin API |
| Active ITDR / threat response | ✅ Done | `domains/threataction` with full executor/policy/registry/admin |
| ReBAC / Zanzibar engine | ✅ Done | `platform/lifecycle/rebac` with memory store + handlers |
| Workload identity federation | ✅ Done | GCP/AWS/Azure validators + `WithWorkloadIdentityProviders` |
| CI security scanning | ✅ Done | Govulncheck, CodeQL, Trivy, Dependabot (12 modules) |
| Benchmark + load test infra | ✅ Done | `make bench-gate`, k6 suite, baseline comparison scripts |
| OTLP/OpenTelemetry tracing | ✅ Done | `platform/tracing`, spans across all critical paths |
| KMS backends | ✅ Done | AWS KMS, GCP KMS, Azure KeyVault, PKCS#11, Vault Transit |
| Admin Console SPA | ✅ Done | `interfaces/web/admin/` with clients/users/tenants CRUD |
| SAML 2.0 IdP + SP + SLO | ✅ Done | `infrastructure/saml/` full implementation |
| CAEP/SSF | ✅ Done | Transmitter + receiver + MQTT delivery |
| DCR approval workflow | ✅ Done | Approve/Reject + `admin_client_approved/rejected` audit |
| Feature gate hot-reload | ✅ Done | SIGHUP for all 7 gates, route-matching-level gate check |
| Batch audit | ✅ Done | `RecordBatch` in sqlite sink with group-commit |
| Fuzz testing | ✅ Done | 10+ `Fuzz*` functions across bind/JWT/aud/federation/JAR/DCR |
| Client secret hashing at rest | ✅ Done | bcrypt in sqlite/postgres, constant-time comparison |
| Per-subject rate limiting | ✅ Done | `KeyBySubject` function + middleware |
| Clock skew tolerance | ✅ Done | `MaxClockSkew` config on SSO client RS, DPoP iat window |
| Transaction Tokens (RFC 9321) | ✅ Done | `oauth/txntoken/` full implementation |
