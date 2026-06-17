# AGENTS.md

Operational guide for AI agents. Follows [agents.md](https://agents.md). User instructions override conflicts. **§4 invariants are gates — violations are regressions.**

---

## 0. Agent Engineering Principles (HARD GATES)

### 0.1 Code Size Budgets

| Metric | Limit | Violation Action |
|---|---|---|
| File lines (`.go`) | ≤ 500 | STOP feature. Run `skills/split-large-file.md` |
| Function lines | ≤ 50 | Extract sub-functions |
| Cyclomatic complexity | ≤ 15 | Run `skills/refactor-high-complexity.md` |
| Cognitive complexity | ≤ 20 | Simplify control flow |
| Switch/if-chain cases | ≤ 10 | Replace with strategy table |
| If-nesting depth | ≤ 3 | Guard clauses / early return |

**Cardinal rule:** If your edit pushes a file OVER 500 lines, you MUST pause feature work, split the file via the skill, then continue. Do not append to an already-over-limit file without splitting first.

### 0.2 Dependency Direction

```
handlers.go → oauth/ → security/ → core/
handlers.go → oidc/   → security/ → core/
```

**Absolute prohibits:** `oauth/ → oidc/`, `oidc/ → oauth/`, `cmd/ ← any`. New packages must slot into the correct layer.

### 0.3 Refactoring > Feature

If during feature work you detect a file at 480+ lines whose limit your change will exceed, or a function at cyclo=14 you will push to 16 — **stop, refactor the pre-existing violation first, then apply your feature change.** Refactoring tasks always outrank feature tasks.

### 0.4 Prohibited Patterns

| Pattern | Why | Do instead |
|---|---|---|
| `TODO: refactor later` | Debt agents never revisit | Refactor immediately |
| Appending to 490+ line file | Death by 1000 cuts | Split, then edit |
| God function / God file | Agent context cost explodes | Split by concern |
| `oidc/` importing `oauth/` | Creates cycle | Route via `handlers.go` |
| Bypassing `SetMeta` for audit | Clobbers enrichment | Use `SetMeta` only |
| Root file count > 15 non-exempt | Structural debt accumulates | Run `skills/project-reorganization/` before feature work |
| Business code (`*_handler.go`, etc.) in root | Breaks domain isolation | Move to `internal/<module>/` |
| New `*_handler.go`, `*_service.go`, `*_store.go` in root | HARDCAP | Blocked by `checks/root_business_code.py` |

### 0.5 Post-Edit Verification

After every change to a `.go` file:
1. `go build ./...` passes
2. File is under 500 lines (unless in HARNESS.md exemption list)
3. If function was modified: lines ≤ 50, cyclo ≤ 15
4. `go vet ./...` passes

**Fail-fast:** If any gate fails, fix immediately before proceeding to the next task.

### 0.6 Root Directory Policy

根目录禁止新增业务代码。Root 只允许包含 server composition 文件。

**Allowed files in root:**
- `sso.go` — Server struct + routes
- `handler.go` — Login orchestrator
- `handlers.go` — Discovery delegators
- `server_extensions.go` — DPoP, mTLS, JAR, JWE, BCL, FCL
- `mesh_authz.go` — Mesh authorization
- `signing_key_aggregation.go` — Key aggregation loop
- `storage_health.go` — Storage health check
- `accessors.go` — Field accessors for Deps interfaces
- `aliases.go` — Re-exports
- `options*.go` — Server configuration options
- `server_routes.go`, `server_helpers.go`, `server_validation.go`, `server_health.go`

**Prohibited in root:**
- `*_handler.go` (except `handler.go`, `handlers.go`)
- `*_service.go`
- `*_store.go`
- `*_grant.go`
- Business logic files (see `checks/root_business_code.py` BANNED_FILES)

**Migration strategy:**
1. Extract logic to pure functions in target domain package
2. Keep thin wrapper methods in root that call domain functions
3. Update Deps interface if needed

**Target locations:**
- OAuth handlers → `oauth/`
- OIDC handlers → `oidc/`
- Security logic → `security/`
- Cluster coordination → `cluster/`
- Tenant logic → `tenant/`
- Self-service → `selfservice/` (new package)

**Enforcement:** `python cli.py check-root`

---

## 1. System Overview

**Binary:** OAuth 2.0 + OIDC SSO server SDK + runnable binary. All concerns are interfaces; defaults in `defaultimpl/` (memory) + `defaultimpl/sqlite/` (pure-Go, no CGO). No external SaaS deps. Consumers wire embedded (`ssoclient/local`) or centralized (`ssoclient/remote`, gRPC+JWKS).

```bash
go build ./...
go test ./... -race
go test ./test/ -run TestE2E -v    # cross-wire HTTP + JWKS + bufconn
make ci                             # gofmt + vet + race + build + proto-lint + ci-modules
```

**Middleware stack** (probes registered OUTSIDE):
```
/metrics, /livez, /readyz                         ← outside ratelimit
tracing → ratelimit → bodyLimit → metrics → CORS → router
```

**Package layout:**

| Package | Purpose |
|---|---|
| `core/` | SPIs: User/Client/Session/Token/Subject/AuthRequest/AuthResult + Authenticator/UserProvider/ClientStore/SessionManager/TokenIssuer/JWK/JWKSProvider + wire consts + sentinels |
| `oauth/` | AuthCode/Device/Refresh/PAR stores, DCR/RAR/claims validators, hexagonal grant handlers |
| `oidc/` | IDTokenIssuer/UserinfoSigner/MetadataSigner SPIs, JWKS/EndSession/SilentRenewal/FormPost/JARM handlers |
| `security/` | Lockout, JTI-replay, JAR-fetch, JWE, step-up, mTLS extractor, pairwise, subject-client index, ConstantTimeEq, QuoteAuthParam |
| `spi/` | Logger, CodeSender, RiskScorer, MFAProvider |
| `fapi/` | FAPI 2.0 Validator (Inspection\|Enforce) |
| `anomaly/` | Async behavioral-detection SPIs |
| `cluster/` | Cross-replica Bus (Publish/Subscribe); memory + etcd |
| `middleware/` | Auth, CORS, Logger, Tracing, RequestID, no-store, base-URL |
| `admin/` | HTTP middleware + gRPC interceptor + scope rules |
| `tenant/` `geo/` | Tenant resolution + Geo enrichment middleware |
| `region/{memory}/` | Multi-region/data-residency SPI + resolvers |
| `authenticators/` | 9 pluggable + `webauthn/` (AAGUID attestation + FIDO MDS) |
| `scim/` | SCIM 2.0 provisioning (RFC 7643/7644) |
| `caep/` | OpenID SSF v1 SET push transmitter + receiver |
| `federation/` | OpenID Federation 1.0 — entity config + trust-chain + auto-register + §8 fetch + trust-marks |
| `defaultimpl/` | Ed25519/ECDSA/RSA issuers + Memory* stores + JWE + KMS bridge + `/sqlite` + `/detectors` + `/vaulttransit` |
| `adapters/{echo,gin}/` | Router adapters |
| `audit/` | Recorder + Sinks + hash chain |
| `permissions/` | Roles + menus + wildcard matcher + policy-bundle export |
| `compliance/` | GDPR/CCPA/PIPL erasure + export |
| `netpolicy/{memory,etcd}/` | Network classification |
| `registry/{memory,etcd}/` | Service discovery |
| `bootstrap/` | First-run init + dist lock |
| `snapshot/` | State export/restore |
| `releases/` | Frontend+backend release pinning |
| `signingkeys/{memory,etcd}/` | Leaderless JWKS key aggregation |
| `ratelimit/ cors/ metrics/ tracing/` | Middleware + observability |
| `config/{etcd}/` | YAML + env + etcd + flag loader |
| `proto/ gen/proto/ grpcserver/` | Protobuf + generated Go + gRPC + REST gateway |
| `ssoclient/{local,remote,dev,bootstrap}/` | Consumer-facing clients |
| `migrate/` | Pure-Go SQLite migration runner (versioned, forward-only) |
| `cmd/{sso-server,sso-audit-verify,sso-snapshotctl,sso-migrate}/` | Binary + offline CLIs |
| `deploy/{openresty,k8s,compose,grafana}/` | Operator artifacts |
| `test/` | Server-level integration suite (`package ssotest`) |

**Nested modules** (no `go.work`; vendor SDK out of core go.mod; `make ci` → `ci-modules`):

| Module | Dep | Notes |
|---|---|---|
| `kms/awskms/` | aws-sdk-go-v2 | No Ed25519 |
| `kms/gcpkms/` | cloud.google.com/go/kms | Ed25519 ✓ |
| `kms/azurekeyvault/` | azure-sdk-for-go | No Ed25519 |
| `kms/pkcs11/` | miekg/pkcs11 | CGO required |
| `saml/` | crewjam/saml | Full SAML 2.0 SP+IdP+SLO |
| `ldap/` | go-ldap/ldap/v3 | Search-then-bind |
| `kerberos/` | gokrb5/v8 | SPNEGO / Windows Integrated Auth |
| `radius/` | layeh.com/radius | PAP + RadSec |
| `extauthz/` | go-control-plane | gRPC Envoy ext_authz |
| `redis/` | go-redis | Hot-path scale layer (>1k QPS) |

---

## 2. Core Module Profiles

### Root Server (`package sso`)

9 non-test files. Integration tests → `test/` (`package ssotest`, full `*sso.Server` over HTTP, shared harness).

| File | Responsibility |
|---|---|
| `sso.go` | Server + Options + routes |
| `handler.go` | Login orchestrator (`/auth/login`) |
| `handlers.go` | Discovery + delegators |
| `server_extensions.go` | DPoP, mTLS, JAR, JWE, BCL, FCL, pairwise, tenant-susp, client-assertion, buildinfo |
| `mesh_authz.go` | `MeshAuthorize` seam + HTTP ext_authz |
| `signing_key_aggregation.go` | Leaderless JWKS aggregation loop |
| `storage_health.go` | Storage-health report (`GET /api/v1/admin/storage-health`, admin:read) |
| `accessors.go` | Field accessors backing the hexagonal `Deps` ifaces |
| `aliases.go` | Re-exports |

### OAuth Layer (`oauth/`)

**Input:** HTTP via `bindOAuthParams` (`oauth/bind.go`) — form-urlencoded + JSON. HTTP Basic > body credentials on `/token`, `/introspect`, `/revoke`, `/par` (RFC 6749 §2.3.1).

| Handler | Spec | File |
|---|---|---|
| Authorization code | RFC 6749 §4.1 | `auth_code.go` |
| Client credentials | RFC 6749 §4.4 | `client_creds.go` |
| Refresh token + rotation | RFC 6749 §6 | `refresh_token.go` |
| Device code | RFC 8628 | `device_code.go` |
| PAR | RFC 9126 | `handle_par.go` |
| DCR | RFC 7591/7592 | `handle_register.go` |
| Introspection | RFC 7662 | `handle_introspect.go` |
| Revocation | RFC 7009 | `handle_revoke.go` |
| CIBA (poll+ping) | OIDC CIBA | `ciba.go` + `handle_ciba.go` |
| Token exchange | RFC 8693 | `token_exchange_helpers.go` |

**Config knobs:**

| YAML | Effect |
|---|---|
| `oauth.<store>.backend` | `memory`\|`sqlite` per store |
| `oauth.jar` | RFC 9101 §5.2.2 request_uri fetcher (HTTPS, no-redirect) |
| `dpop.{proof_max_age,max_clock_skew}` | DPoP iat-window (default 60s each); 0 = SDK default (byte-identical) |
| `security.jti_replay.fail_closed` | Store error → reject (treat-as-replay) instead of fail-open |
| `identity.client_cache.{enabled,ttl}` | Per-login ClientStore.Get TTL cache (default 30s); `KindClientChange` bus-invalidated on every mutation |

**Hard constraints:**
- Oracle-leak collapse: unknown/expired/consumed/mismatch → one response (§4).
- Single-use via `DELETE … RETURNING`.
- Refresh family: `FamilyID` through every rotation; reuse → `DeleteFamily` → `invalid_grant`.
- `WithRefreshRotationGrace(window)`: concurrent double-submit idempotent within window; post-window replay still kills family.
- Optional velocity cap (`RefreshTokenRotationLimiter`): over-cap → same `DeleteFamily` + `invalid_grant` (oracle-safe), fail-OPEN on store error.

### OIDC Layer (`oidc/`)

**Input:** Requests routed from `handlers.go`. MUST NOT import `oauth/` (cycle).

| Handler | Key behavior |
|---|---|
| JWKS | `Cache-Control: public, max-age=<ttl>` + `ETag=sha256(body)[:8]` (default 5min); concurrent computes single-flighted |
| Discovery | Derived from server state; double-cached (`WithDiscoveryCacheTTL` 5s snapshot + `WithDiscoveryDocCacheTTL` 5s body+ETag per base URL); `If-None-Match` → 304; TTL 0 disables cache AND headers |
| EndSession | RP-Initiated Logout |
| SilentRenewal | `prompt=none` (requires `WithSessionManager` + `WithIDTokenIssuer`) |
| FormPost | OIDC Form Post Response Mode |
| JARM | `response_mode={jwt,query.jwt,fragment.jwt,form_post.jwt}` via `WithJARM(signer)`; fail-closed without |

**Config knobs:**

| YAML | Effect |
|---|---|
| `server.issuer` | MUST differ from `sso.DefaultIssuer`; stamped into JWT `iss`, discovery `issuer`, every RFC 9207 `iss` |

**Hard constraints:**
- `at_hash` stamped whenever `access_token` rides the same response (hash per id_token signing alg; left-half base64url; empty → omitted).
- New opt-in feature → branch the discovery doc.
- Token strategies (`jwt`\|`session`) registered via `sso.WithTokenIssuer(name, issuer)`.

### Security Layer (`security/`)

| Module | Function | Hard constraint |
|---|---|---|
| `account_lockout.go` | Per-account lockout | `BEGIN IMMEDIATE` RMW; `WithAccountLockout` |
| JTI replay | Replay prevention | `SET NX EX`; fail-open default; `WithJTIReplayFailClosed` for strict |
| `jar_fetch.go` | RFC 9101 JAR URL fetch | HTTPS only, no-redirect; bounded; best-effort internal-IP block |
| `jwe.go` | JWE decryption (JAR-in, id_token-out, userinfo-out) | RSA-OAEP-256+A256GCM / ECDH-ES / Multi (composes both) |
| `step_up_auth.go` | RFC 9470 step-up helper | Resource-server side |
| `pairwise.go` | Pairwise subject derivation | Opt-in per-client |
| `spiffe_svid.go` | SPIFFE JWT-SVID validation | `WithSPIFFEJWTSVID`; strict `aud`+trust-domain; all failures → `invalid_grant` (oracle-safe) |

**Alg allowlist (`AsymmetricJWSAlgs`):** EdDSA / ES256/384/512 / RS256 / PS256. No `alg=none`, no HS\*. Checked BEFORE signature verify. New signer → extend `supportedJWTAlgs` explicitly.

**Config knobs:**

| YAML | Effect |
|---|---|
| `security.mtls.backend` | `tls`\|`header`; `header` for reverse-proxy edges (`X-SSL-Client-Cert`); edge MUST strip from untrusted traffic |
| `spiffe.{enabled,trust_domain,audience,jwks_file,max_clock_skew}` | Enabled requires ALL of `trust_domain`+`audience`+`jwks_file`; cmd fails loud on missing |

### Signing-Key Lifecycle (`defaultimpl/`)

**Issuers:** `Ed25519JWTIssuer`, `ECDSAJWTIssuer`, `RSAJWTIssuer`. Each accepts ONLY its own alg (structurally alg-confusion-safe). External signer via `With{Algo}ExternalSigner` → `defaultimpl/cryptosigner` bridges `crypto.Signer` (ECDSA DER→R‖S; ECDSA = ES256/P-256 only through bridge).

| KMS peer | ECDSA out | Ed25519 | Constraint |
|---|---|---|---|
| `kms/awskms/` | DER | No → `ErrUnsupportedKey` | Private key never leaves HSM |
| `kms/gcpkms/` | DER | Yes (`EC_SIGN_ED25519`, un-prehashed) | Key = CryptoKeyVersion |
| `kms/pkcs11/` | RAW R‖S→DER | Yes (`CKM_EDDSA`) | CGO required |
| `kms/azurekeyvault/` | RAW R‖S→DER | No → `ErrUnsupportedKey` | Own signing pubkey from raw JWK |
| `defaultimpl/vaulttransit/` | DER (asn1) | Yes (raw message un-prehashed) | `https`-only TLS; token never logged |

**Config knobs:**

| YAML | Effect |
|---|---|
| `keys.signing.alg` | `eddsa`\|`es256`\|`rs256`\|`ps256` |
| `keys.rotation.*` | Wires `StartRotation` loop; emits `signing_key_rotated` audit + `sso_signing_key_rotations_total`; busts signed-discovery cache |
| `keys.rotation.coordinated_cutover` | `WithCoordinatedKeyRotation`: broadcasts demoted+new kids + `now+GracePeriod` retire deadline over `cluster.Bus` (`KindSigningKeyRotation`); FAIL-SAFE: deferred retire only widens verify window, never retires early |
| `keys.signing.revocation_backend` | `With{Algo}RevocationStore` for durable revocation across restarts; `SeedRevocations` re-seeds at boot |
| `keys.signing_key_registry.{backend,replica_id,lease_ttl}` | Opt-in leaderless aggregation (`memory`\|`etcd`). `WithSigningKeyReplicaID` REQUIRED when wired. Degraded → `/readyz` 503 + `signing_key_aggregation_degraded` audit |

**Hard constraints:**
- `RotateKey`/`RetireKey`: overlap-window; demoted key stays verify-only through TTL.
- Leaderless: peer-key adoption is alg-matched BEFORE install (RS256≠PS256 skipped); decode failure OPEN; adopted keys in separate verify set untouched by local rotate/retire. Re-publish on rotation.

### Storage Substrate

**SQLite (`defaultimpl/sqlite/`):**

| Pattern | Used for |
|---|---|
| `DELETE … RETURNING` | Single-use stores (AuthCode/Refresh/Device/PAR) |
| `UPDATE … RETURNING WHERE expires_at>now AND revoked=0` | Session refresh |
| `INSERT … ON CONFLICT` | JTI/index upserts |
| `BEGIN IMMEDIATE` | Lockout RMW |

Prod DSN: `file:/var/lib/sso/sso.db?_journal=WAL`. Tests: `file::memory:?cache=shared`. `sql.ErrNoRows` → typed `ErrNoSuchX`; timestamps Unix-ns INTEGER.

**Redis (`redis/`, nested module):** >1k-QPS multi-replica scale layer. Consume = GETDEL; session Refresh = Lua (refuses expired/revoked before extending); JTI = SET NX EX; ratelimit = Lua INCR+EXPIRE (fixed-window, fail-OPEN); CIBA SetStatus = Lua KEEPTTL; device user_code = pointer key. Fail-CLOSED on `/token`.

**Migrations (`migrate/`):** Forward-only; `BEGIN IMMEDIATE`; per-namespace `schema_migrations_<ns>`; v1 = existing schema (populated DBs no-op + stamp). New column/index → append v2+. Offline: `sso-migrate status --dsn`.

**Backend YAML toggles:**

| Subsystem | Key |
|---|---|
| Identity (User/Client/Session) | `identity.backend` |
| OAuth stores | `oauth.<store>.backend` |
| JTI replay / Lockout | `security.{jti_replay,account_lockout}.backend` |
| Pairwise / BCL index | `server.pairwise_subjects.backend` / `backchannel_logout.index.backend` |
| Rate limiter | `security.rate_limit.backend` |
| WebAuthn | `webauthn.storage.{users,sessions}.backend` |
| MFA / Push / CIBA | `mfa.{challenge,provider.push}.backend` / `ciba.backend` |
| Audit / Permissions | `audit.backend` / `permissions.backend` |
| Tenants + Domains | `tenant.backend` |
| Anomaly detectors | `anomaly.{recent_login,ip_failure}.backend` |
| Signing-key registry | `keys.signing_key_registry.backend` |
| Network policy / Registry | `network.store.backend` / `registry.backend` |

### Audit (`audit/`)

**Pipeline:** Compose `Async → Multi → Retry → leaf`. Hash chain: `PrevHash`+`Hash`; verify via `sso-audit-verify`. Bounded dimensions: outcome/type/client/provider (§4 cardinality rule).

**Hard constraints:**
- Use `SetMeta(e, k, v)`. NEVER `e.Metadata = map{...}` (clobbers enrichment).
- Every Event carries W3C `TraceID`/`SpanID`.
- Optional `FacetQuerier` (type-asserted, `GET /api/v1/audit/facets`); 501 when unsupported.

**Retention schedulers:**

| YAML | Function | label |
|---|---|---|
| `audit.retention.*` | `audit/sqlite.Sink.Prune` | `audit` |
| `snapshot.retention.*` | `snapshot.PruneOldest` | `snapshot` |
| `mfa.provider.push.prune_interval` | `sqlite.PushApprovalStore.PruneExpired` | `push_approvals` |

**Metrics (bounded cardinality — no per-path/per-user labels):**

| Metric | Type | Labels |
|---|---|---|
| `sso_http_requests_total` | Counter | method, status_class |
| `sso_http_request_duration_seconds` | Histogram | method |
| `sso_login_attempts_total` / `_duration_seconds` | Counter/Histogram | provider, outcome |
| `sso_tokens_issued_total` | Counter | strategy |
| `sso_risk_decisions_total` | Counter | decision |
| `sso_mfa_challenges_total` | Counter | mfa_method |
| `sso_mfa_completions_total` / `_duration_seconds` | Counter/Histogram | mfa_method, outcome |
| `sso_webauthn_{registrations,assertions}_total` | Counter | outcome |
| `sso_credential_health_signals_total` | Counter | signal |
| `sso_signing_key_rotations_total` | Counter | — |
| `sso_signing_operations_total` / `_duration_seconds` | Counter/Histogram | alg, outcome / alg |
| `sso_signing_backend_up` | Gauge | alg |
| `sso_signing_key_adoption_errors_total` | Counter | reason (decode\|adopt) |
| `sso_signing_key_aggregation_up` | Gauge | — |
| `sso_signing_key_cutover_total` | Counter | outcome |
| `sso_token_revocations_propagated_total` | Counter | direction (published\|adopted) |
| `sso_fapi_violations_total` | Counter | rule, mode |
| `sso_ciba_ping_total` | Counter | outcome |
| `sso_caep_sets_total` | Counter | outcome |
| `sso_refresh_rotation_velocity_exceeded_total` | Counter | — |
| `sso_client_store_cache_total` | Counter | outcome (hit\|miss) |

**Config knobs:**

| YAML | Effect |
|---|---|
| `metrics.tenant_label_allowlist` | `WithTenantMetricsAllowlist` — bounded per-tenant login/issue metrics + `"other"` bucket; empty = off |

### Admin / gRPC (`grpcserver/`)

**Auth:** `sso.AdminMiddleware` validates Bearer; requires `admin:read`/`admin:write` (`admin:*` ⊇ both). Every mutation emits `admin_*` audit. 401 carries `Bearer realm="admin"`. Protected paths: `/api/v1/audit/*`, `/netpolicy/policies*`, `/classify`, `/api/v1/compliance/*`; `/netpolicy/resolve-me` stays open.

| Phase | Services | REST prefix |
|---|---|---|
| A | `audit.v1.AuditWriter`, `authz.v1.Authorizer`, `discovery.v1.Discovery` | — |
| B | `netpolicy.v1.PolicyService` | `/api/v1/netpolicy/` |
| C | `admin.v1.{Client,User,Token,Permission}AdminService` | `/api/v1/admin/` |
| D | `admin.v1.{Snapshot,Release}AdminService` | `/api/v1/admin/{snapshots,releases}` |
| E | `admin.v1.TenantAdminService` | `/api/v1/admin/{tenants,domains}` |

gRPC services reuse the same `audit.Recorder` / `permissions.Provider` / `registry.Registry` as HTTP.

### Cluster / Multi-Replica (`cluster/`)

**Bus event kinds:** `KindTokenRevoked`, `KindSigningKeyRotation`, `KindClientChange`, `KindAuthzPolicyChange`.

| Feature | Config | Behavior |
|---|---|---|
| Cross-replica revocation | `WithCrossReplicaRevocation` | Broadcasts revoked token+exp; peers adopt local-only; additive, oracle-safe, fail-open, no re-broadcast |
| Coordinated key cutover | `WithCoordinatedKeyRotation` | See Signing-Key Lifecycle |
| Client cache invalidation | `identity.client_cache.enabled` | `KindClientChange` busts per-login TTL cache on every client mutation |
| Authz policy invalidation | `WithAuthzPolicyBundleCacheTTL` (default 5m) | `KindAuthzPolicyChange` via `InvalidateAuthzPolicyBundleCache`; fail-open |

### Tenant, Residency & Geo

| Module | Trigger | Config | Hard constraint |
|---|---|---|---|
| Tenant resolution | `Client.TenantID` set | `tenant.backend` | Mismatch → 403 `tenant_mismatch`; empty = any |
| Tenant suspension | `WithTenantSuspensionCheck(ttl)` | `tenant.suspension_check.cache_ttl` (default 30s) | Suspended → `ErrTenantSuspended`; fail-OPEN on outage; admin SetStatus MUST call `InvalidateTenantSuspensionCache` |
| Multi-region residency | `WithRegionMiddleware` + `WithTenantResidencyCheck(ttl)` | `region.{serving_region,header_name,allowed_regions,residency_check_cache_ttl}` | Write-gate on login mint; read-gate on resource access; fail-OPEN on outage; `region_not_allowed`/`residency_violation` are governance codes (NOT credential oracles); admin mutation MUST call `InvalidateTenantResidencyCache`; neither field set → NOT installed (byte-identical) |
| Geo enrichment | Always if wired | — | UX hint only, NOT security; 200ms timeout; fail-open |

### Permissions (`permissions/`)

| Feature | Detail |
|---|---|
| Wildcard semantics | `user:*` ⊇ `user:read`; `*` ⊇ all; MUST pass `permissionstest.ConformanceSuite` |
| Login embedding | `WithEmbedPermissionsInLogin()` |
| Policy-bundle export | `GET /api/v1/admin/authz/policy-bundle?client_id=` (admin:read) — role DEFINITIONS only, NOT per-subject assignments; ETag-cached; 304 on `If-None-Match` |
| SQLite peer | 3 tables; `RemoveRole` transactionally strips code from every assignment |

### Risk Scoring & Anomaly Detection

| Module | Config | Behavior |
|---|---|---|
| Risk scorer | `WithRuleBasedRiskScorer` | Runs AFTER creds, BEFORE issuance → `Allow`/`RequireMFA`/`Deny` (403); fail-open, zero overhead when unset |
| MFA orchestration | `WithMFAProvider` + `WithMFAChallengeStore`; `mfa.provider.kind`: `totp`\|`webauthn`\|`push`\|`multi` | Two-leg step-up gated by Risk `RequireMFA`; without both → decays to Allow. `/auth/login` → `{mfa_required, mfa_challenge_id, mfa_methods, iss}`; client POSTs `/auth/mfa` |
| Anomaly runner | `anomaly.runner.inspect_timeout` (default 5s) | Async, OFF the request path; 1024 queue / 4 workers / drop-newest; NEVER feeds back into auth decision |
| Password health | `WithPasswordHealthChecker` | Fail-open; result in `AuthResult.CredentialHealth` (`json:"-"`, NEVER in tokens — keep off `Attributes`); surfaces as `password_weak`/`password_compromised` audit (Outcome=success) |

### Authenticators (`authenticators/`)

9 pluggable: `password`, `phone`, `email`, `temp_token`, `keypair`, `apikey`, `certificate`, `totp`, `oidc_federation`. Unknown password users → cost-matched dummy bcrypt hash (anti-enumeration). WebAuthn ceremony cmd-mounted at `/webauthn/{registration,login}/{begin,finish}`.

| WebAuthn attestation config | Constraint |
|---|---|
| `webauthn.attestation.policy_mode` (`off`\|`allowlist`\|`denylist`) | Active mode REQUIRES `conveyance: direct\|enterprise` (boot fails otherwise) + ≥1 AAGUID |
| `webauthn.attestation.mds.*` | `BuildMDSProvider` (JWS-rooted at FIDO ProductionMDSRoot; startup snapshot; reload by restart) makes gate adversary-resistant |
| Off / nil | Byte-identical |

**Hard constraint:** Without MDS, the gate is an operational control only (honest-client gating) — a hostile registrant can craft a self-signed x5c asserting an allowlisted AAGUID.

### Federation (`federation/`)

| Slice | Endpoint | Trigger | Hard constraint |
|---|---|---|---|
| 1 — Entity Config | `/.well-known/openid-federation` | `WithFederationEntity(cfg, signer)` | `iss==sub==issuer`; metadata DERIVED from discovery (byte-identical); signing failure → 500 |
| 2 — Trust-Chain Resolution | internal `TrustChainResolver` | `ResolveTrustChain(ctx, leafEntityID)` | FAIL-CLOSED; all failures → `ErrTrustChainInvalid` (oracle-safe); anchor keys NEVER fetched; path-length + cycle + total-fetch bounds |
| 3 — Auto-Registration | existing `ClientStore.Get` MISS | `WithFederationAutoRegistration()` | Pre-registered client WINS; chain failure → byte-identical `invalid_client`; `Secret=""` NEVER; REQUIRES `WithClientStore`+`WithFederationEntity` with anchors else INERT |
| 4 — Constraints + Trust Marks | additive gate on 2/3 | `EntityConstraints` + `RequiredTrustMarkTypes` | Any fail → slice-3 unknown-client path (oracle-safe) |
| 5 — §8 Fetch (superior) | `/fetch` | Subordinates configured | Statements AUTHORED from operator config, NOT request input; route mounted ONLY when subordinates configured (else slice-1 byte-identical) |

### CAEP / Shared Signals (`caep/`)

| Direction | Config | Scope constraint |
|---|---|---|
| Transmitter | `WithCAEPTransmitter` | Push ONLY to the AFFECTED client's receiver; client-named events → that client; tenant events → `ListByTenant` of THAT tenant only (no cross-tenant leak); async best-effort, fail-open |
| Receiver | `WithCAEPReceiver` (`/ssf/receive`) | Inbound SETs from CONFIGURED trusted transmitters only; FAIL-CLOSED; jti-replay verified; errors → `invalid_key` |

Receiver endpoint from `Client.Attributes["caep_receiver_endpoint"]` (HTTPS, validated at create/update — NEVER request input). Config: `caep.{enabled,receiver_timeout,set_ttl}`.

### Bootstrap, Snapshot & Releases

| Module | Key behavior | Hard constraint |
|---|---|---|
| `bootstrap/` | Versioned; re-runs only `Version > high-water`. Built-in v2 prints generated admin password ONCE to stdout. | Lock: `noop`\|`file`\|`etcd`; loss → `ErrLockLost` cancels in-flight steps |
| `snapshot/` | Modes: `ModeMerge`\|`ModeOverwrite`\|`ModeReplace` (requires `Confirm==SnapshotID`). Encryption: `none`\|`passphrase`\|`aes-gcm`. | `snapshot.redact_secrets` zeros `Client.Secret` on export-local COPIES (NOT restorable — use encryption for backup); default nil ⇒ byte-identical |
| `releases/` | `Validate` refuses one-sided. `Pin` rejects schema regression (`ErrSchemaRegress`). `HealthProbe` gates forward (all-fail → auto-rollback). | — |

### Network Policy & Service Registry

| Module | Backend | Key behavior |
|---|---|---|
| `netpolicy/` | `memory`\|`etcd` via `network.store.backend` | Named CIDR/hostname/URL classes; `Classifier` holds hot snapshot via `Store.Watch`; seeded via `config.ApplyNetworkPolicySeeds` |
| `registry/` | `memory`\|`etcd` via `registry.backend` | cmd self-registers `Name:"sso"`, `ID = registry.service_id` (default `<issuer>-<short-hostname>`; prevents replica clobber), TTL 30s under etcd |

**Config:** Hostname-beats-CIDR, priority breaks ties. Subscribe BEFORE seed `Reload` to avoid lost events.

---

## 3. Feature Matrix

| Spec | Endpoint(s) | Opt-in | File |
|---|---|---|---|
| RFC 6749 §4.1 authorization_code | `/auth/login` + `/token` | `WithAuthCodeStore` | `oauth/auth_code.go` |
| RFC 6749 §4.4 client_credentials | `/token` | always | `oauth/client_creds.go` |
| RFC 6749 §6 refresh_token | `/token` | `WithRefreshTokenStore`; grace: `WithRefreshRotationGrace(window)` | `oauth/refresh_token.go` |
| RFC 7636 PKCE | `/auth/login` + `/token` | per-request / `Client.RequirePKCE` | `oauth/auth_code.go` |
| RFC 7662 introspection | `/token/introspect` | always | `oauth/handle_introspect.go` |
| RFC 7009 revocation | `/token/revoke[-all]` | always; bulk: `RefreshTokenSubjectIndex`; cross-replica: `WithCrossReplicaRevocation`; durable: `With{Algo}RevocationStore` | `oauth/handle_revoke.go` |
| RFC 8628 device | `/device/{code,verify}`, `/token` | `WithDeviceCodeStore` | `oauth/device_code.go` |
| RFC 8693 token-exchange | `/token` | always; refresh: `WithRefreshTokenStore`; actor replay: `WithJTIReplayStore` | `handlers.go` + `oauth/token_exchange_helpers.go` |
| RFC 8707 resource indicators | every issuance | `Client.AllowedResources` | per-grant |
| RFC 9126 PAR | `/par` | `WithPARStore` | `oauth/handle_par.go` |
| RFC 7591/7592 DCR | `/register[/:id]` | `WithDynamicClientRegistration` | `oauth/handle_register.go` |
| OIDC Core ID Token | `id_token` w/ `openid` | `WithIDTokenIssuer`; `at_hash` when `access_token` in same response | `handler.go` + `oidc/userinfo_signing.go` |
| OIDC Discovery 1.0 | `/.well-known/openid-configuration` | always | `handlers.go` + `oidc/discovery_doc_cache.go` |
| OIDC RP-Initiated Logout | `/end_session` | always | `oidc/handle_end_session.go` |
| OIDC BCL 1.0 | `/logout`, `/end_session` | `WithBackchannelLogout`; multi-RP: `WithSubjectClientIndex` | `server_extensions.go` |
| OIDC FCL 1.0 | `/end_session` | `Client.FrontchannelLogoutURI` | `server_extensions.go` |
| OIDC `sid` claim | access + id + logout | `WithSessionManager` | `defaultimpl/ed25519_jwt_issuer.go` |
| OIDC `login_hint` | `/auth/login`, `/par`, JAR | always | `handler.go` + `oauth/par.go` + `server_extensions.go` |
| OIDC Form Post | `/auth/login`, `/par`, JAR | always | `oidc/form_post.go` |
| JARM | `response_mode={jwt,query.jwt,fragment.jwt,form_post.jwt}` | `WithJARM(signer)` (fail-closed without) | `oidc/jarm.go` |
| OIDC `prompt=none` | `/auth/login` | `WithSessionManager` + `WithIDTokenIssuer` | `oidc/handle_silent_renewal.go` |
| RFC 7521+7523 `private_key_jwt` | `/token`, `/par`, `/introspect`, `/revoke` | `Client.JWKS`; sig via `AsymmetricJWSAlgs` | `server_extensions.go` |
| RFC 9207 AS Issuer Id | every `/auth/login` | always | `handlers.go` |
| RFC 9068 JWT Access Token | JWT access tokens | always; alg gate `WithSupportedSigningAlgs` | `defaultimpl/{ed25519,ecdsa,rsa}_jwt_issuer.go` |
| RFC 8705 mTLS-bound + aliases | `/token` + `/userinfo` | `WithClientCertExtractor` | `server_extensions.go` |
| RFC 9470 Step-Up | resource-server helper | always | `security/step_up_auth.go` |
| RFC 9449 DPoP | `/token` + `/userinfo` | header-triggered; replay: `WithJTIReplayStore`; nonce: `WithDPoPNonceProvider` | `server_extensions.go` |
| RFC 8414 §2.1 signed_metadata | discovery | `WithMetadataSigner` | `handlers.go` |
| OAuth 2.1 strict | `/auth/login` | `WithOAuth21StrictMode` | `handler.go` |
| FAPI 2.0 profile | `/auth/login` + `/token` + discovery | `WithFAPIProfile(Inspection\|Enforce)` | `fapi/` + `handler.go` |
| RFC 9396 RAR | `authorization_details` | per-client allowlist | `oauth/rar.go` |
| RFC 9101 JAR | `request`, `request_uri` | `Client.JWKS`; URL fetch: `WithJARFetcher`; required: `Client.RequireSignedRequestObject` | `server_extensions.go` + `security/jar_fetch.go` |
| RFC 9101 §6.4 JWE JAR | `request` (JWE) | `WithJARDecrypter`; enc key in JWKS `use:enc` | `security/jwe.go` |
| OIDC §10.2 id_token JWE | `id_token` (encrypted) | `WithJWEResponseEncrypter` + per-client `IDTokenEncryptedResponseAlg/_Enc` | `oidc/userinfo_signing.go` |
| OIDC §5.3.2 userinfo JWE | `/userinfo` (encrypted) | `WithJWEResponseEncrypter` + per-client `UserinfoEncryptedResponseAlg/_Enc` | `oidc/userinfo_signing.go` |
| OIDC CIBA (poll+ping) | `/backchannel-authentication`, `/token` | `WithCIBA`; ping: `WithCIBAPingNotifier` | `oauth/ciba.go` + `oauth/handle_ciba.go` |
| MFA orchestration | `/auth/login` + `/auth/mfa` | `WithMFAProvider` + `WithMFAChallengeStore` | `handlers.go` + `spi/mfa.go` |
| Per-account lockout | `/auth/login` | `WithAccountLockout` | `security/account_lockout.go` |
| SPIFFE JWT-SVID token-exchange | `/token` | `WithSPIFFEJWTSVID(trustDomain, audience, JWKSSource)` | `security/spiffe_svid.go` |
| OpenID SSF v1 SET transmitter | push to RP receiver | `WithCAEPTransmitter` | `caep/` |
| OpenID SSF v1 SET receiver | `/ssf/receive` | `WithCAEPReceiver` | `caep/receiver.go` |
| Envoy ext_authz HTTP | `/mesh/ext-authz` | `WithMeshExtAuthz(path)` | `handler.go` + `mesh_authz.go` |
| Envoy ext_authz gRPC | `envoy.service.auth.v3.Authorization` | `extauthz` nested module | `extauthz/authz.go` |
| SAML 2.0 SP+IdP | `/auth/saml/*`, `/saml/*` | `saml` nested module | `saml/saml.go` |
| Kerberos/SPNEGO | `/auth/kerberos` | `kerberos` nested module | `kerberos/handler.go` |
| RADIUS authenticator | via `WithAuthenticator` | `radius` nested module | `radius/authenticator.go` |
| WebAuthn attestation policy | `/webauthn/registration/finish` | `webauthn.Config.{AttestationConveyance,AttestationPolicy,MDS}` | `authenticators/webauthn/` |
| Multi-region data residency | `/auth/login` + `/userinfo` + mesh + WebAuthn | `WithRegionMiddleware` + `WithTenantResidencyCheck` | `region/region.go` + `server_extensions.go` |
| SCIM 2.0 | `/api/v1/scim/v2/` | `scim.NewHandler(users, basePath, ...)` | `scim/handler.go` |
| OpenID Federation 1.0 (5 slices) | `/.well-known/openid-federation`, `/fetch` | `WithFederationEntity(cfg, signer)` | `federation/` + `handlers.go` + `sso.go` |

---

## 4. Global Constraints & Edge Cases

### Wire-Contract Invariants (GATES — violations are regressions)

**SPI + Storage**
- Every concern = interface + `memory` impl ± `sqlite`/`etcd`/`file`. New backends via `WithXxx`. No mocks — use Memory* in tests.

**Form + JSON**
- All OAuth/OIDC endpoints: `bindOAuthParams` (`oauth/bind.go`). Accepts form-urlencoded + JSON.

**Oracle-Leak Hardening**

| Scenario | Required response |
|---|---|
| AuthCode/Refresh/Device/PAR: unknown/expired/consumed/client-mismatch on `/token` | `400 invalid_grant` |
| Stale/missing PAR `request_uri` on `/auth/login` | `invalid_request_uri` |
| DPoP/mTLS failure | `invalid_token` |
| `private_key_jwt` | `invalid_client` |

**Anti-Enumeration**

| Endpoint | Required behavior |
|---|---|
| `/register/:client_id` | Missing/wrong/unknown bearer → identical 401 `invalid_token` (subtle compare) |
| `/token/revoke` | 200 on valid client creds regardless of token existence |
| `/token/introspect` inactive | `{"active":false}` |
| bcrypt (unknown user) | Cost-matched dummy hash |
| WebAuthn (unknown user/session) | `404 session_invalid` |
| MFA `/auth/mfa` | Unknown/expired/consumed/unsupported/wrong factor → `400 mfa_invalid`; detail ONLY in `mfa_failure` audit |

**Fail-Open** (log + continue): refresh issuance, ID Token issuance, geo, risk-scorer error, audit Sink error, tenant-suspension outage, JTI-replay store error (default).

**Fail-Closed**: refresh rotation grant (500), signature/validation failure, scope expansion, family reuse → `DeleteFamily` → `400 invalid_grant`.

**PKCE:** `code_challenge` captured at `/auth/login`; verified at `/token` `grant=authorization_code` only. Refresh carries no verifier (bound via `client_id`).

**Refresh-Token Family Rotation:**
- `FamilyID` carried through every rotation.
- `RefreshTokenFamilyTracker`: replay → `ErrRefreshTokenReused` → `DeleteFamily` → audit `refresh_token_reuse_detected` → `invalid_grant`.
- Empty `FamilyID` opts out.
- `WithRefreshRotationGrace(window)`: concurrent double-submit idempotent within window; post-window replay still kills family (§4.13 unweakened).
- Optional velocity cap (`RefreshTokenRotationLimiter`): over-cap → same `DeleteFamily` + `invalid_grant` (oracle-safe), fail-OPEN on store error, audit `refresh_rotation_velocity_exceeded`.

**Session Refresh:** Refuses expired/revoked rows BEFORE extending. Forward/monotonic wall clock assumed — ops MUST slew, never step (chrony).

**Audit Metadata:** Use `SetMeta(e, k, v)`. NEVER `e.Metadata = map{...}` (clobbers enrichment).

**X-Forwarded-* Trust:** `requestBaseURL` + geo + host honor first-hop XFF — ONLY safe behind a trusted edge that strips + re-sets them. Same model governs `security.mtls.backend: header`, ratelimit IP keying, and mesh `X-Auth-*` headers (mesh MUST strip client-supplied `X-Auth-*` at ingress).

**`aud` Claim:** Unmarshals string or array (RFC 7519 §4.1.3); marshals single-aud as compact string per OIDC.

**`alg` + `typ` Allowlist:** Checked BEFORE signature verify. `alg=none` rejected. New signer → extend `supportedJWTAlgs` explicitly.

**RFC 9068 Claims (REQUIRED on every Issue):**
- MUST set `Subject.ClientID`.
- Login: `AuthTime`+`AMR` from live event (`amrForResult` = `AuthResult.AuthMethods`; falls back to provider id); `acr` from `AuthResult.AchievedACR` (empty → omitted). MFA second leg: `withMFAMethod` folds factor + `mfa`.
- `auth_code` grant: stamps `auth_time` from `AuthCode.AuthTime` (the real `/auth/login` moment, NOT exchange time); AMR = stored provider id.
- Refresh: propagates original AMR without resetting `AuthTime`.
- Token-exchange: propagates `AuthTime`+`ACR`+`AMR`+`SID` from inbound `subject_token`; multi-hop `act` chain prepended (time-ordered).
- `client_credentials`: `ClientID` only.
- `jti`: always auto-generated.

**RFC 9207 `iss` on Authorization Responses:** Every `/auth/login` response uses `s.resolveIssuer(ctx)`. New authz handlers MUST use `s.authzErrorBody(ctx, code)`, not `errorBody`.

**Cache Headers on Credential Endpoints:** `/token`, `/introspect`, `/revoke[-all]`, `/par`, `/auth/login`, `/userinfo`, `/register*` → `tokenNoStoreHeaders(ctx)` = `Cache-Control: no-store` + `Pragma: no-cache`. Including error responses.

**WWW-Authenticate on 401:** `setBearerChallenge`: missing token omits `error=`; validation failure carries `error="invalid_token"`. Descriptions via `security.QuoteAuthParam`.

**Discovery is derived** from server state. New opt-in → branch the discovery doc. New bearer endpoint → `tokenNoStoreHeaders` + `setBearerChallenge`.

### Coding Conventions

- **No literal leaks** — paths/headers/error codes in `consts.go` (root or per-package).
- **No mocks** — use real `MemoryProvider`/`MemorySink`/`memory.Registry`.
- **No emojis** in code, comments, or commits.
- **Comments explain WHY** — hidden constraints, invariants, workarounds only. Never "what".
- **Interface guards** in implementation packages (e.g. `var _ ssoclient.AuthClient = (*remote.AuthClient)(nil)`). Never in the interface package (cycle).
- **gRPC names:** protoc-gen-go does `ID→Id`, `URL→Url`.
- **Tests:** Subpackage unit tests beside the code. Cross-server integration tests → `test/` (`package ssotest`, shared harness). Race fixes prove with `-count=10+`.
- **Hexagonal extraction:** Handler bodies → `oauth/`/`oidc/` as `HandleX(deps Deps, ctx)` free functions. `*sso.Server` satisfies `Deps` via `accessors.go`. `oauth/` MUST NOT import `oidc/`.
- **Error codes:** New `Err*` → update `docs/error-codes.md` in the same commit.
- **API specs:** Documented endpoint change → update `docs/openapi.yaml` in the same commit.
- **Maintainability gates** (`docs/maintainability-gates.md`): committed tests enforce a 500-line per-file budget (`maintainability_budget_test.go`) and import boundaries (`architecture_gate_test.go`), both ratcheting. When one fails, SPLIT the file / fix the import — do NOT grow the exemption list. Add new gates as committed tests (not Makefile/CI/hooks — `make harness` clobbers those).

### Don'ts
- No `git reset --hard`, `push --force`, `branch -D` without explicit authorization.
- No git-config changes; no hook bypass (`--no-verify`/`--no-gpg-sign`).
- No mocks where an in-memory impl exists.
- No "while I'm here" cleanup/refactors; no Markdown files unless asked.
- Never violate oracle-leak / anti-enumeration patterns.
- Never bypass `SetMeta` for audit metadata.

### Common Task Patterns

| Task | Steps |
|---|---|
| New authenticator | `authenticators/<name>.go` → YAML knob in `config/config.go` → wire in `buildAuthenticators` → whitelist in `allowed_authenticators:` |
| New audit Sink | Implement `audit.Sink` (+ `audit.Closer`); wire via `audit.New(...)` / `MultiSink` |
| New permissions backend | Implement `permissions.Provider` in `permissions/<name>/`; run `permissionstest.ConformanceSuite` |
| New gRPC service | `proto/<name>/v1/<name>.proto` → regen → `grpcserver/<name>.go` → register in `newGRPCServer` → `bufconn` test |
| New OAuth/OIDC grant | `bindOAuthParams`; HTTP Basic > body creds; `400 invalid_<...>` oracle-leak; `DELETE RETURNING`; wire in `sso.go`; advertise in discovery; add `WithXxxStore`; enumerate oracle-leak cases in tests |
| New credential/bearer endpoint | `tokenNoStoreHeaders(ctx)` at entry; `setBearerChallenge(ctx, ...)` on 401 |

### Commits
Conventional (`feat(area):`, `fix(area):`, `chore:`, `docs:`). Imperative subject. Body explains why. Co-author trailer when AI-assisted. Don't commit binaries (four `cmd/` outputs are gitignored).
