# Configuration Reference

YAML configuration knobs extracted from AGENTS.md. See [AGENTS.md](../AGENTS.md) for architectural constraints.

## OAuth

| Key | Effect |
|---|---|
| `oauth.backend` | ONE key for the four hot stores (auth_code / refresh_token / device_code / par): `memory`\|`sqlite`\|`redis` |
| `oauth.jar` | RFC 9101 §5.2.2 request_uri fetcher (HTTPS, no-redirect) |
| `dpop.{proof_max_age,max_clock_skew}` | DPoP iat-window (default 60s each); 0 = SDK default (byte-identical) |
| `security.jti_replay.fail_closed` | Store error → reject (treat-as-replay) instead of fail-open |
| `identity.client_cache.{enabled,ttl}` | Per-login ClientStore.Get TTL cache (default 30s); `KindClientChange` bus-invalidated on every mutation |

## OIDC

| Key | Effect |
|---|---|
| `server.issuer` | MUST differ from `sso.DefaultIssuer`; stamped into JWT `iss`, discovery `issuer`, every RFC 9207 `iss` |

## Security

| Key | Effect |
|---|---|
| `security.mtls.backend` | `tls`\|`header`; `header` for reverse-proxy edges (`X-SSL-Client-Cert`); edge MUST strip from untrusted traffic |
| `security.trusted_proxies.{cidrs,hops}` | CIDR allowlist for XFF-aware real-IP extraction; gates rate-limit IP keying AND geo/risk-scorer IP resolution (`WithGeoMiddlewareOptions.IPExtractor` — falls back to `X-Forwarded-For`'s raw leftmost hop when unset) |
| `spiffe.{enabled,trust_domain,audience,jwks_file,max_clock_skew}` | Enabled requires ALL of `trust_domain`+`audience`+`jwks_file`; cmd fails loud on missing |

## Signing Keys

| Key | Effect |
|---|---|
| `keys.signing.alg` | `eddsa`\|`es256`\|`rs256`\|`ps256` |
| `keys.rotation.*` | Wires `StartRotation` loop; emits `signing_key_rotated` audit + `sso_signing_key_rotations_total`; busts signed-discovery cache |
| `keys.rotation.coordinated_cutover` | `WithCoordinatedKeyRotation`: broadcasts demoted+new kids + `now+GracePeriod` retire deadline over `cluster.Bus` (`KindSigningKeyRotation`); FAIL-SAFE: deferred retire only widens verify window, never retires early |
| `keys.signing.revocation_backend` | `With{Algo}RevocationStore` for durable revocation across restarts; `SeedRevocations` re-seeds at boot |
| `keys.signing_key_registry.{backend,replica_id,lease_ttl}` | Opt-in leaderless aggregation (`memory`\|`etcd`). `WithSigningKeyReplicaID` REQUIRED when wired. Degraded → `/readyz` 503 + `signing_key_aggregation_degraded` audit |

## Storage Backend Toggles

Every store picks its substrate via a `backend:` key; `memory` is the default.
Values below are exactly what the binary's boot-time dispatch accepts
(`cmd/sso-server/serverbuild*`); an unknown value fails loud at startup.

| Store | Key | Accepted backends |
|---|---|---|
| Clients + Users (durable identity) | `identity.backend` | `memory` · `sqlite` · `postgres` |
| Sessions (hot; falls back to `identity.backend`) | `identity.session_backend` | `memory` · `sqlite` · `redis` · `postgres` |
| OAuth hot stores (auth_code / refresh_token / device_code / par — one key) | `oauth.backend` | `memory` · `sqlite` · `redis` |
| Refresh rotation grace | `oauth.refresh_token.rotation_grace_backend` | `memory` · `sqlite` · `redis` |
| CIBA requests | `ciba.backend` | `memory` · `sqlite` · `redis` |
| MFA challenge | `mfa.challenge.backend` | `memory` · `sqlite` · `redis` |
| MFA push approvals | `mfa.provider.push.backend` | `memory` · `sqlite` |
| TOTP enrollment | `authenticators.totp.backend` | `memory` · `sqlite` · `postgres` (empty infers sqlite when `sqlite_dsn` set, else memory) |
| WebAuthn passkey credentials | `webauthn.storage.users.backend` | `memory` · `sqlite` · `postgres` |
| WebAuthn ceremony sessions | `webauthn.storage.sessions.backend` | `memory` · `sqlite` · `redis` |
| JTI replay | `security.jti_replay.backend` | `memory` · `sqlite` · `redis` |
| Account lockout | `security.account_lockout.backend` | `memory` · `sqlite` · `redis` |
| Rate limiter | `security.rate_limit.backend` | `memory` · `sqlite` · `redis` |
| Pairwise subjects | `server.pairwise_subjects.backend` | `memory` · `sqlite` · `postgres` |
| BCL subject-client index | `backchannel_logout.index.backend` | `memory` · `sqlite` · `redis` |
| Native SSO device_secrets | `native_sso.backend` | off (`""`) · `memory` · `sqlite` · `postgres` |
| Self-service consent | `self_service.consent.backend` | off · `memory` · `sqlite` · `postgres` |
| Self-service password credentials | `self_service.password.backend` | off · `memory` · `sqlite` · `postgres` |
| Password reset tokens | `self_service.password_reset.backend` | off · `memory` · `sqlite` · `redis` |
| Tenants + Domains | `tenant.backend` | `memory` · `sqlite` · `postgres` |
| Tenant usage metering | `tenant.usage_metering.backend` | off · `memory` · `sqlite` (reads the audit DB) |
| B2B connections | `connections.backend` | `memory` · `sqlite` |
| Audit primary sink | `audit.backend` | `memory` · `sqlite` · `postgres` |
| Permissions | `permissions.backend` | `memory` · `sqlite` · `postgres` |
| Anomaly detectors | `anomaly.{recent_login,ip_failure}.backend` | `memory` · `sqlite` |
| Signing-key revocation | `keys.signing.revocation_backend` | `memory` · `sqlite` |
| Signing-key registry | `keys.signing_key_registry.backend` | off · `memory` · `etcd` |
| Cross-replica bus | `cluster.bus.backend` | off · `memory` · `etcd` |
| Service registry | `registry.backend` | `memory` · `etcd` |
| Network policy store | `network.store` | `memory` · `etcd` |
| Bootstrap lock | `bootstrap.lock.backend` | `noop` · `file` · `etcd` |

All `backend: redis` **hot** stores share the ONE `redis:` block below. All
`backend: postgres` **durable** stores share the ONE `postgres:` block below —
a shared *sql.DB pool per replica, not one pool per store. Selecting `redis`/
`postgres` without its block is a boot error (`<domain>.backend=postgres but no
postgres block configured (set postgres.dsn)`).

## Redis (shared hot-store backend)

One client (single/sentinel/cluster) fanned out to every `backend: redis` store.
Secrets are typically injected via env (`SSO_REDIS__PASSWORD`) not the file.

| Key | Effect |
|---|---|
| `redis.mode` | `""` (infer: master_name→sentinel, >1 addr→cluster, else single) \| `single` \| `sentinel` \| `cluster` |
| `redis.addrs` | seed addresses (≥1); >1 implies cluster unless `mode` says otherwise |
| `redis.{username,password,password_file}` | AUTH; `password_file` read + trimmed at boot |
| `redis.db` | logical DB (single/sentinel only — **cluster requires 0**, validated at boot) |
| `redis.master_name` | **required for sentinel** |
| `redis.{pool_size,min_idle_conns,max_retries}` | pool sizing; go-redis handles MOVED/ASK on cluster transparently |
| `redis.{dial,read,write,pool}_timeout`, `redis.conn_max_{idle_time,lifetime}` | timeouts; keep read/write ~200–500ms so `/token` fails closed fast |
| `redis.{route_by_latency,route_randomly,read_only}` | spread cluster reads to replicas — **leave OFF** for correctness (single-use/replay reads must hit the master) |
| `redis.tls.{enabled,ca_file,cert_file,key_file,server_name,insecure_skip_verify}` | optional TLS transport |

Operator hard requirement: the Redis auth keyspace MUST run
`maxmemory-policy noeviction` (or `volatile-ttl`) — evicting a refresh-family
ledger or jti key silently breaks reuse/replay detection (a security regression).
Single-node→cluster migration is not drop-in (hash-tag key layout changes); drain
rather than expect key continuity (acceptable — hot state is short-TTL).

## Postgres (shared durable-store backend)

One shared pool (`cmd/sso-server` `wirePostgres`) fanned out to every
`backend: postgres` store; registers a `/readyz` check named `postgres`.
`dialect: cockroach` switches advisory-locks to serialization-retry semantics.
DSN is typically injected via env (`SSO_POSTGRES__DSN`) or a `secret://` ref.

| Key | Effect |
|---|---|
| `postgres.dsn` | pgx DSN (required to enable the block). Behind a tx-mode pooler (pgbouncer) append `default_query_exec_mode=simple_protocol` |
| `postgres.dialect` | `""`\|`postgres`\|`cockroach` |
| `postgres.max_open_conns` | pool cap — N replicas x this MUST stay under DB `max_connections` |
| `postgres.max_idle_conns` | idle pool size |
| `postgres.conn_max_lifetime` / `postgres.conn_max_idle_time` | connection recycling |

See [deployment.md](deployment.md) for the HA topology and
`ops/deploy/k8s-prod/config.yaml` for the canonical production selection
(durable → postgres, hot → redis, coordination → etcd).

## Tenant & Region

| Key | Effect |
|---|---|
| `tenant.suspension_check.cache_ttl` | Cache TTL for suspension checks (default 30s); admin SetStatus MUST call `InvalidateTenantSuspensionCache` |
| `region.{serving_region,header_name,allowed_regions,residency_check_cache_ttl}` | Multi-region residency; write-gate on login mint, read-gate on resource access; admin mutation MUST call `InvalidateTenantResidencyCache` |

## Audit & Metrics

| Key | Effect |
|---|---|
| `audit.retention.*` | `audit/sqlite.Sink.Prune` |
| `snapshot.retention.*` | `snapshot.PruneOldest` |
| `mfa.provider.push.prune_interval` | `sqlite.PushApprovalStore.PruneExpired` |
| `metrics.tenant_label_allowlist` | `WithTenantMetricsAllowlist` — bounded per-tenant login/issue metrics + `"other"` bucket; empty = off |
| `audit.webhook.signing_secret` | HMAC-SHA256 payload signing on the audit `WebhookSink` — every POST carries `X-Signature: t=<unix>,v1=<hex>`; empty = off; receivers verify with `security.VerifyWebhookSignature`. Inject via env/`secret://`, never YAML literal |
| `mfa.provider.push.webhook.signing_secret` | Same HMAC-SHA256 `X-Signature` signing on the MFA push webhook transport, re-signed with a fresh timestamp per retry; empty = off. `ciba.webhook.signing_secret` shares the same `MFAPushWebhookConfig` struct, so it behaves identically for CIBA notifications |
| `config_audit.enabled` / `.backend` / `.sqlite.dsn` | Runtime-config audit (`platform/configaudit`): `GET /api/v1/admin/config/{running,applied,diff,history}` + the client/tenant/policy change-capture hook. `sso.WithConfigSnapshots` / `WithConfigAuditStore` do the actual wiring — the YAML section documents backend choice only |
| `config_audit.drift.interval` | `sso.WithConfigDriftDetection` — cross-replica config-digest broadcast (`cluster.KindConfigDigest`) + compare loop; `<= 0` (default) = off, report-only |

## Cluster

| Feature | Config | Behavior |
|---|---|---|
| Cross-replica revocation | `WithCrossReplicaRevocation` | Broadcasts revoked token+exp; peers adopt local-only; additive, oracle-safe, fail-open, no re-broadcast |
| Coordinated key cutover | `WithCoordinatedKeyRotation` | Broadcasts demoted+new kids over `cluster.Bus`; FAIL-SAFE deferred retire |
| Client cache invalidation | `identity.client_cache.enabled` | `KindClientChange` busts per-login TTL cache on every client mutation |
| Authz policy invalidation | `WithAuthzPolicyBundleCacheTTL` (default 5m) | `KindAuthzPolicyChange` via `InvalidateAuthzPolicyBundleCache`; fail-open |
| Config drift detection | `config_audit.drift.interval` / `WithConfigDriftDetection` | `KindConfigDigest` broadcast + compare; mismatch -> `config_drift_detected` audit event + `sso_config_drift_detected_total`; report-only, never blocks |

## CAEP / SSF

| Key | Effect |
|---|---|
| `caep.{enabled,receiver_timeout,set_ttl,delivery_retry_max_attempts,delivery_retry_initial_backoff,delivery_retry_max_backoff}` | SSF SET transmitter/receiver config |

## WebAuthn

| Key | Effect |
|---|---|
| `webauthn.attestation.policy_mode` | `off`\|`allowlist`\|`denylist`; active mode REQUIRES `conveyance: direct\|enterprise` + ≥1 AAGUID |
| `webauthn.attestation.mds.*` | FIDO MDS integration (JWS-rooted at production root; startup snapshot; reload by restart) |

## Snapshot

| Key | Effect |
|---|---|
| `snapshot.redact_secrets` | Zeros `Client.Secret` on export-local copies (NOT restorable — use encryption for backup); default nil ⇒ byte-identical |

## Backup

| Key | Effect |
|---|---|
| `backup.dir` | Destination directory for `POST /api/v1/admin/backup` (`VACUUM INTO` snapshots); empty (default) = OS temp dir. Filenames are timestamped (`sso-backup-<source>-<UTC stamp>.db`), so without `backup.keep` the directory grows monotonically — one file per source per triggered backup, never overwritten |
| `backup.keep` | Retain only the newest N backup files per source after each run; `0` (default) disables retention (keep all). Pruning filters on the per-source filename prefix, so unrelated files sharing the directory are never deleted |

## Feature Gates (attack-surface reduction)

| Key | Effect |
|---|---|
| `feature_gates.{oidc,ciba,caep,federation,self_service,admin_api,web_spa}` | Each is `*bool`; omitted (default) or `true` = routes mounted (today's behavior); explicit `false` = `Mount()` never registers that surface's routes — a probe gets a router-native 404, not a reachable-but-declining handler. A surface's own opt-in config (e.g. `caep.receiver`) keeps gating its routes on TOP of this — the gate never re-enables a surface that isn't otherwise wired |
| `feature_gates.oidc` | Gates `/userinfo` + `/end_session`; discovery drops `userinfo_endpoint`/`end_session_endpoint` (both `omitempty`) when off |
| `feature_gates.ciba` | Gates `POST /backchannel-authentication` (previously mounted unconditionally, 501-ing without a CIBA store — this is the first way to make it a 404 instead) |
| `feature_gates.admin_api` | Gates the ENTIRE `/api/v1/admin/*` group (incl. the new `GET /api/v1/admin/endpoints` runtime inventory); off ⇒ `Mount()` never creates the `/api/v1` admin group |
| GET `/api/v1/admin/endpoints` | Admin-gated (`admin:read`) runtime inventory: method + path + `feature_gates` surface (or `core`) for every route THIS replica actually registered |
| Startup visibility | Any explicitly-disabled gate emits a `feature_gates_disabled` audit event + log line + sets `sso_feature_gate_enabled{feature=...}` to 0 (1 for every enabled gate) — attack-surface changes are security-relevant |
