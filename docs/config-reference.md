# Configuration Reference

YAML configuration knobs extracted from AGENTS.md. See [AGENTS.md](../AGENTS.md) for architectural constraints.

## OAuth

| Key | Effect |
|---|---|
| `oauth.<store>.backend` | `memory`\|`sqlite` per store |
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

## Cluster

| Feature | Config | Behavior |
|---|---|---|
| Cross-replica revocation | `WithCrossReplicaRevocation` | Broadcasts revoked token+exp; peers adopt local-only; additive, oracle-safe, fail-open, no re-broadcast |
| Coordinated key cutover | `WithCoordinatedKeyRotation` | Broadcasts demoted+new kids over `cluster.Bus`; FAIL-SAFE deferred retire |
| Client cache invalidation | `identity.client_cache.enabled` | `KindClientChange` busts per-login TTL cache on every client mutation |
| Authz policy invalidation | `WithAuthzPolicyBundleCacheTTL` (default 5m) | `KindAuthzPolicyChange` via `InvalidateAuthzPolicyBundleCache`; fail-open |

## CAEP / SSF

| Key | Effect |
|---|---|
| `caep.{enabled,receiver_timeout,set_ttl}` | SSF SET transmitter/receiver config |

## WebAuthn

| Key | Effect |
|---|---|
| `webauthn.attestation.policy_mode` | `off`\|`allowlist`\|`denylist`; active mode REQUIRES `conveyance: direct\|enterprise` + ≥1 AAGUID |
| `webauthn.attestation.mds.*` | FIDO MDS integration (JWS-rooted at production root; startup snapshot; reload by restart) |

## Snapshot

| Key | Effect |
|---|---|
| `snapshot.redact_secrets` | Zeros `Client.Secret` on export-local copies (NOT restorable — use encryption for backup); default nil ⇒ byte-identical |
