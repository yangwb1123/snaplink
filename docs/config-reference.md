# Configuration Reference

YAML configuration accepted by the stock `sso-server` binary. SDK-only options
and nested-module integration APIs are documented with their packages and are
not automatically expressible in this file. See [AGENTS.md](../AGENTS.md) for
architectural constraints.

`sso-server` is an API-only backend. It does not serve hosted-login, admin,
self-service, developer or setup frontend applications. A frontend deployment
uses the APIs below and is normally reverse-proxied beside the server.

## OAuth

| Key | Effect |
|---|---|
| `oauth.backend` | ONE key for the four hot stores (auth_code / refresh_token / device_code / par): `memory`\|`sqlite`\|`redis` |
| `oauth.jar` | RFC 9101 §5.2.2 request_uri fetcher (HTTPS, no-redirect) |
| `oauth.refresh_token.absolute_max_lifetime` | Hard ceiling on a refresh-token family's total age since original issuance, enforced at rotation independent of the per-token TTL/rotation-velocity cap; 0 (default) = no cap |
| `oauth.token_exchange.max_chain_lifetime` | Hard ceiling on an RFC 8693 token-exchange delegation chain's age (measured from the subject_token's `AuthTime`, propagated unchanged across hops); 0 (default) = no cap. The hop-authorization `TokenExchangePolicy` SPI (`domains/tokenexchange`) and act-chain cycle detection are always-on / Option-wired, not YAML-driven — see `sso.WithTokenExchangePolicy` |
| `oauth.scope_registry.{enabled,matrix,extra_scopes}` | Global scope registry (scope-matrix-v2, B4-2). When `enabled: true`, `/token` grants may only mint registered scopes — the scope-matrix-v2 table plus the pre-seeded OIDC protocol scopes (`openid`, `device_sso`, `profile`, `email`, `address`, `phone`, `offline_access`) plus `extra_scopes` — and an unregistered effective scope is rejected with the standard 400 `invalid_scope` (byte-identical plain body, no new error surface). Default-off: no block (or `enabled: false`) = byte-identical server. `matrix` provisions the table from config: absent or empty = the built-in nine-scope table (`admin:read`, `admin:write`, `billing:payment:order:read`, `billing:payment:write`, `billing:checkout:create`, `metering:write`, `billing:entitlement:read`, `audit:event:write`, `admin:*`); present = the provisioned table REPLACES the built-in at the registry construction site (provisioning is explicit and complete-table CI-verifiable). Rows follow the registry pattern grammar (exact scope or `domain:*` only); row grammar and exact-string duplicates are boot errors ALWAYS (even when `enabled: false`), mirroring `extra_scopes`. A row equal to a pre-seeded protocol scope, or listed in both `matrix` and `extra_scopes`, is an idempotent no-op (registry set semantics), not an error. When `enabled: true`, `sso-ctl config validate` ALSO fails pre-deploy (exit 1, naming the client id, scope, and key) on any `client.allowed_scopes` entry not registered by matrix ∪ protocol scopes ∪ `extra_scopes` — the exact runtime predicate, so the config gate can never disagree with `/token`; when `enabled: false` or the block is absent, no membership check runs (byte-compat pin). `extra_scopes` holds tenant RESOURCE scopes only (protocol scopes are pre-seeded; listing them is a harmless no-op) and feeds the registry only — it never expands discovery, which is filtered through the registry instead when enabled. Boot-time only — no hot-reload; enablement is a coordinated deployment-wide config change, never a per-replica toggle (replicas from the same snapshot answer identically; rollback = flip `enabled` off or drop the block). Production enablement order: land `matrix`/`extra_scopes` with `enabled: false` (grammar/duplicates still checked) → staging `config validate` pre-flight surfaces every dirty client → fix flagged clients → fleet-wide flip → rollback by dropping the block |
| `oauth.introspection.cache_ttl` | Opt-in short-lived cache for `/token/introspect` responses keyed by `SHA-256(token)` (`handler.MemoryIntrospectionCache`); 0 (default) = no caching |
| `oauth.introspection.signed_response_enabled` | Opt-in RFC 9701-style JWT-signed `/token/introspect` responses, reusing the existing signing-key infra; takes effect only when the client ALSO sends `Accept: application/token-introspection+jwt` |
| `oauth.introspection.{batch_enabled,max_batch_size}` | Opt-in `tokens` array support on `/token/introspect` (one round trip, results returned under `results`); `max_batch_size` defaults to `oauth.DefaultMaxIntrospectBatchSize` (50) when unset |
| `dpop.{proof_max_age,max_clock_skew}` | DPoP iat-window (default 60s each); 0 = SDK default (byte-identical) |
| `security.jti_replay.fail_closed` | Store error → reject (treat-as-replay) instead of fail-open |
| `identity.client_cache.{enabled,ttl}` | Per-login ClientStore.Get TTL cache (default 30s); `KindClientChange` bus-invalidated on every mutation |
| `client_registration.default_active` | `true` (default) activates a new DCR registration immediately; `false` opts into the developer-app registration review workflow — the client registers pending (`Active=false`, unable to authenticate on ANY grant) until an admin calls `POST /api/v1/admin/clients/{id}/approve` or `/reject` (`ClientAdminService`) |
| `client_registration.rotate_access_token_overlap` | Recovery window for RFC 7592 registration-token rotation. The credential used for a successful PUT remains valid for retries during this interval; `<= 0` defaults to 5 minutes. |

## Clients

| Key | Effect |
|---|---|
| `clients[].login_page_uri` | Absolute hosted-login URL used after a verified upstream OIDC/SAML callback. Required for federated RP authorization: Snaplink redirects here with a fresh one-use `login_transaction_id` in the fragment, then the page POSTs it to `/auth/login` to resume the original post-PAR/JAR request through policy, MFA, consent, and response delivery. Must be HTTPS, except HTTP loopback URLs used for local development. Missing or unsafe values make `authorization_request_passthrough_supported=false` and federated kickoff fails closed. |
| `clients[].redirect_uri_patterns` | Optional Snaplink extension for dynamic HTTPS callback paths, additive to `clients[].redirect_uris`. Each value must use a concrete host and exactly one complete interior `*` path segment bounded by literal segments (for example `https://app.example.test/test/*/callback`); host wildcards, queries, fragments, userinfo, HTTP, and invalid patterns are rejected at boot. Empty or omitted preserves exact-match-only behavior. |
| `clients[].id_token_signed_response_alg` | OIDC Core §3.1.3.1 / RFC 7591 §2 per-client ID-token signing algorithm (`id_token_encrypted_response_alg`'s signing sibling; design `docs/design/per-client-id-token-alg.md`). Empty (default) = the server's default issuer, byte-identical. When set, this client's ID tokens are signed with the named JWS algorithm; the value MUST equal the wired signing alg (`keys.signing.alg` — the cmd wires exactly one issuer) or config validation fails at boot, mirroring the DCR rule that a client may only register an alg the AS can actually produce. Product-level FAPI 2.0 unblock: an RS256 login client can coexist with ES256/PS256 FAPI clients. |

## Server

| Key | Effect |
|---|---|
| `server.http2.enabled` | Controls HTTP/2 server-side support. `false` (default) disables HTTP/2 via `GODEBUG=http2server=0` (safe behind a reverse proxy). `true` enables HTTP/2 — required for gRPC or direct-client deployments. If the `GODEBUG` env var is already explicitly set, this field is ignored (explicit env override takes precedence). See `config.HTTP2Config`. |
| `server.topology.{mode,allow_per_pod_state}` | `mode: single` declares one process; `mode: multi` makes per-process OAuth, session, replay, identity, CIBA, MFA challenge, pairwise-subject, identity-link, ReBAC, and enabled user-lifecycle stores a boot error. `allow_per_pod_state: true` is an explicit development-only escape hatch and is rejected unless mode is `multi`. |
| `server.require_form_content_type` | Opt-in strict OAuth credential wire (B4-4). When `true`, the four credential endpoints (`/token`, `/token/introspect`, `/token/revoke`, `/par`) accept ONLY `application/x-www-form-urlencoded` (RFC 6749 §3.2 / 7662 §2.1 / 7009 §2.1 / 9126 §4.1): a JSON body, a missing Content-Type, or any other media type returns `415 Unsupported Media Type` with the plain `{"error":"invalid_request"}` envelope before the body is read — nothing is minted, revoked, introspected, or stored, and every response carries `Cache-Control: no-store` + `Pragma: no-cache`. The 415 is byte-identical across the four endpoints and fires before client authentication (media-type-deterministic, never a credential oracle). Form-urlencoded requests are byte-identical to the default mode; malformed percent-encoding under a form Content-Type still takes the existing `400 invalid_request` bind-error path. Default unset/`false` = legacy JSON acceptance, byte-identical server; SDK embedders use `sso.WithCredentialFormOnly(true)`. Boot-time only, no hot-reload; rollback = drop the key or set `false`. |
| `hosted_login.enabled` | **Deprecated no-op.** The field is parsed (with a startup warning when enabled) but the stock binary has no hosted-login filesystem or route wiring, so setting it never mounts `/login/` or any other frontend. Deploy the login UI as a separate project and drive it through the APIs in [frontend-contract.md](frontend-contract.md). Do not use this key as a readiness/capability signal. Removed with the next schema-version bump. |

## OIDC

| Key | Effect |
|---|---|
| `server.issuer` | MUST differ from `sso.DefaultIssuer`; stamped into JWT `iss`, discovery `issuer`, every RFC 9207 `iss` |
| `server.required_capabilities` | Optional build/deployment contract. Startup and `--validate-only` fail closed unless every listed capability ID appears in the immutable inventory embedded by `python cli.py configure`; inspect with `sso-server modules --json` |
| `oidc.response_encryption.backend` | JWE-encrypts `id_token` + `/userinfo` responses for clients registering `id_token_encrypted_response_alg`/`userinfo_encrypted_response_alg`: `""` (off, default) \| `rsa` (RSA-OAEP-256) \| `ecdh` (ECDH-ES[+A256KW]) \| `multi` (both, routed per-client by registered key type). Stateless — reads each recipient's public key from the client's registered JWKS |
| `backchannel_logout.enabled` | Enables OIDC Back-Channel Logout for `/logout` and `/end_session`. Each RP delivery has a shared 5-second budget and retries transient transport, 408, 429, and 5xx failures up to three total attempts with jittered exponential backoff. Retry tokens are freshly signed to avoid the RP's `jti` replay guard, and delivery preserves request values while ignoring browser/gateway cancellation. |
| `backchannel_logout.max_concurrent` | Bounds simultaneous RP notifications in multi-RP fan-out; `<=0` uses 8. |
| `backchannel_logout.index.backend` | Subject-to-client fan-out index: `memory` (single replica), `sqlite`, or `redis`. Successfully notified clients are removed; failed clients remain indexed for a later logout/session-hub retry. |
| `backchannel_logout.failure_queue.backend` | Exhausted-delivery queue: `""` disables it; `memory` enables bounded process-local governance; `redis` persists failures across restart and coordinates replay leases across replicas. The queue stores subject/client/SID/URI inputs, never the signed logout token. |
| `backchannel_logout.failure_queue.retry_interval` | Background sweep cadence and first retry delay; default `30s`. Recoverable transport/timeout/408/429/5xx/issuer failures are retried; permanent RP 4xx entries remain visible for manual replay without background hammering. |
| `backchannel_logout.failure_queue.batch_size` | Maximum due entries claimed per sweep; default 50, admin list/replay APIs clamp requests to 200. |
| `backchannel_logout.failure_queue.lease_duration` | Per-entry replay ownership lease; default `30s`. Prevents concurrent workers/admins from sending one entry at the same time and expires after a crashed worker. |

When a failure queue is wired, administrators gain `GET
/api/v1/admin/backchannel-logout/failures`, single-item `POST
.../failures/{id}/replay`, and due-batch `POST .../failures/replay`. GET requires
`admin:read`; POST requires `admin:write`. Successful replay acknowledges the
entry and removes the matching subject/client fan-out index record. Shutdown
waits for the replay worker to stop before Redis closes.

## Security

| Key | Effect |
|---|---|
| `security.mtls.backend` | `tls`\|`header`; `header` for reverse-proxy edges (`X-SSL-Client-Cert`); edge MUST strip from untrusted traffic |
| `security.trusted_proxies.{cidrs,hops}` | CIDR allowlist compiled once (`peertrust.Checker`) gating proxy-supplied input on the direct peer (`RemoteAddr`): XFF client IP (rate limit, geo/risk, audit, push callback), `X-Forwarded-Host/Proto` (issuer/discovery/registration/DPoP `htu`, tenant domain routing), mesh `X-Auth-*`, serving-region headers, and header-backed mTLS certificates. Untrusted peer ⇒ direct IP/Host/TLS or the consumer's normal unauthenticated fallback. The resource-server SDK accepts the same middleware through `rs.Config.TrustedProxies`. Unset = legacy first-hop trust |
| `security.security_headers.{enabled,csp_directives,permissions_policy}` | Off by default. Adds CSP (with a per-request `script-src` nonce) + Permissions-Policy to API responses; also adds `Clear-Site-Data` on `POST /logout` and a non-dry-run `POST /me/account/erase`. Separately deployed frontends must set their own static-asset CSP. `csp_directives`/`permissions_policy` override the SDK's conservative default (`handler.DefaultSecurityHeadersPolicy`) — leave unset to use it |
| `spiffe.{enabled,trust_domain,audience,jwks_file,max_clock_skew}` | Enabled requires ALL of `trust_domain`+`audience`+`jwks_file`; cmd fails loud on missing |
| `security.rar_limits.{max_bytes,max_elements,max_depth}` | Bounds an RFC 9396 `authorization_details` payload's SHAPE (serialized size / top-level array element count / max nesting depth) BEFORE it is fully unmarshaled, on `/auth/login` and `/par`. Each sub-field `<= 0` (default) = unbounded — composes with, does not replace, `security.body_limit`. Rejects with the existing `invalid_authorization_details` code. Maps to `sso.WithAuthorizationDetailsLimits` |
| `security.rar_catalog_check.enabled` | When `true`, PAR additionally verifies `http_api` (`method`,`path`), `grpc_api` (`service`,`method`), and `graphql_api` (`op`,`field`) authorization details against the requesting client’s tenant/client-scoped permission resource catalog. Unknown or mismatched entries fail with `invalid_authorization_details`; other RAR types remain shape-only. Default `false`. Maps to `sso.WithRARCatalogCheck` |
| `security.scope_limit.max_count` | Caps the number of space/array-separated scopes accepted in a single `/auth/login` or `/par` request. `<= 0` (default) = unbounded. Distinct from the SDK's internal `oauth.MaxScopeLen` byte cap — this is a token-COUNT cap. Rejects with `invalid_scope`. Maps to `sso.WithMaxScopeCount` |
| `security.max_token_bytes` | Caps the byte length of an inbound bearer token `validateAnyToken` will attempt to parse/verify; over-cap tokens are rejected with the standard `invalid_token`/`{"active":false}` response BEFORE any base64/JSON decode or issuer `Validate` call. `<= 0` (default) = unbounded. Maps to `sso.WithMaxTokenBytes` |
| `security.client_registration_rate_limit.{disabled,per_sec,burst}` | Narrow, IP-keyed rate limit on `POST /register` (RFC 7591 DCR) — UNLIKE every other `security.*` block above, the section being absent/zero is NOT "disabled": `sso.NewServer` always seeds a conservative built-in limiter (5 req/min/IP, burst 5) so an unauthenticated registration endpoint is never left completely unthrottled just because an operator didn't configure it. Set `disabled: true` to turn it off entirely (e.g. already throttled at an edge/WAF); set `per_sec`+`burst` (both `> 0`) to override the built-in rate without disabling it. Independent of `security.rate_limit` (which already supports a `/register` prefix rule via `security.rate_limit.prefixes`, but only takes effect when `security.rate_limit.enabled` is also true) — this guard needs no such opt-in. Rejects with the standard `rate_limited` 429 + `Retry-After` (see Rate limiting + payload in [error-codes.md](error-codes.md)). Maps to `sso.WithClientRegistrationRateLimit`; not part of the `security.rate_limit.*` SIGHUP hot-reload rebuild (see Hot Reload below) — a change here needs a restart |

## Signing Keys

| Key | Effect |
|---|---|
| `keys.signing.alg` | `eddsa`\|`es256`\|`rs256`\|`ps256` |
| `keys.id_token_algs[]` | Additional per-client ID-token signing keys (the config-facing form of `sso.WithIDTokenIssuerAlg`): each entry (`alg` required: `eddsa`\|`es256`\|`rs256`\|`ps256`; optional `key_file`/`external` with the same semantics as the primary `keys.signing.*`) wires a DEDICATED issuer so a client that declares `id_token_signed_response_alg` is served ID tokens signed with THAT algorithm while `keys.signing.alg` keeps signing everything else — the product-level FAPI 2.0 unblock (a plain-OIDC RS256 login client coexists with ES256/PS256 FAPI clients). Boot gate: the alg must differ from the primary `keys.signing.alg` and must not repeat another entry; the issuer's public key lands in the aggregated `/.well-known/jwks.json` and the alg is advertised in `id_token_signing_alg_values_supported` (the same set DCR validates against). Empty (default) = byte-identical behavior. |
| `keys.rotation.*` | Wires `StartRotation` loop; emits `signing_key_rotated` audit + `sso_signing_key_rotations_total`; busts signed-discovery cache |
| `keys.rotation.grace_period` | Overlap window the demoted key stays verify-only. Also the DEFAULT for on-demand `POST /api/v1/admin/keys/rotate` (see below); when unset the admin rotate falls back to a 24h constant. MUST be >= the max access-token TTL or tokens minted just before a rotation are stranded |
| `POST /api/v1/admin/keys/rotate`, `GET /api/v1/admin/keys` | On-demand `KeyAdminService` (admin:write / admin:read): rotate the primary signing key now (reusing the scheduled side effects) or list public key metadata. Request `grace_seconds` (>=60) overrides `grace_period`; external-signer builds refuse (412), non-rotatable issuers return 501 |
| `keys.rotation.coordinated_cutover` | `WithCoordinatedKeyRotation`: broadcasts demoted+new kids + `now+GracePeriod` retire deadline over `cluster.Bus` (`KindSigningKeyRotation`); FAIL-SAFE: deferred retire only widens verify window, never retires early |
| `keys.signing.revocation_backend` | `With{Algo}RevocationStore` for restart/recovery-safe revocation; `SeedRevocations` re-seeds at boot and after invalidation-bus recovery. `redis` uses the shared top-level client and is required when `server.topology.mode=multi` and `cluster.cross_replica_revocation=true`; memory/SQLite cannot recover an event missed by another pod. |
| `keys.signing_key_registry.{backend,replica_id,lease_ttl}` | Opt-in leaderless aggregation (`memory`\|`etcd`). `WithSigningKeyReplicaID` REQUIRED when wired. Degraded → `/readyz` 503 + `signing_key_aggregation_degraded` audit |
| `keys.signing.fips_mode` | Off by default. When `true`, `BuildSigningIssuer` requires the binary's Go Cryptographic Module to actually be active (`GOFIPS140`/`GODEBUG=fips140`) and validates `keys.signing.alg` against a FIPS 186-5-approved allowlist (default: all four supported algs — see [docs/fips.md](fips.md) for why Ed25519 is included) before constructing the issuer |
| `keys.signing.fips_allowed_algs` | Optional narrower allowlist consulted only when `fips_mode` is `true`; empty (default) = the package's full approved set |
| `keys.introspection_signing.enabled` | RFC 9701 JWT-formatted `/token/introspect` responses (`sso.WithIntrospectionSigning`). Default `false` = byte-identical to a build without the feature. Builds a SEPARATE issuer from `keys.signing` — its own key, never the access/ID-token signer — so a compromise of one can't forge the other's output |
| `keys.introspection_signing.{alg,external,revocation_backend,revocation_dsn}` | Same shape + semantics as the matching `keys.signing.*` fields, reused for the dedicated introspection key (its own `BuildSigningIssuer` call). Rotation is independent of `keys.rotation` (which targets only the primary key) — call `RotateKey`/`RotateNow` directly on the constructed issuer; a named-role admin-rotation RPC is a deferred follow-on |
| `GET /.well-known/jwks.json` `use: introspection` entry | Published only when `keys.introspection_signing.enabled`; distinguishes the dedicated key from the `sig` (access/ID token) and `enc` (JAR/response JWE) entries |
| `introspection_signing_alg_values_supported` (discovery) | Advertised only when `keys.introspection_signing.enabled`; a resource server sends `Accept: application/token-introspection+jwt` on `/token/introspect` to opt into the signed response per request — callers that don't send it keep getting plain RFC 7662 JSON |

## Storage Backend Toggles

Every store picks its substrate via a `backend:` key; `memory` is the default.
Values below are exactly what the binary's boot-time dispatch accepts
(`cmd/sso-server/serverbuild*`); an unknown value fails loud at startup.

| Store | Key | Accepted backends |
|---|---|---|
| Clients + Users (durable identity) | `identity.backend` | `memory` · `sqlite` · `postgres` |
| Sessions (hot; falls back to `identity.backend`) | `identity.session_backend` | `memory` · `sqlite` · `redis` · `postgres` |
| OAuth hot stores (auth_code / refresh_token / device_code / par — one key) | `oauth.backend` | `memory` · `sqlite` · `redis` |
| OAuth opaque lookup protection | `oauth.{sqlite,redis}.{lookup_hmac_key_file,lookup_hmac_previous_key_file}` | Optional files containing at least 32 bytes. New authorization codes, refresh tokens, device/user codes and PAR URIs are stored only as domain-separated HMAC lookup keys. Redis also protects refresh-token index members and removes raw device/user codes from stored JSON and pointer values. Reads try current key, previous key, then legacy plaintext so rollout and rotation preserve in-flight grants. Remove the previous key only after the longest artifact TTL has elapsed; plaintext fallback exists solely for pre-feature records. |
| OAuth expiry cleanup | `oauth.{auth_code,refresh_token,device_code,par}.reap_interval` | Positive cadence starts background cleanup for memory and SQLite stores; Redis relies on native key TTL. SQLite cleanup uses each table's `expires_at` index. Refresh cleanup also expires the consumed-token family ledger after the token validity window, preventing unbounded reuse-history growth without weakening live-token replay detection. `0` disables background cleanup. |
| Refresh rotation grace | `oauth.refresh_token.rotation_grace_backend` | `memory` · `sqlite` · `redis` |
| CIBA requests | `ciba.backend` | `memory` · `sqlite` · `redis` |
| MFA challenge and login transactions | `mfa.challenge.backend` | `memory` · `sqlite` · `redis`; the configured shared backend is reused for the one-use federated hosted-login transaction, even if MFA is disabled. Redis also backs it automatically whenever Redis is configured. |
| MFA push approvals | `mfa.provider.push.backend` | `memory` · `sqlite` |
| TOTP enrollment | `authenticators.totp.backend` | `memory` · `sqlite` · `postgres` (empty infers sqlite when `sqlite_dsn` set, else memory) |
| WebAuthn passkey credentials | `webauthn.storage.users.backend` | `memory` · `sqlite` · `postgres` |
| WebAuthn ceremony sessions | `webauthn.storage.sessions.backend` | `memory` · `sqlite` · `redis` |
| JTI replay | `security.jti_replay.backend` | `memory` · `sqlite` · `redis` |
| Account lockout | `security.account_lockout.backend` | `memory` · `sqlite` · `redis` |
| Rate limiter | `security.rate_limit.backend` | `memory` · `sqlite` · `redis` (redis = cluster-shared smooth token bucket: burst + per-second refill against the server clock, so the effective limit is exactly the configured one across replicas with no fixed-window edge burst) |
| Pairwise subjects | `server.pairwise_subjects.backend` | `memory` · `sqlite` · `postgres` |
| BCL subject-client index | `backchannel_logout.index.backend` | `memory` · `sqlite` · `redis` |
| Native SSO device_secrets | `native_sso.backend` | off (`""`) · `memory` · `sqlite` · `postgres` |
| Self-service consent | `self_service.consent.backend` | off · `memory` · `sqlite` · `postgres` |
| Self-service password credentials | `self_service.password.backend` | off · `memory` · `sqlite` · `postgres` |
| Password reset tokens | `self_service.password_reset.backend` | off · `memory` · `sqlite` · `redis` |
| Tenants + Domains | `tenant.backend` | `memory` · `sqlite` · `postgres` |
| Tenant resource quotas | `tenant.resource_quota.backend` | off (`disabled`/empty) · `memory` (single replica) · `postgres` (shared pool) |
| Tenant usage metering | `tenant.usage_metering.backend` | off · `memory` · `sqlite` (reads the audit DB) |
| B2B connections | `connections.backend` | `memory` · `sqlite` |
| Audit primary sink | `audit.backend` | `memory` · `sqlite` · `postgres` |
| Permissions | `permissions.backend` | `memory` · `sqlite` · `postgres` |
| ReBAC / FGA tuples + check | `rebac.{enabled,backend}` · `rebac.sqlite.dsn` | off unless enabled · `memory` (single replica) · `sqlite` (shared) |
| Anomaly detectors | `anomaly.{recent_login,ip_failure}.backend` | `memory` · `sqlite` |
| Signing-key revocation | `keys.signing.revocation_backend` | off · `memory` · `sqlite` · `redis` |
| Signing-key registry | `keys.signing_key_registry.backend` | off · `memory` · `etcd` |
| Cross-replica bus | `cluster.bus.backend` | off · `memory` · `etcd` · `redis` |
| Service registry | `registry.backend` | `memory` · `etcd` |
| Network policy store | `network.store` | `memory` · `etcd` |
| Bootstrap lock | `bootstrap.lock.backend` | `noop` · `file` · `etcd` |

All `backend: redis` **hot** stores share the ONE `redis:` block below. All
`backend: postgres` **durable** stores share the ONE `postgres:` block below —
a shared *sql.DB pool per replica, not one pool per store. Selecting
`redis`/`postgres` without its block is a boot error:
`<domain>.backend=postgres but no postgres block configured (set postgres.dsn)`.

The Redis invalidation bus and revocation set carry complete bearer tokens.
Production Redis ACLs and network policy MUST limit the application identity to
its `snaplink:cluster:bus` channel and `sso:jwt:revocations` key (plus the other
explicitly configured Snaplink keyspaces), and TLS MUST protect traffic outside
a trusted private network.

### B2B connection email-domain verification

| Key | Effect |
|---|---|
| `connections.domain_verification.enabled` | `false` (default): last-write-wins `Upsert` — byte-identical to the pre-feature build. `true`: an admin-API `Upsert` claiming a domain another connection has already **verified** cannot steal its home-realm routing; the new claimant must prove control by publishing a DNS TXT record and calling `POST /api/v1/admin/connections/:id/domains/:domain/verify`. |
| `connections.domain_verification.record_prefix` | DNS label prepended to the claimed domain to form the challenge record name (`<prefix>.<domain>`). Empty uses the built-in default (`_snaplink-domain-verify`). |

Boot-time YAML-seeded connections (`connections.connections`) are always
auto-verified regardless of the flag — the operator authoring the YAML is an
equivalent trust level to a direct DB write. The verify endpoint uses the
stdlib DNS resolver by default; an SDK embedder can inject a custom one via
`sso.WithDomainVerificationResolver` (e.g. DNS-over-HTTPS).

### B2B connection health probing

| Key | Effect |
|---|---|
| `connections.probe.timeout` | Bounds a single admin-triggered reachability probe's (`POST /api/v1/admin/connections/:id/probe`) HTTP round-trip. `<=0` (default) uses the SDK default, `connections.DefaultProbeTimeout` (10s). |

The probe fetches OIDC discovery (`{oidc_issuer}/.well-known/openid-configuration`)
for `type: oidc` connections or the SAML metadata document (`saml_metadata_url`)
for `type: saml`, and persists the outcome (`unknown` \| `healthy` \| `degraded`
\| `unreachable`) plus `last_checked_at` / `last_success_at` / a bounded-length
`last_error`, readable via `GET /api/v1/admin/connections/:id/health`. An SDK
embedder can inject a custom prober (e.g. for a protocol this SDK doesn't
natively probe) via `sso.WithConnectionProber`. Each probe increments
`sso_connection_health_probes_total{type,outcome}` — see
[observability.md](observability.md).

## Self-Service

| Key | Effect |
|---|---|
| `self_service.consent.max_ttl` | Hard server-wide ceiling on consent grant lifetime (`WithConsentTTL`): every recorded grant gets `ExpiresAt = GrantedAt + max_ttl`, after which `GetConsent` treats it as absent and `/auth/login` re-prompts. `0` (default) = no server-enforced expiry — permanent until revoked. Independent of, and can only be tightened by, a client's own `consent_refresh_interval`. Requires `self_service.consent.backend` to be set. |
| `self_service.identity_link.enabled` | Wires `sso.WithIdentityLinkStore`, mounting `GET`/`DELETE /me/identities` and mapping subjects in built-in static/connection-backed OIDC federation. Disabled by default |
| `self_service.identity_link.backend` | `memory` (default/compatibility, single process), `sqlite` (durable one-host install; requires `.sqlite.dsn`), or `postgres` (uses the global Postgres pool for multi-replica consistency). One active `(provider, subject)` can belong to exactly one local account |
| `self_service.identity_link.merge_policy` | `""` / `"reject"` (**default, safe**) rejects conflicting account ownership. `"link_only"` atomically reassigns the losing account's active identity links to the existing owner; sessions, consents, OAuth/refresh tokens, MFA and audit ownership are deliberately NOT merged. Any other value fails at boot |

## Setup Wizard (first-run onboarding)

| Key | Effect |
|---|---|
| `setup_wizard.enabled` | `false` (default) — the public `GET /api/v1/setup/status` + `POST /api/v1/setup` endpoints 404. `true` enables them: while the system is uninitialized (no admin exists), status reports `setup_required`; `POST /api/v1/setup` provisions the first admin (username + password → `sso-admin` role) and an optional first application, then LOCKS (subsequent calls → `409 already_initialized`). sso-server itself serves no wizard frontend — a separate project (reverse-proxied alongside this server) drives the flow through these two endpoints; "config has an admin → straight in; empty → wizard" is entirely that frontend's decision, made by polling status. Requires the identity, permissions and `self_service.password` stores to be wired (the wizard writes to all three). |

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
`ops/deploy/kustomize/overlays/prod/config.yaml` for the canonical production selection
(durable → postgres, hot → redis, coordination → etcd).

## Email (SMTP)

Built-in outbound email sender (`infrastructure/defaultimpl/emailsmtp`) that
delivers password-reset, email-verification, email-change, org-invitation,
and email-OTP messages over `net/smtp` — no external mail-provider dependency.
`smtp.enabled=false` or an empty `smtp.host` leaves the four SDK sender
options unwired, same no-op-delivery behavior as a build without this. Send
is ASYNC fire-and-forget (a background goroutine bounded by `smtp.timeout`) so
`/auth/forgot-password` stays constant-time regardless of SMTP latency
(anti-enumeration) — send failures are logged, never surfaced to the caller.

| Key | Effect |
|---|---|
| `smtp.enabled` | Master switch; `false` = byte-identical no-op delivery |
| `smtp.host` | SMTP relay hostname (also required — enabling without a host is a no-op) |
| `smtp.port` | SMTP relay port (`587` STARTTLS, `25` plaintext relay; `465` = implicit TLS — the connection is TLS-encrypted before the first SMTP verb) |
| `smtp.username` | AUTH username; empty = no AUTH attempted |
| `smtp.password` | AUTH password — supports `secret://` resolution (`config/secrets.go`) and the `SSO_SMTP__PASSWORD` env override; never commit a plaintext value |
| `smtp.from` | Envelope + `From:` header address |
| `smtp.starttls` | Documents intent: `net/smtp.SendMail` negotiates STARTTLS automatically whenever the server advertises it and falls back to plaintext otherwise — the pre-existing 587/25 behavior, unchanged. Require TLS at the relay/edge when plaintext fallback is unacceptable |
| `smtp.tls_mode` | SMTP TLS selection: `auto` (default; also the behavior for an unset or unrecognized value) = implicit TLS on port `465` only; `implicit` = TLS handshake before the first SMTP verb on any port (non-standard implicit-TLS relays). Verification is always fail-closed: `ServerName` is the relay host, the TLS floor is 1.2, and `InsecureSkipVerify` is never set — a relay with an untrusted certificate must be terminated at the edge/relay |
| `smtp.timeout` | Per-send bound for the background dispatch goroutine; 0 = 10s default |
| `smtp.templates_dir` | Filesystem overlay for the six go:embed default templates (`password_reset`/`email_verification`/`email_change`/`invitation`/`otp`/`notification`); empty = embedded defaults only |
| `smtp.link_base_url` | Prefixed to reset/verify/invite links — required because the sender only ever sees the token/target its `spi.*Sender` method receives, never `server.issuer` |

## User Notifications

The notification subsystem is opt-in. When enabled, security-relevant audit
events are routed asynchronously to the in-app inbox and, when configured, to
email. Delivery failure never changes the result of the originating security
operation. See [notifications.md](notifications.md) for event mappings and API
semantics.

| Key | Effect |
|---|---|
| `notifications.enabled` | Enables the notification stores, audit-event router, self-service inbox/preferences API, and subject-filtered SSE feed. Default `false` |
| `notifications.backend` | Inbox and preference persistence: `memory` (default) or `sqlite` |
| `notifications.sqlite.dsn` | Required when `backend: sqlite`; both notification tables share this database |
| `notifications.email_enabled` | Also deliver enabled notification types through the built-in SMTP sender. Requires `smtp.enabled` and a resolvable user email; otherwise only in-app delivery is wired |
| `notifications.cooldown` | Per-`{subject,type}` duplicate suppression window. Default `5m`; `0` disables suppression |
| `notifications.queue_size` | Bounded asynchronous audit-event queue capacity. Default `256`; must be positive |
| `notifications.workers` | Delivery worker count. Default `2`; must be positive |
| `notifications.session_expiry_warning` | Notify once an active server-side session enters this remaining-lifetime window. Default `30m`; must be positive |
| `notifications.session_scan_interval` | How often the session index is scanned for expiry warnings. Default `1m`; must be positive |

```yaml
notifications:
  enabled: true
  backend: sqlite
  sqlite:
    dsn: file:/var/lib/snaplink/notifications.db
  email_enabled: true
  cooldown: 5m
  queue_size: 256
  workers: 2
  session_expiry_warning: 30m
  session_scan_interval: 1m
```

## SMS

The phone one-time-code authenticator (`authenticators.phone`) dials an
`authenticators.SMSSender`; `authenticators.phone.sms` selects the transport.
All built-in email/SMS OTP and magic-link authenticators share three abuse
controls in their `CodeStore`: a 60-second resend cooldown, at most five failed
verification attempts per issued value, and fixed-window send budgets. The
default budgets are 20 sends per tenant-scoped identity and 1,000 sends per
tenant every 24 hours. Redis reserves the identity and tenant counters in one
Lua operation, so multiple replicas cannot overspend the budget. The fifth mismatch
invalidates that value while returning the same generic credential error as
an ordinary mismatch. If a synchronous delivery call fails, the built-in
memory and Redis stores conditionally remove that undelivered value and release
its cooldown and quota reservation, allowing an immediate retry without risking
deletion of a newer issuance. Quota exhaustion is deliberately returned as the
same HTTP 200 `{"status":"sent"}` response as a successful send and does not call
the transport, preventing account/target and budget-state probing.
`provider` unset or `"log"` (the default) logs the code instead of sending
it — byte-identical to the stub that shipped before this config section
existed. `provider: "http"` dispatches over the built-in
`infrastructure/sms` sender, a generic HTTP REST transport compatible with
Twilio's Messages API contract (no vendor SDK dependency; any
Twilio-compatible gateway works via `base_url`). A misconfigured `"http"`
provider (missing required field, or an unrecognized `provider` value)
fails the boot loudly rather than silently falling back to the log stub.

| Key | Effect |
|---|---|
| `authenticators.code_send_quota.identity_limit` | Maximum sends to one target inside one tenant and window; default 20. `-1` disables this dimension; `0` selects the default |
| `authenticators.code_send_quota.tenant_limit` | Maximum sends across all targets in one tenant and window; default 1,000. `-1` disables this dimension; `0` selects the default |
| `authenticators.code_send_quota.window` | Fixed-window duration shared by both limits; default `24h` and must be positive after defaults are applied |
| `authenticators.code_delivery.async` | Enables the bounded in-memory OTP/magic-link worker queue; default `false` preserves synchronous delivery |
| `authenticators.code_delivery.queue_size` | Maximum accepted pending deliveries; default 256, maximum 10,000. A full queue fails the request and conditionally invalidates the freshly stored code |
| `authenticators.code_delivery.workers` | Concurrent delivery workers; default 2, maximum 64 |
| `authenticators.code_delivery.attempts` | Maximum provider attempts per accepted delivery; default 3, maximum 10 |
| `authenticators.code_delivery.attempt_timeout` | Per-provider-attempt timeout; default `10s`, maximum `2m` |
| `authenticators.code_delivery.retry_backoff` | Initial exponential retry delay; default `200ms`, maximum `30s` |
| `authenticators.phone.sms.provider` | `""` / `"log"` (default; log-only stub) \| `"http"` (real SMS via `infrastructure/sms`) |
| `authenticators.phone.sms.account_sid` | Twilio (or compatible) Account SID — HTTP Basic Auth username AND the Messages-resource path segment; required when `provider: "http"` |
| `authenticators.phone.sms.auth_token` | HTTP Basic Auth password — supports `secret://` resolution (`config/secrets.go`) and the `SSO_AUTHENTICATORS__PHONE__SMS__AUTH_TOKEN` env override; never commit a plaintext value; required when `provider: "http"` |
| `authenticators.phone.sms.from_number` | Sending number / alphanumeric sender ID; required when `provider: "http"` |
| `authenticators.phone.sms.message_template` | Outbound body template; the literal substring `{code}` is replaced with the generated code. Empty uses the SDK default (`"Your verification code is: {code}"`) |
| `authenticators.phone.sms.http_timeout` | Per-request bound; 0 = 10s default |
| `authenticators.phone.sms.base_url` | Overrides the REST API origin — set only to point at a Twilio-compatible gateway; empty uses the real Twilio API origin |

## Magic Link

The passwordless emailed-link authenticator (`authenticators.magic_link`,
provider name `magiclink`). Functionally the email-OTP authenticator with two
differences: `SendCode` mints a long, high-entropy opaque token
(`authenticators.GenerateOpaqueToken`, base64url — same construction the
temp-token authenticator uses for single-use bearer tokens) instead of a
short digit code, and it emails a full clickable URL rather than a bare code.
`Authenticate` is otherwise identical to email-OTP: it reads the SAME
`credential.email` / `credential.code` keys and consumes the SAME `CodeStore`
`Verify` call (single-use — a replayed click, e.g. an email-security-scanner
prefetch racing the real click, fails the second attempt), just keyed under a
namespace distinct from email-OTP's so requesting both for one address never
collides. `magiclink` reuses `email:` (the CodeAuthConfig SMTP sender) — no
separate transport to configure.

The emailed link is shaped `base_url?token=<opaque>#email=<address>` —
deliberately NOT a second `&`-joined query parameter: the built-in SMTP
sender renders the OTP body through `html/template` for XSS-hardening, which
HTML-entity-escapes a literal `&` in an interpolated value to `&amp;` and
would corrupt a two-`&`-joined-param link. Splitting the email into a `#`
fragment keeps the whole link free of any HTML-special character, so it
survives that renderer unmodified — zero changes to
`infrastructure/defaultimpl/emailsmtp` were needed. `base_url` should point at the
deployment's external login frontend or another operator-controlled page
whose script parses `?token=` + `#email=` from the URL and POSTs
`{provider: "magiclink", credential: {email, code: token}}` to `/auth/login`
— the SAME request shape every other credential authenticator already uses,
so no new HTTP endpoint or request-binding change is needed. This repository
does not provide that landing page.

Caveat: because the link is opened out-of-band (a different browser/device
than the one that started the OAuth flow may open it), the emailed link
cannot carry the original `client_id` / `redirect_uri` / `state` — `SendCode`
intentionally has no such parameter (it shares the plain `CodeSender`
interface every code-based authenticator implements). A deployment that
needs the click to resume a SPECIFIC client's authorization request must
either restrict `magiclink` to a single default client, or extend the
`/auth/send-code` caller to persist that context out-of-band — this SDK
does not do so today.

| Key | Effect |
|---|---|
| `authenticators.magic_link.enabled` | Master switch; `false`/omitted = byte-identical to a build without the feature |
| `authenticators.magic_link.base_url` | Login-UI landing page the emailed link points at. REQUIRED when enabled — an enabled authenticator with no landing page fails the boot loudly rather than shipping a dead feature |
| `authenticators.magic_link.token_length` | Opaque-token `crypto/rand` byte length before base64url encoding; 0 = 32 (256 bits) |
| `authenticators.magic_link.ttl` | How long the emailed link remains valid; 0 = 15m |

## Tenant & Region

| Key | Effect |
|---|---|
| `tenant.suspension_check.cache_ttl` | Cache TTL for suspension checks (default 30s); admin SetStatus MUST call `InvalidateTenantSuspensionCache` |
| `tenant.resource_quota.backend` | `disabled`/empty leaves the server unlimited and starts no worker; `memory` is allowed only for a single replica; `postgres` reuses the top-level shared pool and is the required backend for `server.topology.mode: multi`. The multi-replica memory rejection is not weakened by `allow_per_pod_state` because independent commercial counters can oversell an entitlement. |
| `tenant.resource_quota.cleanup_interval` | Cadence for removing expired rolling token-rate buckets. `0` uses 1 minute; negative durations fail validation. The worker starts only after successful server assembly, participates in bounded graceful shutdown, and PostgreSQL reachability is included in `/readyz`. |
| `tenant.resource_quota.limits[]` | Boot-time legacy limit seeds keyed by unique, non-empty `tenant_id`: `max_clients`, `max_users`, `max_sessions`, and `max_token_rate`; every limit is non-negative and `0` means unlimited. `max_token_rate` bounds the one-minute rolling average across all of the tenant's clients. A commercial hard zero is intentionally not encoded by this legacy YAML shape: entitlement delivery uses `TenantQuotaProjectionStore` and its explicit `*Limited` flags. Once a positive-revision entitlement projection exists, an unversioned `SetQuota` seed is rejected rather than overwriting newer billing state. |
| Tenant quota consistency and projection | Memory and PostgreSQL implement idempotent resource leases keyed by `(tenant, resource, resource_id)` and advance a per-resource generation on every first transition. `TenantQuotaResourceSetStore.ReconcileResourceSet` replaces the counter and exact active lease set in one generation CAS; removed identities remain tombstones, so a late duplicate release cannot decrement a rebuilt counter. At startup existing clients are reconciled before routes are served. Known session tenants are also reconciled, and an apparent session cap triggers another exact scan so TTL-expired sessions are reclaimed. `TenantQuotaProjectionStore` applies entitlement revisions monotonically, ignores older revisions, and rejects same-revision content changes. PostgreSQL persists leases, tombstones, generations, explicit hard-zero flags, and projection revision in the shared pool. |
| Tenant quota enforcement coverage | The stock request path reserves tenant clients by generated `client_id` before DCR persistence and releases the exact lease on failed persistence or successful RFC 7592/admin deletion. For sessions, the stock memory/SQLite/PostgreSQL/Redis managers are wrapped with a two-phase lifecycle: a new row is stored as internal `quota_pending`, its exact session-ID lease is reserved, and only then is it published; pending rows are invisible to Get/List/Refresh, over-limit candidates are destroyed, and abandoned pending rows are drained after a bounded recovery grace. Every logout, bulk tenant revocation, account erasure, and other `SessionManager.Destroy` path releases the same lease idempotently; exact-set CAS repairs natural expiry and crash drift without losing concurrent creates/deletes. Break-glass impersonation sessions stay outside commercial quota. Authenticated tenant-matched `/token` dispatches are charged after idempotency replay lookup; exhaustion is `429 rate_limited` + `Retry-After` with no-store headers. Operational quota-store errors preserve the documented fail-open login posture and are logged; a definitive hard limit is `403 quota_exceeded`. Exact SSO membership/user leasing remains intentionally unwired because `TenantUserStore.Add` is an upsert in a separate transaction; Aero ID owns the commercial account/user quota lifecycle. |
| `region.{serving_region,header_name,allowed_regions,residency_check_cache_ttl}` | Multi-region residency; write-gate on login mint, read-gate on resource access; admin mutation MUST call `InvalidateTenantResidencyCache` |
| `region.policy_store.backend` / `region.policy_store.sqlite.dsn` / `region.policy_store.seed[]` | Optional durable `region.PolicyStore` (memory \| sqlite): a non-zero stored policy is the authoritative, constraint-adding residency source ahead of tenant fields; zero/error falls through (fail-open). Seed entries are applied at boot and invalid region IDs fail boot loud. Empty backend = not wired (tenant-row-only, byte-identical) |
| `geo.backend` | IP → geo enrichment middleware's `geo.Provider`: `static` (default; in-process operator-curated CIDR table, see `geo.static.*`). The SDK additionally ships `platform/geo/maxmind` (production .mmdb coverage with atomic snapshot replacement) and `geo.NewComposite` (static overlay + maxmind primary) for embedders; the stock binary's `static` default stays zero-dependency |

## Runtime Webhook Exporter

The optional `webhooks` block enables the stock server's precompiled, generic
audit-event webhook exporter. It is separate from the startup-only
`audit.webhook` sink: administrators register subscriptions through the
webhook admin API, while the primary audit store remains authoritative. The
exporter preserves subscription and dead-letter stores across delivery-policy
replacements; configuration and credentials are never part of lifecycle audit
events.

| Key | Effect |
|---|---|
| `webhooks.enabled` | Enables the exporter and its admin subscription/dead-letter routes. Disabled or absent means no runtime exporter is built. This enablement is boot-time only and requires a restart to change. |
| `webhooks.delivery_timeout` | Per-POST timeout for each registered subscription; `0` uses the SDK default (`10s`). Safe to change with `SIGHUP`; the active exporter generation drains before replacement. |
| `webhooks.retry.{max_attempts,initial_backoff,max_backoff}` | Total attempts and bounded exponential backoff for asynchronous delivery. Safe to change with `SIGHUP`; the subscription and dead-letter stores remain shared across generations. |
| `webhooks.dead_letter_capacity` | Process-local dead-letter ring capacity; `0` uses the SDK default (`1000`). Requires restart because changing it would replace delivery state. Use the admin dead-letter endpoints for inspection and replay. |
| Runtime lifecycle | The webhook exporter and ReBAC `/authz/check` capability use precompiled generations with readiness, request leases, graceful drain and bounded transition observers. `webhook_lifecycle_transition` and `rebac_lifecycle_transition` audit events contain only module ID, generation, related generation and transition type. A failed replacement leaves the previous generation active. |

## Audit & Metrics

| Key | Effect |
|---|---|
| `audit.retention.*` | `platform/audit/sqlite.Sink.Prune` |
| `audit.external_worker.enabled` | Enables one lifecycle-supervised out-of-process audit-batch worker. `audit.enabled` is also required; enablement is boot-time only and requires restart. The worker receives the Recorder's already-redacted and hash-stamped events, never OAuth credentials or primary-store read access. Delivery is fail-open with an operator log; `/readyz` checks the manager and the worker's authenticated readiness RPC. |
| `audit.external_worker` local mode | Requires `module_id`, absolute `executable`, absolute `socket_path`, `auth_token`, a 64-character `expected_sha256`, absolute `provenance_path`, `provenance_public_key`, `release_id`, and `build_profile`. `build_profile` must equal the immutable host build profile. The signed manifest is schema 1 and binds module ID, executable digest, release ID, build profile and non-empty source revision. `provenance_public_key` and optional `signature_public_key` are 32-byte Ed25519 public keys encoded as hex or standard/raw base64; `signature_path` is an optional detached artifact signature. The worker is launched directly without a shell. |
| `audit.external_worker` remote mode | Set `remote_address` plus `tls.cert_file` and `tls.key_file`; `tls.ca_file` is optional (empty uses platform roots), and `tls.server_name`/`peer_spiffe_id` may pin the peer. Remote mode rejects local executable, digest, signature and provenance fields, uses TLS 1.2+, and never starts a local process. |
| `audit.external_worker.{startup_timeout,request_timeout,max_frame_bytes,max_batch_events}` | Bounds worker startup/RPC and the typed newline-framed audit protocol. Zero values use safe SDK defaults; upper bounds are enforced by the external supervisor. The only current external capability is `deliver_audit_batch`; arbitrary business routes are not enabled by this config. |
| `audit.async.{enabled,buffer_size,workers,record_timeout_ms}` | Wraps the composed audit sink in `audit.AsyncSink` so `Record` returns on a buffered hot path instead of waiting for the inner sink — critical when the sink is network-bound (webhook/kafka), pointless overhead for a bare `MemorySink`. `buffer_size`/`workers` fall back to library defaults when `<= 0`; `record_timeout_ms` caps a single inner `Record` call so a hung downstream can't pin a worker (`0` = no timeout). Drops (queue full / closed / inner error) are logged and scraped via the `sso_audit_async_*` collectors when `metrics.enabled` |
| `audit.async.batch_size` | `> 1` switches the async worker to batch draining (`audit.NewBatchAsyncSink`): up to `batch_size` queued events collapse into ONE `RecordBatch` call — a single SQLite/Postgres transaction instead of N single-row INSERTs. Requires the composed sink to support batch writes: the `memory`/`sqlite`/`postgres` primary alone does, but any webhook/cef/ocsf/syslog/kafka fan-out (`MultiSink`) does not — that combination **fails boot loud** rather than leaving the knob silently inert. `0` (default) and `1` both mean per-event delivery, byte-identical to the pre-batching behavior; negative values fail boot (unlike `buffer_size`/`workers` there is no "default please" reading — the library's own `<= 1` fallback is `DefaultBatchSize` 64, which a config typo must never surprise-enable) |
| `snapshot.retention.*` | `interfaces/snapshot.PruneOldest` |
| `mfa.provider.push.prune_interval` | `infrastructure/defaultimpl/sqlite.PushApprovalStore.PruneExpired` |
| `metrics.tenant_label_allowlist` | `WithTenantMetricsAllowlist` — bounded per-tenant login/issue metrics + `"other"` bucket; empty = off |
| `audit.webhook.signing_secret` | HMAC-SHA256 payload signing on the audit `WebhookSink` — every POST carries `X-Signature: t=<unix>,v1=<hex>`; empty = off; receivers verify with `security.VerifyWebhookSignature`. Inject via env/`secret://`, never YAML literal |
| `audit.webhook.subscriptions[]` | Fan the audit stream to multiple endpoints, each with its own event-type filter. Per entry the stack is `RetryingSink(FilteringSink(WebhookSink))`, all fanned into the one `MultiSink` beside the primary sink. The legacy scalar `audit.webhook.url` (when set) is compiled as an implicit **unfiltered** subscription named `default`; both may be set together |
| `audit.webhook.subscriptions[].name` | REQUIRED, unique across the list (boot fails on empty or duplicate). Names the subscription in logs (and reserves identity for future per-subscription metrics); the name `default` is reserved for the legacy scalar url when that is set |
| `audit.webhook.subscriptions[].url` | REQUIRED delivery endpoint for this subscription (boot fails when empty) |
| `audit.webhook.subscriptions[].event_types` | Delivery filter. Each entry is an **exact** type (`login`) or a **trailing-`*` prefix wildcard** (`admin_*` matches every `admin_` event); no other globbing. **Empty list = firehose** (all events). Unknown/custom type strings are accepted (custom event types are legal) with a boot log line |
| `audit.webhook.subscriptions[].{timeout,headers,signing_secret,retry}` | Per-subscription transport, mirroring the scalar webhook fields (fall back to library defaults when zero). `signing_secret` reuses the same HMAC-SHA256 `X-Signature` signing; it is a credential — inject via a `secret://` reference (resolved inside the list), never a YAML literal |
| `mfa.provider.push.webhook.signing_secret` | Same HMAC-SHA256 `X-Signature` signing on the MFA push webhook transport, re-signed with a fresh timestamp per retry; empty = off. `ciba.webhook.signing_secret` shares the same `MFAPushWebhookConfig` struct, so it behaves identically for CIBA notifications |
| `config_audit.enabled` / `.backend` / `.sqlite.dsn` | Runtime-config audit (`platform/configaudit`): when enabled, cmd builds the `configaudit.Store` (`memory`\|`sqlite`), captures the redacted applied-config snapshot once at boot, and wires `sso.WithConfigSnapshots` + `WithConfigAuditStore`, mounting `GET /api/v1/admin/config/{running,applied,diff,history}` + `POST .../config/{apply,rollback}` (the declared peer-config baseline write path — admin:write + mandatory `?approve=true`, split-brain digest gate, redacted-only storage, transactional version chain; rollback accepts optional `expected_version_id` for an atomic CAS guard; `?canary=true&window=60s` opts into bounded health observation with automatic predecessor rollback; see `docs/design/config-apply-mode.md`, `docs/design/config-canary-apply.md` and `docs/design/operator-config-rollback.md`) + the client/tenant/policy change-capture hook |
| `config_audit.drift.interval` | `sso.WithConfigDriftDetection` — cross-replica config-digest broadcast (`cluster.KindConfigDigest`) + compare loop; `<= 0` (default) = off, report-only |

## Logging

| Key | Effect |
|---|---|
| `logging.level` | `debug` \| `info` \| `error` (default `info`); swaps the server's `*slog.LevelVar` so verbosity changes with no restart and no dropped log lines |
| `logging.access_log.enabled` | Always-on structured access log (design `docs/design/middleware-observability-unified.md` Decision 1): one INFO `"access"` record per request with the fixed low-cardinality field set `method`, `path` (never `RawQuery` — query strings can carry `code`/`token` credentials), `status` (default 200 when the handler never calls WriteHeader), `duration_ms` (wall-clock since middleware entry, includes rate-limit wait), `client_ip` (canonical `peertrust.ClientIP`: the validated real IP under trusted proxies, else the first X-Forwarded-For hop → X-Real-IP → RemoteAddr), `request_id`, `trace_id` (both empty when no tracing/correlation middleware is installed). **Default ON for `sso-server`** — the block is tri-state: absent (nil) or `true` installs the middleware, only an explicit `false` removes it entirely (zero added chain overhead). Probes `/livez` `/readyz` `/metrics` are served by `buildProbeMux` outside the whole chain and never produce access records. SDK embedders default OFF (option absent = not installed); `sso.WithAccessLogging(policy)` opts in. Not hot-reloadable: the middleware slot is fixed at boot, so a SIGHUP change is reported under `ignored_requires_restart` |
| `logging.access_log.body.paths` | Exact-path allowlist of request/response bodies eligible for capture; empty (default) = no path eligible, bodies are never read, so no body fields ever appear in the record. Captured bodies are redacted before logging (credential-shaped keys — exact vocabulary plus a substring heuristic on `secret`/`password`/`token`/`assertion`/`code` — replaced with exactly `[redacted]`, no length-preserving padding) and capped per field at `max_body_bytes`. Malformed bodies pass through capped raw bytes |
| `logging.access_log.body.allow_all_paths` | **Deprecated** escape hatch reproducing the old `logBodies=true` semantics — logging every body on every path is a credential-exposure posture, not a debug flag. Only applies when `paths` is empty; combining it with a populated `paths` fails boot loud |
| `logging.access_log.body.sample_rate` | Fraction (0.0–1.0) of eligible requests whose bodies are captured (a per-request Bernoulli decision, applied to body capture only — the fixed access-log fields are never sampled). `0` (default) means capture never happens even on allowlisted paths; body capture exists only under explicit operator config. Out-of-range values fail boot |
| `logging.access_log.body.max_body_bytes` | Per-captured-field cap (request and response each); `0` (default) selects 4096; negative values fail boot |

## Authentication Pipeline

Optional built-in lifecycle Hooks. An absent block registers no Hooks and keeps
the original authentication/token path unchanged. See
[Authentication Pipeline Hooks](auth-pipeline-hooks.md) for the SDK SPI, custom
Hooks, failure semantics, and WASM/SIEM adapters.

| Key | Effect |
|---|---|
| `auth_pipeline.ip_skip_mfa_cidrs` | CIDRs whose successfully authenticated requests may skip MFA challenges. CIDRs are validated at startup; risk and conditional-access deny verdicts still reject. Empty = no Hook. |
| `auth_pipeline.required_profile_attributes` | Authenticated-user attribute names that must be non-empty before session/token side effects. Empty/duplicate names fail startup. Empty list = no Hook. |

## Config JSON Schema & Validation

`config/schema` reflects over `config.Config`'s `yaml` struct tags to generate a
minimal JSON Schema (draft-07 subset: `type`/`properties`/`items`/`required`/
`additionalProperties`) — no external schema-generation tool or dependency.
`required` is a best-effort heuristic (absence of `,omitempty` on a plain
scalar field); nested sections, pointers, slices, and maps are NEVER marked
required, since Go's zero-value defaulting means every one of them is
decodable when absent. Treat it as an IDE/documentation aid (e.g. for the
redhat.vscode-yaml extension's autocompletion + typo-squiggles), not a
strict "config fails to load without this key" contract.

| Key / Command | Effect |
|---|---|
| `sso-ctl config schema [--out <file>]` | Prints the generated JSON Schema for `config.Config` (stdout, or `--out` to write a file) |
| `sso-ctl config validate-schema --file <config.yaml>` | Validates ONE config file's raw YAML shape against the generated schema; exits 1 and prints every violation (`path: expected TYPE, got TYPE` / `path: unknown field`) on ANY mismatch — a strict CI / pre-deploy gate |
| Loader.Load's built-in check | Every server boot ALSO runs the same `schema.Validate` over the fully-merged (file+env+etcd+flag) document and logs a WARNING (`config: schema violations detected`) listing every violation — alongside, not replacing, the existing `DisallowUnknownFields` warn-then-fallback decode. Deliberately warn-only: the schema cannot capture every decode-time flexibility goccy/go-yaml offers (e.g. `time.Duration` accepts both a duration string and a bare integer), so promoting it to a hard boot failure risks rejecting a config that would actually load fine. Use `validate-schema` in CI for a strict gate instead |

## Hot Reload (SIGHUP)

`cmd/sso-server` optionally re-reads its config on `SIGHUP` and applies the
SAFE subset live, via `config/reload.Reloader` — entirely opt-in: a build (or
caller) that never constructs a `Reloader` behaves exactly as before this
feature existed (no extra signal handler is even registered).

| Key / Behavior | Effect |
|---|---|
| `SIGHUP` (running `sso-server` process) | Re-reads config from the SAME source chain (file + env + etcd + flag) it booted with, diffs it against the previously-tracked config (`platform/configaudit.Diff`, the same JSON-Patch engine the admin running-vs-applied endpoint uses), applies the safe subset, and logs `config reload applied` with `applied` (what changed live) and `ignored_requires_restart` (everything else that changed but was left untouched) |
| `logging.level` | Swaps the server's `*slog.LevelVar`, so verbosity changes with no restart and no dropped log lines |
| `logging.access_log.*` | NOT hot-reloadable: reported under `ignored_requires_restart` and left untouched — the access-log middleware slot is fixed at boot (same as rate limiting's enabled flag); pick it up with a restart |
| `security.rate_limit.*` | Rebuilds the WHOLE `ratelimit.Policy` (via the same `serverbuildplatform.BuildRateLimitPolicy` the boot path uses) and hot-swaps it into the already-mounted middleware (`ratelimit.DynamicMiddleware` reads its Policy from a `ratelimit.PolicyStore` fresh on every request, instead of a plain `ratelimit.Middleware`'s baked-in-by-value closure). Every changed leaf under the block (a prefix's `per_sec`, `default_burst`, …) triggers exactly ONE rebuild, not one per leaf. In-memory limiter bucket state resets on rebuild (a safe, side-effect-free change — no correctness impact). Enabling/disabling rate limiting ENTIRELY (the `enabled` flag going from `false` to `true`, when no `WithRateLimit` was ever wired) still needs a restart — there is no middleware slot to swap into if it was never installed |
| `webhooks.delivery_timeout` / `webhooks.retry.*` | Rebuilds the active precompiled webhook-exporter generation on `SIGHUP`; request leases drain and in-flight POSTs finish before the old generation stops. Subscription and dead-letter stores survive the replacement. |
| `webhooks.enabled` / `webhooks.dead_letter_capacity` | Detected and reported under `ignored_requires_restart`; left untouched until restart. |
| `feature_gates.{admin_api,branding,oidc,ciba,caep,federation,self_service}` | `interfaces/sso` registers the applicable route groups at `Mount()` time and checks live gate state through `shared/core.GatedRouter`. Each `Set*GateHook` flips reachable routes in both directions without a restart; gate-off returns a router-native 404. A gate cannot create missing dependencies: `branding` is ignored when no tenant store exists (it now gates only `/branding`), `caep` cannot create an unwired receiver/stream store, and `federation` cannot create an unwired entity/connection store. The deprecated `web_spa` name is accepted as an alias of `branding` (both set = startup error). |
| Storage backends, `server.listen`, TLS material, cluster/etcd endpoints, … | Detected if changed, reported under `ignored_requires_restart`, and left COMPLETELY untouched — never silently misapplied. These require closing and re-opening a connection or listener; applying them live risks leaking the old one or serving with an inconsistent half-applied state. See `config/reload`'s package doc for the full rationale |
| A failed reload (e.g. the file was hand-edited into an invalid state) | Logged (`config reload failed; continuing with previous configuration`) and otherwise ignored — the process keeps running on its last-good configuration; SIGHUP can never crash a running server |

## SIEM Export Formats

| Key / Command | Effect |
|---|---|
| `audit.cef.*` / `audit.ocsf.*` / `audit.syslog.*` | Three INDEPENDENT SIEM export formatters (`platform/audit/auditsink/{cef,ocsf,syslog}.go`) — any subset may be enabled simultaneously (e.g. CEF to one collector AND OCSF to another). Each composes a `WriterSink` into the same `MultiSink` fan-out as `audit.webhook`, wired AFTER PII redaction (inside the `Recorder`), so operators get the same redacted view every other sink sees. Formatters only: `output` is `stdout`, `stderr`, or a local file path (opened append-only, created `0600`) — no network transport (the network delivery of these same formatters is `audit.kafka` below) |
| `audit.cef.{enabled,output}` | Enables an ArcSight CEF sink. `vendor`/`product`/`version` fill the CEF header's Device Vendor/Product/Version fields; empty falls back to `Snaplink`/`SSO`/the running binary's build version |
| `audit.ocsf.{enabled,output}` | Enables an OCSF (Open Cybersecurity Schema Framework) NDJSON sink — one OCSF Authentication/Account Change/Authorize Session/API Activity-class JSON object per line, with `product.name`/`product.vendor_name` fixed to `SSO`/`Snaplink` |
| `audit.syslog.{enabled,output,facility,hostname,app_name}` | Enables an RFC 5424 syslog sink (structured-data carries `Event.Metadata`; RFC 3164 legacy BSD framing is NOT supported). `facility` follows RFC 5424 Table 1 (0-23); `0` (the Go zero value) falls back to `10` (authpriv), since facility 0 (kernel) is never a realistic choice for an application audit trail. `hostname` empty resolves `os.Hostname()` at wiring time; `app_name` empty defaults to `sso-server` |
| SIEM severity | All three formatters project ONE shared internal severity scale (`Outcome` + a small per-`EventType` override table in `auditsink`) into their own range: CEF `0-10`, OCSF `severity_id` `1-6`, syslog `0-7` — an event escalated once is escalated identically across every export format |
| `audit.kafka.enabled` | Publishes every recorded event as one Kafka message on `audit.kafka.topic`. The `github.com/segmentio/kafka-go` dependency lives ONLY in the `infrastructure/kafka` nested Go module (own `go.mod`) — the root module never imports it. Build the public `full` profile or the historical `standard-kafka` compatibility profile; their generated registrar explicitly installs `kafkaaudit.Factory` at startup without `init` or a fork. The ordinary `standard` binary intentionally has no Kafka factory, so `enabled: true` there fails boot CLOSED instead of silently dropping audit events |
| `audit.kafka.{brokers,topic}` | REQUIRED when enabled. `brokers` lists bootstrap broker addresses (host:port), tried in order; `topic` is the single destination topic for every event (no per-tenant/per-event-type routing — pair with a downstream Kafka Streams/Connect job for that) |
| `audit.kafka.format` | Wire encoding per message: `json` (default) — an explicit `schema_version` field wrapping the `auditspi.Event` JSON, since a Kafka consumer (unlike an HTTP webhook receiver) has no per-message content negotiation — or `cef` \| `ocsf` \| `syslog`, reusing the SAME `auditsink` formatters `audit.cef`/`audit.ocsf`/`audit.syslog` use, unchanged, over this transport |
| `audit.kafka.{client_id,required_acks,batch_timeout,async}` | `client_id` (default `sso-server`) identifies the producer in broker-side logs. `required_acks` is `none`\|`one`\|`all` (default `all` — full ISR ack; audit events are a compliance record this sink does not want silently dropped on a leader failover, the opposite of the underlying Kafka client's own library default). `batch_timeout` bounds partial-batch buffering (library default 1s when zero). `async` (default `false`) publishes fire-and-forget when `true`, swallowing the produce error — leave `false` and pair with `audit.async` to move the broker round-trip off the request hot path instead, so `Record`'s error return stays a real signal for the audit Recorder's fail-open policy |
| `audit.kafka` sink lifecycle | Composed into the primary `MultiSink` behind a `RetryingSink` (masks transient broker hiccups, same posture as `audit.webhook`). Graceful shutdown calls `Close(ctx)` on the underlying producer (flush + disconnect) before the process exits |

## Cluster

| Feature | Config | Behavior |
|---|---|---|
| Cross-replica revocation | `WithCrossReplicaRevocation` | Broadcasts revoked token+exp; peers adopt local-only; additive, oracle-safe, fail-open, no re-broadcast |
| Coordinated key cutover | `WithCoordinatedKeyRotation` | Broadcasts demoted+new kids over `cluster.Bus`; FAIL-SAFE deferred retire |
| Client cache invalidation | `identity.client_cache.enabled` | `KindClientChange` busts per-login TTL cache on every client mutation |
| Authz policy invalidation | `WithAuthzPolicyBundleCacheTTL` (default 5m) | `KindAuthzPolicyChange` via `InvalidateAuthzPolicyBundleCache` after role, resource-catalog, or SoD policy mutations; fail-open |
| Config drift detection | `config_audit.drift.interval` / `WithConfigDriftDetection` | `KindConfigDigest` broadcast + compare; mismatch -> `config_drift_detected` audit event + `sso_config_drift_detected_total`; report-only, never blocks |

## CAEP / SSF

| Key | Effect |
|---|---|
| `caep.{enabled,receiver_timeout,set_ttl,delivery_retry_max_attempts,delivery_retry_initial_backoff,delivery_retry_max_backoff}` | SSF SET transmitter/receiver config |

## SCIM Push Provisioning

Outbound SCIM 2.0 provisioning (`protocols/scimprovision`, `sso.WithSCIMProvisioner`) — the reverse direction of the SCIM `/Users` + `/Groups` receiver (`scim.groups.*` above): pushes user create/update/delete and group-membership changes to ONE downstream SCIM 2.0 application, as an additional audit Sink (same tap as `webhooks.*`). Disabled by default (`scim.push.enabled: false`) — zero outbound SCIM traffic, byte-identical to a build without the feature.

| Key | Effect |
|---|---|
| `scim.push.enabled` | Builds an `HTTPSCIMProvisioner` + `scimprovision.Sink` and wires `sso.WithSCIMProvisioner`. `false` (default) = no sink tap, no outbound requests |
| `scim.push.base_url` | Downstream SCIM 2.0 service root (e.g. `https://app.example.com/scim/v2`); `/Users` and `/Groups` resolve relative to it. Required when enabled |
| `scim.push.bearer_token` | `Authorization: Bearer <token>` on every outbound request (RFC 7644 §2's common auth model). Inject via `SSO_SCIM__PUSH__BEARER_TOKEN` or a `secret://` reference — never commit the literal to YAML |
| `scim.push.timeout` | Per-request HTTP timeout; 0 = SDK default (10s) |
| `scim.push.group_client_id` | Which `permissions.Role` fleet to push as SCIM Groups; falls back to `scim.groups.group_client_id` when unset |
| `scim.push.retry.{max_attempts,initial_backoff,max_backoff}` | Per-delivery retry/backoff (reuses `platform/audit/auditsink.RetryingSink`); a delivery that exhausts its budget lands in a process-local `platform/lifecycle/webhook.MemoryDeadLetterStore` |

Downstream identity resolution uses `externalId` (RFC 7643 §3.1) + a `filter=externalId eq "..."` lookup (RFC 7644 §3.4.2.2), resolved fresh on every call — no local id-mapping table. A downstream that doesn't support filtering on `externalId` is a known limitation of the reference `HTTPSCIMProvisioner`; see `protocols/scimprovision/doc.go`.

## WebAuthn

| Key | Effect |
|---|---|
| `webauthn.attestation.policy_mode` | `off`\|`allowlist`\|`denylist`; active mode REQUIRES `conveyance: direct\|enterprise` + ≥1 AAGUID |
| `webauthn.attestation.mds.*` | FIDO MDS integration (JWS-rooted at production root; startup snapshot; reload by restart) |
| `webauthn.primary_auth_enabled` | Opt-in passwordless passkey PRIMARY login: registers a `core.Authenticator` under `provider=webauthn` at `/auth/login` (discoverable credential, no username). Requires `webauthn.enabled`; default false is byte-identical — purely additive alongside password + WebAuthn-as-second-factor. Per-client `allow_passwordless_only` (in `clients[]`) then refuses `provider=password` for that client (400 `passwordless_required`) while leaving every other provider available |
| `webauthn.passkey_policy.require_passkey` | Opt-in require-passkey enrollment-nudge policy (`domains/authenticators/passkeypolicy`, `sso.WithPasskeyPolicy`): a successful `/auth/login` response for a user with no registered WebAuthn credential carries an advisory `passkey_enrollment_recommended: true` field. NEVER blocks or degrades the login — pure UX nudge. Default false is byte-identical. Requires `webauthn.enabled` (cmd fails loud at boot otherwise) and an `MFAEnrollmentStore` wired (else the nudge never fires — no factor data to check) |
| `webauthn.passkey_policy.passkey_prompt_frequency` | `never` (suppress the nudge outright) \| `once` (default; nudge every login while the user has no passkey) \| `periodic` (additionally consult the wired `trust.TrustScorer`, `sso.WithTrustScorer` — throttle on a low-risk login, always nudge on a high-risk one; no scorer wired, or a scoring error, degrades to `once` — fail-open toward MORE nudging). An unrecognized value fails loud at boot |
| `webauthn.passkey_policy.passkey_recovery_allowed` | Advisory metadata echoed alongside the nudge (`passkey_recovery_allowed: true`) so client UI knows whether to offer a "lost your passkey?" affordance. Enforces no recovery flow itself — see `domains/authenticators/passkeypolicy`'s package doc for the recommended reuse of the existing recovery-code (`POST /me/mfa/recovery-codes`, MFA method `recovery`) + WebAuthn re-registration (`POST /me/mfa/webauthn/{begin,finish}`) endpoints, and the passwordless-only gap that reuse does NOT close |

**Precision note:** as of this policy's introduction, `core.MFAEnrolledFactor` carries no per-credential "discoverable" bit and the WebAuthn ceremony does not request/capture the `credProps` extension, so "has a passkey" is currently determined as "has ANY registered WebAuthn credential" — a security key registered purely as a second factor also satisfies the policy. See the package doc's PRECISION NOTE.

## Snapshot

| Key | Effect |
|---|---|
| `snapshot.redact_secrets` | Removes client credentials, known user credential attributes and secret-bearing enterprise-connection config keys from export-local copies (NOT restorable — use encryption for backup); default nil ⇒ byte-identical |
| `snapshot.storage.backend` | Where `Pipeline` persists envelopes: `file` (default; `snapshot.storage.file.dir`, defaults to `./snapshots`) \| `inline` (in-memory; tests only) |
| `snapshot.encryption.backend` | Sealer for snapshot envelopes: `none` (default; plaintext JSON) \| `passphrase` (argon2id + XChaCha20-Poly1305; `passphrase`/`passphrase_file`) \| `key` (operator-supplied 32-byte `key`/`key_file`, e.g. from a KMS-issued DEK) |

Snapshot schema v2 carries an explicit category manifest and adds tenants,
tenant-domain routing, enterprise connections and pairwise-subject mappings.
Readers continue accepting v1; a v1 replace restore cannot delete categories
that v1 could not represent. After a successful non-dry-run restore, the server
flushes every local control-plane cache and broadcasts the same full
invalidation to peer replicas. Sessions and live tokens remain deliberately
excluded.

## Releases

Admin app version pin / rollback subsystem (Phase D-3, `POST /api/v1/admin/releases*`). Disabled by default (`releases.enabled`).

| Key | Effect |
|---|---|
| `releases.store.backend` | Where `Release` records persist: `file` (default; one `<id>.json` per release + a CURRENT marker, `releases.store.file.dir`) \| `memory` (lost on restart; tests/demos) |
| `releases.pinner.backend` | Deploy mechanism a `Pin`/`Rollback` invokes: `noop` (default; records the call only) \| `static` (on-disk bundle symlink swap) \| `docker` (`docker compose pull && up -d`) |
| `releases.probe.backend` | Post-`Pin` health probe: `""` (default; no probe, Pin always "succeeds") \| `http` (GETs `releases.probe.http.url`, 2xx = healthy; `polls`/`backoff` control the retry loop) |

## Backup

| Key | Effect |
|---|---|
| `backup.dir` | Destination directory for `POST /api/v1/admin/backup` (`VACUUM INTO` snapshots); empty (default) = OS temp dir. Filenames are timestamped (`sso-backup-<source>-<UTC stamp>.db`), so without `backup.keep` the directory grows monotonically — one file per source per triggered backup, never overwritten |

## Disaster Recovery

See [dr-framework.md](dr-framework.md) for failure levels, RPO/RTO targets, and the recovery runbook. Disabled by default; requires `snapshot.enabled: true`.

| Key | Effect |
|---|---|
| `dr.enabled` | Starts the background `SnapshotReplicator` loop. Requires `snapshot.enabled: true` — fails loud at boot otherwise |
| `dr.target_dir` | DR replica mount the replicator copies checksum-verified snapshot envelopes into |
| `dr.interval` | Replication cycle interval; default 15m. First cycle fires immediately on boot |
| `dr.keep` | Retained replica count in `target_dir`; default 7 |
| `dr.rpo_target` | Max acceptable replica staleness; `<=0` disables the age check (any replica counts as ready) |
| `dr.rto_target` | Reported alongside measured recovery history on the admin status endpoint; does not gate anything live |
| `dr.rto_history` | Bounded measured-RTO record count kept in memory; default 32 |
| `dr.gate_readiness` | Folds the DR readiness verdict into `/readyz`. Default false — DR status stays report-only (`GET /api/v1/admin/dr/status` + `sso_dr_*` metrics) and never blocks auth traffic on its own |
| `backup.keep` | Retain only the newest N backup files per source after each run; `0` (default) disables retention (keep all). Pruning filters on the per-source filename prefix, so unrelated files sharing the directory are never deleted |

## Credential Rotation

Disabled by default; the read-only governance inventory (`GET /api/v1/admin/credentials`) never exposes secret material.

| Key | Effect |
|---|---|
| `rotation.enabled` | Builds a `platform/lifecycle/rotation` Registry + Scheduler and wires `sso.WithCredentialRotation`. Registers the webhook-HMAC secret rotator (seeded from `audit.webhook.signing_secret`; empty ⇒ a fresh random secret). The Scheduler Start/Stops with the process lifecycle |
| `rotation.interval` | Per-class rotation cadence; required (`> 0`) when enabled — the first rotation fires one interval after boot |
| `rotation.overlap` | Window a demoted secret stays verify-only after each rotation so in-flight pre-rotation deliveries still authenticate; `<=0` = no overlap |
| `rotation.tick` | Scheduler due-check poll resolution (how late a due rotation can fire, NOT the cadence); `<=0` = `rotation.DefaultSchedulerTick` |
| `rotation.retry_base` / `rotation.retry_max` | Failure-retry backoff (base doubled per consecutive failure, capped) while the old credential keeps serving; `<=0` = package defaults |

OAuth client secrets use the same scheduler but have an independent cadence and a storage-backed zero-downtime rollout window:

| Key | Effect |
|---|---|
| `client_secret_rotation.enabled` | Enables scheduled rotation for active confidential clients. The configured client store must implement due-listing and overlap rotation; memory, SQLite, Postgres, Redis, and the built-in cache/federation decorators do |
| `client_secret_rotation.interval` | How old a client secret may become and how often that credential class is scheduled; required (`> 0`) when enabled |
| `client_secret_rotation.overlap` | How long the previous bcrypt hash remains valid after rotation. `0` selects the 24h default; an explicit value must be at least 1h. The new secret works immediately, the old secret works only before the persisted deadline, and a later rotation replaces the prior fallback |
| `client_secret_rotation.lifetime` | Validity of each newly rotated secret. `0` selects `interval + overlap`; an explicit value must be greater than `interval`, preventing scheduler jitter from expiring a secret before its replacement is installed |

The admin `RotateSecret` RPC uses a 24h default overlap and 90-day lifetime even when scheduled rotation is disabled, allowing operators to deploy the newly returned secret without downtime. It accepts explicit `overlap_seconds` / `lifetime_seconds`, returns `client_secret_expires_at`, and `GET /api/v1/admin/clients/expiring?within_seconds=` provides the 30-day warning view. Direct store calls with no overlap remain an immediate-cutover primitive for compromise response and tests. Previous hashes and overlap deadlines are persisted by every production client-store backend but never appear in client DTOs, snapshots, or discovery metadata; expiry itself is safe admin metadata and is included in the admin/DCR projections.

Enabling `rotation` also wires `sso.WithCredentialCompromise` against the SAME Scheduler, mounting the emergency `POST /api/v1/admin/credentials/{type}/compromise` (`admin:write`) — force-rotates a leaked credential class OFF schedule with NO overlap window; the response is the new version's governance metadata only, never the secret.

## Token Policies

Token-policy governance engine (`domains/tokenpolicy`, `sso.WithTokenPolicy`). Disabled by default; an absent section is byte-identical to a build without it. A store lookup error at issuance FAILS OPEN (issue the token). The read-only governance view is `GET /api/v1/admin/token-policies` (never exposes secret material). Provide rules via EITHER `token_policies.file` OR `token_policies.policies` — setting both fails loud at boot.

| Key | Effect |
|---|---|
| `token_policies.file` | Path to a standalone bundle whose top-level `token_policies:` list is parsed by `tokenpolicy.ParseYAML`. Mutually exclusive with `token_policies.policies` |
| `token_policies.policies` | Inline rule list (same schema as a bundle entry): `name`, optional selector (`client_id`, `scopes`), and dimensions (`max_ttl`, `max_refresh_depth`, `max_active_sessions`, `require_renew_after`, `block_scope_combos`). Rules only ever TIGHTEN (clamp TTL downward, deny scope combos) |

## Conditional Access

Zero-trust conditional-access (CAP) engine (`domains/conditionalaccess`, `sso.WithConditionalAccess`), mounting `GET /api/v1/admin/access-policies` and the immediate convergence operation `POST /api/v1/admin/access-policies/converge`. Disabled by default. The engine is ALWAYS evaluable via `Server.EvaluateConditionalAccess`; when `access_policies.enforce` is `true` it additionally becomes a LIVE Policy Enforcement Point after credential validation on `/auth/login`, on `prompt=none` renewal, before every refresh-token successor is issued, and in a periodic active-session convergence worker. With `enforce` left `false` (the default), a wired store changes no live auth decision, matching every prior release's advisory-only behavior. Provide policies via EITHER `access_policies.file` OR `access_policies.policies`; both fails loud.

A matched `deny` verdict returns `403 conditional_access_denied` during interactive login; a matched `require_step_up` verdict routes through the SAME MFA orchestration `mfa.*` configures (`WithMFAProvider` + `WithMFAChallengeStore`). Without both MFA dependencies wired, the resolved operator policy fails closed with `403 conditional_access_denied` instead of being bypassed. `restrict_scopes` is intersected with the client-authorized scope set and survives MFA and consent continuations, so authorization codes, access tokens, and refresh tokens all inherit the reduced authority; `log: true` emits the resolved structured decision. `prompt=none` silent renewal re-evaluates the same policy after validating the ID-token hint and its exact `sid`: deny is blocked, required step-up returns `interaction_required`, and scope restrictions cap the renewed token. The hint binds its original scopes, RFC 8707 resources, and RFC 9396 authorization details; renewal may preserve or reduce that grant but expansion returns `400 consent_required` and requires an interactive flow. Refresh-token use re-evaluates current groups, device, trust, geo, session age, and authentication age: deny collapses to `400 invalid_grant`, step-up (or a continuously verified session marked `StepUpRequired`) returns `400 insufficient_user_authentication`, and scope restriction can only shrink the successor grant. The caller must restart an interactive login to satisfy a refresh-time step-up. A trust-scorer or policy-store outage still FAILS OPEN on login, silent renewal, and refresh (logs and proceeds), regardless of `default_deny` — an unavailable risk signal must never become an account-lockout oracle.

Pair with `sso.WithTrustScorer` (a `shared/trust.TrustScorer`, typically a `trust.WeightedComposite` — see "Trust Scoring" below for the reference-implementation cmd wiring) and `sso.WithDeviceFingerprint` (a `conditionalaccess.DeviceFingerprint`, e.g. `conditionalaccess.NewMemoryDeviceFingerprint()`) to feed the engine real composite-trust and managed-posture signals. `user.member_of` reads the current per-user/client role codes from `permissions.Provider`; `device.type` is parsed from User-Agent, while `device.trust_level`, `device.is_new`, and `device.is_new_location` read the physical device inventory wired by `sso.WithDeviceStore`. `session.age_seconds` and `authentication.age_seconds` are inclusive minimum ages used for periodic reauthentication; a missing or future-dated timestamp does not match. `session.max_concurrent` is a per-subject/client ceiling: login evaluates existing sessions plus the prospective new one, while convergence removes newest excess sessions until the count is within the ceiling. Missing/erroring role, device, geo, or session-count sources degrade to an absent signal instead of denying.

When enforcement is active, server-side sessions persist client, scope, authentication-time, device and trust context across memory, SQLite, Redis and Postgres backends. Each sweep uses one policy snapshot: deny revokes; step-up writes `StepUpRequired`; scope restriction persists an authorization ceiling that refresh may preserve or reduce but never re-expand. The first sweep runs at process startup, later sweeps use the configured interval, and the admin POST runs the same bounded pass immediately. Policy-store failure mutates nothing and is retried on the next interval.

| Key | Effect |
|---|---|
| `access_policies.file` | Path to a standalone CAP policy bundle, parsed by the strict `conditionalaccess` loader (unknown keys rejected). Mutually exclusive with `access_policies.policies` |
| `access_policies.policies` | Inline CAP rule list (`name`, `priority`, `enabled`, `dry_run`, `conditions`, `actions`) |
| `access_policies.degraded_trust` | Conservative trust value substituted when a signal is missing; `<=0` or `>1` normalizes to the engine default (`0.3`) |
| `access_policies.default_deny` | Flips the no-policy-matched verdict from allow to deny (a zero-trust posture) and governs the fallback when the store is unavailable |
| `access_policies.enforce` | Activates live enforcement on `/auth/login`, `prompt=none`, and refresh-token issuance. `false` (default) keeps the engine advisory-only even with policies configured — stage policies (`dry_run` entries, `enforce: false`) and check the admin governance view before flipping this on |
| `access_policies.session_sweep_interval` | Active-session convergence cadence when enforcement is enabled. `0` takes `5m`; negative values fail startup |
| `access_policies.session_sweep_batch_size` | Maximum sessions evaluated/mutated per pass. `0` takes `500`; negative values fail startup. The cursor advances between passes |

## Trust Scoring

Zero Trust Framework Phase 1 composite trust score (`shared/trust`, `sso.WithTrustScorer`). Disabled by default: an absent/`false` section wires nothing — byte-identical to a build without the feature. The reference sso-server binary auto-wires `trust.enabled` (`cmd/sso-server/serverbuildplatform.BuildTrustScorer`) into a `trust.WeightedComposite` over whichever reference scorers `trust.weights` names, each configured from its own section below, and hands it to `sso.WithTrustScorer`. The score itself is a pure SCORING foundation — it is ADVISORY-only, never an allow/deny decision by itself: it only affects a live `/auth/login` outcome once paired with the Conditional Access engine ABOVE running with `access_policies.enforce: true` (see that section's fail-open contract). Wiring `trust.enabled` alone, with no conditional-access policy consulting it, changes no request behavior.

`trust.weights` keys select which reference scorers join the composite (a missing key excludes that scorer): `geo_risk` (country allow/deny lists, never errors), `ip_reputation` and `behavior` (need a login-history data source — see below), and `device_posture` (an explicit stub reserved for a future MDM integration; always returns `device_posture.default_score`, never errors). Every scorer degrades to its own `floor_on_error` (or, for the two that never error, is simply always available) rather than failing the whole composite — a flaky scorer never blocks `/auth/login`.

When `anomaly.enabled`, the `ip_reputation` and `behavior` scorers read the SAME `domains/anomaly` stores (`IPFailureCounter` / `RecentLoginStore`) the anomaly detectors already populate — composition-root adapters in `BuildTrustScorer` hash the caller's IP with the exact same salted scheme (`sha256(anomaly.ip_salt || ip)`, truncated to 16 hex chars) the anomaly detectors use, so `ip_reputation` reads the exact rows a brute-force-shadow detector already wrote rather than a second, disconnected hash space. With `anomaly.enabled: false` (or the relevant sub-store unopened), both scorers simply cold-start to their "no_signal" value — never an error.

| Key | Effect |
|---|---|
| `trust.enabled` | Builds the composite scorer and wires `sso.WithTrustScorer`. Requires at least one `trust.weights` entry — an unknown scorer name or a weight `<=0` fails loud at boot |
| `trust.weights` | Map of scorer name (`geo_risk`, `ip_reputation`, `behavior`, `device_posture`) to its relative composite weight (`>0`); a missing key excludes that scorer |
| `trust.geo.trusted_countries` / `trust.geo.denied_countries` | ISO 3166-1 alpha-2 lists the `geo_risk` scorer compares (case-insensitively) against the request's enriched country |
| `trust.ip_reputation.window` / `.failure_threshold` / `.distinct_subject_threshold` | Tuning for the shared brute-force-shadow signal, read as an advisory score instead of a hard block; zero values fall back to the scorer's package defaults |
| `trust.ip_reputation.floor_on_error` | Score substituted when the backing store errors (fail-open) |
| `trust.behavior.history_limit` | How many past logins the time-of-day baseline consults; zero uses the package default |
| `trust.behavior.floor_on_error` | Score substituted when the backing store errors (fail-open) |
| `trust.device_posture.default_score` | The stub's unconditional return value (clamped to `[0,1]`) until an MDM integration replaces it |
| `trust.serialization.stamp_session_metadata` / `.include_token_claim` / `.claim_name` | Both default `false` — surfacing the computed score into the login audit event's metadata and/or a token claim is opt-in and changes nothing on the wire until enabled. Applies ONLY to the direct-mint `/auth/login` response (`response_type` empty/`token`, where a token is minted synchronously) — the `authorization_code` response branch persists a code and mints no token until a LATER, separate `/token` exchange that this section does not reach |

When `metrics.enabled` is also set, the composite registers `sso_trust_score` (a histogram of every scorer's returned value, labeled by scorer name, including the composite's own aggregate under `scorer="composite"`) and `sso_trust_scorer_errors_total` (a counter of degrade-to-floor events, labeled by scorer name) on the shared metrics registry.

## Session Trust Decay (continuous verification)

Zero-trust session-trust-decay (`shared/trust`, `platform/lifecycle/continuousverify`, `sso.WithSessionTrustDecay`). A trust score bound to each session at login decays over time; a background `ContinuousVerificationAgent` marks below-floor sessions for step-up; and the min-trust gate `Server.RequireSessionTrust(ctx, sessionID, minTrust)` returns an RFC 9470 step-up challenge (`insufficient_user_authentication`) for a high-risk operation whose session trust has decayed. **Disabled by default**: an absent section (or `interval<=0` / `factor` outside `(0,1)`) stamps no trust at login, starts no agent, and the gate fail-opens — byte-identical to a build without the feature. FAIL-OPEN throughout: a missing trust signal (legacy/zero-value session), a store outage, or a scoring gap NEVER hard-denies — the decay/agent are advisory infra.

| Key | Effect |
|---|---|
| `session_trust_decay.interval` + `session_trust_decay.factor` | The exponential decay curve: the bound score is multiplied by `factor` (in `(0,1)`, e.g. `0.95`) once per `interval` (e.g. `5m`). Both are the enable switch — `interval<=0` or `factor` outside `(0,1)` disables the feature |
| `session_trust_decay.floor` | The agent's step-up threshold; a live session whose decayed score drops below `floor` is marked for step-up on its next request |
| `session_trust_decay.min_score` | Asymptotic lower bound the decayed score never falls below (avoids decaying an old-but-legitimate session to a hard `0`) |
| `session_trust_decay.sweep_interval` | The agent's polling cadence (`<=0` = 1m default). Off the request hot path |
| `session_trust_decay.step_up_acr_values` / `session_trust_decay.step_up_max_age` | Shape the RFC 9470 challenge the gate returns; both empty ⇒ the gate demands a fresh re-authentication |
| `session_trust_decay.initial_score` | Trust bound to a session at login (`0 < v <= 1`); out of range defaults to `1.0` (fully trusted at login, decaying thereafter) |

The agent emits a `session_trust_stepup` audit event and increments `sso_zero_trust_session_stepup_total` for each session it marks.

## Token Anomaly Detection

Token-behavior anomaly detection (`domains/tokenanomaly`, `sso.WithTokenAnomalyDetector`, Phase 3 token governance). A `tokenanomaly.Detector` DECORATES the token-usage store, captures per-thumbprint geo/velocity observations off the request path, and a periodic `Server.RunTokenAnomalyDetection` sweep turns them (plus the per-client rate buckets) into governance findings on `GET /api/v1/admin/tokens/suspicious`. **DETECTION / REPORTING ONLY** — a finding NEVER feeds an auth decision (same hard contract as `anomaly.Runner`). **Disabled by default**: an absent section (`enabled=false`) starts no sweep and wires nothing — byte-identical to a build without the feature.

Because the detector is a `tokenusage.Store` decorator, enabling it **also co-wires the wave-1 token-usage recorder** (`sso.WithTokenUsageRecorder`) as its telemetry substrate: the recorder drains usage events into the detector off the request path. That co-wiring also mounts the token-usage / portfolio admin read APIs (`GET /api/v1/admin/tokens/usage`, `/portfolio`, `/subjects/:subject`, `POST /revoke`). The recorder is not independently configurable this wave — it exists to feed the detector. When `metrics.enabled` is also set, `NewServer` arms the findings counter (`sso_token_anomaly_findings_total`) and the usage counters.

| Key | Effect |
|---|---|
| `token_anomaly.enabled` | Builds the token-usage recorder + the anomaly detector decorating its store, wires both Options, and starts the background sweep. `token_anomaly.sweep_interval` MUST be `> 0` when enabled (fails loud at boot otherwise) |
| `token_anomaly.sweep_interval` | Cadence of the off-path `RunTokenAnomalyDetection` sweep — how often observations become findings (e.g. `1m`) |
| `token_anomaly.max_findings` | Bound on the in-memory finding store the sweep upserts into (`<=0` = package default). A rolling operational view, not an archive |
| `token_anomaly.queue_size` | Bound on the recorder's drop-on-full ingest queue (`<=0` = default). Lower sheds telemetry load sooner; a full queue drops events (fail-open — telemetry loss never adds `/token` latency) |
| `token_anomaly.max_buckets` | Bound on the token-usage aggregation store the detector decorates (`<=0` = default) |
| `token_anomaly.max_thumbprints` / `window` / `velocity_gap` / `spike_factor` / `spike_min_count` | Optional detector tuning (each zero value keeps the adaptive package default): observation-table cap, analysis look-back, impossible-travel interval, and the per-client rate-spike multiple + absolute floor |

## Active ITDR (Threat-Action Executor)

The detection-to-response bridge (`domains/threataction`, `sso.WithThreatExecutor` + `sso.WithThreatPolicyStore`): a composite executor that turns `anomaly.Runner` and `tokenanomaly.Detector` findings into response actions — session suspension, refresh-token family revocation, MFA step-up, admin notification — off the request path. Without this section, anomaly/token-anomaly detection is audit-only ("smoke alarm, no fire department"); enabling it wires the SAME executor instance into both detectors plus the Server, so they share one rate-limiter and one policy view. **Disabled by default**: an absent/`false` section wires neither the executor nor the policy store — byte-identical to a build without the feature. Enabling it with an empty `policies` list mounts the admin CRUD API (`GET`/`PUT`/`DELETE /api/v1/admin/threat-policies`) but every threat still resolves to `default_action` (or the package's `noop`) until a policy is added there or in config.

`suspend`/`revoke`/`step_up_mfa`/`challenge` handlers each fail-open when their backing store isn't wired (no session manager, no refresh-token family tracker) — the executor still builds and the `notify` action (audit-only) always works. `challenge` and `step_up_mfa` currently share the same underlying mechanism (`core.SessionTrustManager.MarkStepUp` — the only "require something extra on the next auth" primitive the SPI exposes today) but are distinct policy-facing action names, so both are available to policy authors independently.

| Key | Effect |
|---|---|
| `threat_action.enabled` | Builds the composite `ThreatExecutors` + in-memory `ThreatPolicyStore` and wires `sso.WithThreatExecutor` / `sso.WithThreatPolicyStore`, plus `anomaly.WithThreatExecutor` / `tokenanomaly.WithThreatExecutor` on whichever of those two detectors is also enabled |
| `threat_action.default_action` | Action applied when no policy matches a threat: `noop` (default, audit-only) \| `suspend` \| `revoke` \| `step_up_mfa` \| `challenge` \| `notify` |
| `threat_action.policies` | Inline policy list seeding the `ThreatPolicyStore` at boot (`name`, `enabled`, `type`, `severity`, `action`, `rate_limit: {per_window, max}`, `conditions`). Further policies can be added/edited at runtime via the admin CRUD API. `type` supports wildcard matching in addition to an exact string: a trailing `*` (`"impossible_travel/*"`) is a prefix match, a leading `*` (`"*_burst"`) is a suffix match, and a bare `"*"` matches any type (same result as leaving `type` empty). Any other placement of `*` (mid-string, or more than one) is treated as a literal character, not expanded — see `ThreatPolicy.Type` / `matchType` in `domains/threataction/policy.go` |

## Degraded-Service Modes

Disaster-recovery degraded-service control plane (`platform/lifecycle/degradation`, `sso.WithDegradationManager`). Disabled by default: an absent section installs no gate and mounts no route (byte-identical). An enabled-but-`normal` build is a pass-through (one atomic load per request). With `auto_read_only_on_store_loss` the section additionally arms the automatic read_only driver described below (each replica runs its own pull-based loop; an external controller can still drive the mode endpoint).

| Key | Effect |
|---|---|
| `degradation.enabled` | Builds the degraded-service `Manager` and wires `sso.WithDegradationManager`, mounting the admin `GET`/`POST /api/v1/admin/dr/mode` read+toggle. The enforcement middleware sheds the request classes the active mode names with `503` + `Retry-After` (probes always pass) |
| `degradation.initial_mode` | Boot posture: `normal` (default) \| `read_only` \| `auth_only` \| `local_only` \| `maintenance`. An unrecognized value fails loud at boot |
| `degradation.auto_read_only_on_store_loss` | Operator INTENT flag: arms the in-process auto driver, which polls the wired storage-health sources (every store exposing a `Ping`, audit sinks excluded — audit errors are fail-open by contract) and calls `SetMode(read_only)` after a store has been continuously unhealthy for the grace window; a healthy sweep restores `initial_mode`. Transitions travel the SAME `OnChange` path as the admin dr/mode toggle (audit event + metric gauge). A deployment with no watchable store (memory-only) arms nothing and keeps booting |
| `degradation.auto_read_only.interval` | Auto-driver poll cadence; `<=0` takes the package default 30s (`degradation.DefaultAutoInterval`). Probe timeouts are bounded to half the interval, capped at 3s — a hung probe is fail-open and never drives a transition |
| `degradation.auto_read_only.grace` | Continuous-unhealthy window a store must sustain before the driver flips `read_only` (hysteresis: a transient probe jitter never flaps the mode); `<=0` takes the package default 60s (`degradation.DefaultAutoGrace`). A probe that errors or times out is indeterminate (fail-open) — it neither starts nor extends the window |

## Break-glass

Emergency ("break-glass") admin sessions. Disabled by default; without it no break-glass surface exists.

| Key | Effect |
|---|---|
| `break_glass.enabled` | Builds the in-memory `core.BreakGlassStore` and wires `sso.WithBreakGlassStore`, mounting the `POST`/`GET`/`DELETE`/`approve` `/api/v1/admin/break-glass` lifecycle endpoints |
| `break_glass.sweeper_interval` | Cadence of the active expiry sweeper (`Server.RunBreakGlassSweeper`) that destroys a grant's derived sessions at expiry; `<=0` = 1m. The grant TTL default/cap (`core.DefaultBreakGlassTTL`/`MaxBreakGlassTTL`) and per-request `require_approval` are SDK-side, not config |

## User Lifecycle

User lifecycle is both an admin state machine (`domains/userlifecycle`, `sso.WithUserLifecycle`) and an end-user authentication gate. It mounts `GET`/`POST /api/v1/admin/users/:id/lifecycle`; only `active` accounts may complete interactive, MFA or federated continuation login, redeem/renew/exchange an end-user grant (authorization code, refresh, device, CIBA, token exchange, JWT bearer, SAML bearer or agent delegation), or pass the server's access/ID-token validation path. Validation checks both `sub` and every RFC 8693 `act` link, so suspending a delegating human also stops an agent token. `client_credentials` is deliberately unaffected because it has no user subject. A missing lifecycle record is implicitly `active`; a lifecycle-store read failure fails closed. This is additive to SCIM/core `User.IsActive`: either control can deny an account.

The stock server synchronously revokes the subject's live sessions and all refresh tokens when a transition enters `invited`, `suspended`, `inactive`, `archived`, or `purged`. Stateless access tokens cannot be physically deleted, but subsequent validation by this server rejects them and RFC 7662 introspection returns `active: false`; lifecycle state and the complete `act` chain are rechecked even on an introspection-cache hit. A resource server that validates JWTs entirely offline must use introspection or a separate revocation/event channel when immediate lifecycle enforcement is required.

Disabled by default: an absent/`false` section wires nothing, byte-identical to a build without the feature. The default `memory` backend is process-local and loses state on restart. `postgres` stores the current state and append-only transition history on the shared top-level Postgres/Cockroach pool; state advancement and history insertion commit atomically. `server.topology.mode: multi` requires this shared backend when lifecycle enforcement is enabled, unless the explicitly unsafe `allow_per_pod_state` development override is set.

`user_lifecycle.auto_deprovision` is a SEPARATE, independently-gated opt-in — mirrors `sso.WithUserAutoDeprovision` itself requiring `sso.WithUserLifecycle` at the SDK layer, since the sweep persists through the SAME store. Enabling it with `user_lifecycle.enabled: false` fails loud at boot rather than silently building a sweep with nowhere to persist its transitions. When armed, `Server.RunUserAutoDeprovision` runs in a background goroutine (standard cancel/done shutdown lifecycle) advancing dormant accounts: `ACTIVE` → `INACTIVE` past `dormant_after`, and — when `archive_after > 0` — `INACTIVE` → `ARCHIVED` past `dormant_after + archive_after`. Activity is derived from the wired `SessionManager` (`userlifecycle.SessionLastActive`) — a user with no live session reads as "unknown" and is never touched (fail-safe by design; no other activity backend exists in this wiring today).

| Key | Effect |
|---|---|
| `user_lifecycle.enabled` | Builds the selected `userlifecycle.Store`, mounts the admin state-machine endpoints, enables the fail-closed end-user auth/token gate, and wires transition-triggered session/refresh-token revocation |
| `user_lifecycle.backend` | `memory` (default; single-process) or `postgres` (shared, restart-safe state and history). `postgres` requires the top-level `postgres` block and is the only HA-safe stock backend |
| `user_lifecycle.auto_deprovision.enabled` | Arms the background dormancy sweep. Requires `user_lifecycle.enabled: true`, plus `dormant_after` and `sweep_interval` both `> 0` (fails loud at boot otherwise) |
| `user_lifecycle.auto_deprovision.dormant_after` | How long an `ACTIVE` account may be idle before the sweep moves it to `INACTIVE`. `<=0` disables the sweep |
| `user_lifecycle.auto_deprovision.archive_after` | ADDITIONAL idle time beyond `dormant_after` before an `INACTIVE` account advances to `ARCHIVED` (measured from last activity). `<=0` leaves `INACTIVE` accounts untouched indefinitely |
| `user_lifecycle.auto_deprovision.max_per_sweep` | Caps transitions applied per sweep (a deprovisioning-storm guard); `0` = unlimited |
| `user_lifecycle.auto_deprovision.sweep_interval` | `Server.RunUserAutoDeprovision` background-loop cadence; `<=0` disables the loop even when `dormant_after` is set |

Every applied transition (admin- or sweep-driven) emits `admin_user_lifecycle_changed` and runs the same revocation reaction (see `docs/error-codes.md`'s "User lifecycle state machine" section for the full state table and wire error codes).

## Admin Governance Framework

Four independently opt-in `/api/v1/admin/*` governance mechanisms
(`platform/lifecycle/admingovernance`). Every section below defaults to `enabled: false`
— an absent/disabled section wires nothing, byte-identical to a build
without this framework. See `docs/error-codes.md` "Admin governance
framework" for the wire error codes each mechanism returns.

| Key | Effect |
|---|---|
| `admin_write_quota.enabled` | Wires a per-tenant/admin write-op QUOTA onto the admin middleware (`AdminMiddleware.SetWriteQuota`) — a hard, fixed-window budget on POST/PUT/PATCH/DELETE under `/api/v1/admin/`, distinct from `security.rate_limit`'s token-bucket RATE (which never resets wholesale, only refills) |
| `admin_write_quota.limit` / `admin_write_quota.window` | Max writes allowed per fixed window (e.g. `limit: 500`, `window: 1h`); `<=0` on either disables enforcement even when `enabled: true` |
| `admin_write_quota.key_by` | `tenant` keys the budget by the acting admin's tenant (falling back to admin identity when the token carries none); anything else (including omitted) keys by admin identity — each admin gets an independent budget |
| `admin_change_approval.enabled` | Builds an in-memory `admingovernance.ApprovalStore` and wires `sso.WithChangeApprovalStore`, mounting the generic two-person change-approval workflow: `POST`/`GET /api/v1/admin/changes`, `GET .../{id}`, `POST .../{id}/approve\|reject`. Generalizes break-glass's propose/approve/self-approval-refusal shape to arbitrary admin mutation types. The stock binary registers NO `Applier` — an approved change stays `approved` unless a custom composition root registers one into its own `*admingovernance.Registry` |
| `admin_change_approval.action_types` | Allow-list restricting `POST /api/v1/admin/changes`'s `action_type` to these values; empty (default) accepts any `action_type` |
| `admin_destructive_actions.enabled` | Wires a destructive-action confirmation guard onto the admin middleware (`AdminMiddleware.SetDestructiveActions`): a request matching a configured `(method, path_prefix)` rule is refused (`409`) unless it carries `X-Confirm: true` — mirrors the `{confirm: true}` convention the bulk-revoke-by-user and self-service account-erase endpoints already use, generalized to a header because this gate runs BEFORE any handler parses a body (and must also cover the grpc-gateway-proxied tenant/client/user/token/permission CRUD services) |
| `admin_destructive_actions.rules[].method` / `.path_prefix` / `.action` | One classified-destructive rule; `path_prefix` matches by prefix (not exact template) since a resolved request path carries the real id, e.g. `path_prefix: /api/v1/admin/tenants/` catches every tenant id. `action` is an operator-chosen label for logging only |
| `admin_ip_allowlist.enabled` | Wires an IP-allowlist/geo-lock onto the admin middleware (`AdminMiddleware.SetIPAllowlist`), checked BEFORE bearer auth. Composes with the EXISTING `geo.Provider` (reused via `Server.GeoProvider()`) rather than reimplementing IP/geo resolution |
| `admin_ip_allowlist.cidrs` | CIDR allow-list checked directly against the request IP (via the same `geo.DefaultIPExtractor` the enrichment middleware uses); empty = this dimension is not enforced |
| `admin_ip_allowlist.countries` | ISO 3166-1 alpha-2 allow-list checked against the WIRED `geo.Provider`'s resolution for the request IP. Unlike geo enrichment elsewhere (fail-open, UX-only), a configured `countries` list with NO resolved geo info FAILS CLOSED — an explicitly opted-in governance gate must never silently no-op. When BOTH `cidrs` and `countries` are configured, a request must satisfy BOTH (AND across dimensions) |

## Feature Gates (attack-surface reduction)

| Key | Effect |
|---|---|
| `feature_gates.{oidc,ciba,caep,federation,self_service,admin_api,branding}` | Each is `*bool`; omitted (default) or `true` = reachable when the surface's own dependencies are wired; explicit `false` = request-time gate returns the router-native 404. A gate never constructs a missing store/handler. |
| `feature_gates.oidc` | Gates `/userinfo` + `/end_session`; discovery drops `userinfo_endpoint`/`end_session_endpoint` (both `omitempty`) when off |
| `feature_gates.ciba` | Gates `POST /backchannel-authentication` (previously mounted unconditionally, 501-ing without a CIBA store — this is the first way to make it a 404 instead) |
| `feature_gates.admin_api` | Gates the ENTIRE `/api/v1/admin/*` group (incl. the `GET /api/v1/admin/endpoints` runtime inventory); off ⇒ every route in the group answers a router-native 404 — the group itself is always registered (so this gate is SIGHUP hot-reloadable in both directions; see "Hot Reload" above), reachability is what the gate controls |
| `feature_gates.branding` | Canonical name (formerly `web_spa`). With a tenant store wired it gates only public `GET /branding`; no SPA/static frontend is mounted. |
| `feature_gates.web_spa` | Deprecated alias of `feature_gates.branding`, parsed with a startup warning. Setting BOTH keys is a startup error. Removed with the next schema-version bump. |
| GET `/api/v1/admin/endpoints` | Admin-gated (`admin:read`) runtime inventory: method + path + `feature_gates` surface (or `core`) for every route THIS replica actually registered |
| Startup visibility | Any explicitly-disabled gate emits a `feature_gates_disabled` audit event + log line + sets `sso_feature_gate_enabled{feature=...}` to 0 (1 for every enabled gate) — attack-surface changes are security-relevant |

## Standalone Billing Automatic Renewals

These environment variables and equivalent `--renewals-*` flags configure the
API-only `snaplink-billing` composition root, not `sso-server` YAML. The worker
uses the same Snaplink-authenticated commerce service, PostgreSQL store and
tenant-scoped Audit Governance outbox as the billing APIs.

| Environment / flag | Effect |
|---|---|
| `SNAPLINK_BILLING_RENEWALS_ENABLED` / `--renewals-enabled` | Explicit enable switch; default `false`. A disabled process neither claims nor settles subscriptions. |
| `SNAPLINK_BILLING_RENEWALS_OWNER` / `--renewals-owner` | Unique lease owner. When enabled and empty, defaults to hostname-PID plus `-renewal`. Newlines are rejected. |
| `SNAPLINK_BILLING_RENEWALS_INTERVAL` / `--renewals-interval` | Due-subscription scan cadence; default `1m`, must be positive and less than the fixed 15-minute readiness tolerance when enabled. An enabled worker also scans immediately at startup. |
| `SNAPLINK_BILLING_RENEWALS_LEASE` / `--renewals-lease` | Persistent claim duration; default `2m`, must be positive. Exact owner and lease generation are checked before commit. |
| `SNAPLINK_BILLING_RENEWALS_RETRY_DELAY` / `--renewals-retry-delay` | Delay after insufficient wallet balance; default `1h`, capped by the fixed subscription `grace_until`. |
| `SNAPLINK_BILLING_RENEWALS_BATCH_SIZE` / `--renewals-batch-size` | Claim batch size; default `50`, valid range `1..500`. Full batches are drained before the worker waits for the next scan. |

Renewal interval, price, currency and grace days are snapshotted onto each
subscription at creation or explicit plan change. A successful paid renewal
commits the wallet debit, immutable `subscription` ledger entry, next contract
period, Entitlement snapshot and outbox facts in one serializable transaction.
Insufficient funds writes no debit; it commits `past_due`, a retry schedule and
`snaplink.billing.subscription.renewal_failed`. The first failure fixes
`grace_until`; retries never extend it, and settlement at the boundary expires
the subscription and deactivates Entitlement. PostgreSQL uses
`FOR UPDATE SKIP LOCKED`, persistent leases and deterministic per-period ledger
idempotency keys, so multiple replicas may run safely. Memory storage implements
the same state contract but is not restart-safe and remains development-only.

`snaplink-billing` exposes bounded renewal telemetry at `GET /metrics` and adds
`subscription_renewals` to `/readyz` when this worker is enabled. A cycle error
does not immediately withdraw readiness. Readiness fails only after the oldest
durable due row exceeds the fixed 15-minute tolerance, or no fully successful
cycle has completed for 15 minutes (including the startup grace window). The
worker continues running while unready so it can drain a recovered backlog.

## Standalone Billing Audit Relay Hot Activation

These settings affect only the independently deployed `snaplink-billing`
process. The relay executable is selected by the cold `billing` build profile;
runtime state can activate or drain only that already-compiled background
module.

| Environment / flag | Effect |
|---|---|
| `SNAPLINK_BILLING_AUDIT_RUNTIME_FILE` / `--audit-runtime-file` | Optional strict desired-state file containing exactly `revision` (positive integer) and `enabled` (boolean). Empty means activate revision 1 at boot. A path requires the Audit base URL and relay credentials to be configured. |
| File watch / `SIGHUP` | The process polls every 5 seconds; `SIGHUP` requests an immediate read. A higher revision activates a fresh blue/green generation or drains the active one. Equal revision/equal value is idempotent; equal revision/different value and lower revisions are rejected without replacing the active generation. |

The file is bounded to 4 KiB, must be a regular file, and must not be writable
by group or other. It contains no endpoint or credential. Audit URL, OAuth
client credentials, scope, resource, source prefix and HTTP timeouts remain
cold startup configuration. A rejected reload makes the static
`audit_relay_module` readiness check fail until the applied state is restored
or a valid newer revision is applied. Each generation has a distinct outbox lease owner; old generations
stop claiming new batches and finish an in-flight batch before shutdown.
Authentication, token issuance, quota enforcement, the primary audit sink,
redaction and hash chaining are not hot-swappable through this mechanism.

## Standalone Billing Quota Projection Relay

This precompiled worker belongs to the cold `billing` profile. It uses the
commerce store's independent quota-delivery cursor to project the latest
Entitlement revision into a separately deployed `sso-server`; it never shares
delivery state or credentials with Audit Governance or a payment adapter.

| Environment / flag | Effect |
|---|---|
| `SNAPLINK_BILLING_QUOTA_BASE_URL` / `--quota-base-url` | SSO base URL. Empty disables construction of the relay. HTTPS is required except for explicit loopback development. If the base is empty, any other non-default quota relay setting is rejected as partial configuration. |
| `SNAPLINK_BILLING_QUOTA_TOKEN_URL` / `--quota-token-url` | Snaplink client-credentials endpoint; defaults to the configured issuer plus `/token` only when the relay is enabled. HTTPS/loopback policy is identical to the base URL. |
| `SNAPLINK_BILLING_QUOTA_CLIENT_ID` / `--quota-client-id` | Dedicated, pre-registered machine client. Runtime validation rejects reuse of the Billing Audit Governance client ID; do not reuse a payment-adapter client either. |
| `SNAPLINK_BILLING_QUOTA_CLIENT_SECRET` | Environment-only secret; there is deliberately no command-line flag. When both relays are enabled, runtime validation also rejects reuse of the Audit Governance client secret. |
| `SNAPLINK_BILLING_QUOTA_SOURCE_PREFIX` / `--quota-source-prefix` | Tenant source derivation prefix; default `snaplink-billing-quota`. The exact source is `prefix + "." + base64url(SHA-256(tenant_id))` and must be pre-registered in SSO. |
| `SNAPLINK_BILLING_QUOTA_SCOPE` / `--quota-scope` | Must be exactly `tenant-quota:projection:write`; extra scopes are rejected at startup. |
| `SNAPLINK_BILLING_QUOTA_RESOURCE` / `--quota-resource` | Required exact RFC 8707 resource/audience. It must equal `tenant.resource_quota.projection_ingress.audience` in SSO and be allowed by the OAuth client. |
| `SNAPLINK_BILLING_QUOTA_RELAY_OWNER` / `--quota-relay-owner` | Unique durable claim owner; enabled relays default to hostname-PID plus `-quota`. Deployments inject a Pod/host-specific value. |
| `SNAPLINK_BILLING_QUOTA_HTTP_TIMEOUT` / `--quota-http-timeout` | Token and projection request timeout; default `5s`, positive. |
| `SNAPLINK_BILLING_QUOTA_LEASE` / `--quota-lease` | Per-delivery claim lease; default `30s`. It must exceed two quota HTTP windows plus, when enabled, two retention HTTP windows so cold token acquisition and both writes remain fenced. |
| `SNAPLINK_BILLING_QUOTA_BATCH_SIZE` / `--quota-batch-size` | Maximum claims per scan; default `100`, valid range `1..500`. |
| `SNAPLINK_BILLING_QUOTA_INITIAL_BACKOFF` / `--quota-initial-backoff` | First persisted delivery retry delay; default `1s`. |
| `SNAPLINK_BILLING_QUOTA_MAX_BACKOFF` / `--quota-max-backoff` | Exponential retry ceiling before deterministic jitter; default `1m`, not less than the initial delay. |
| `SNAPLINK_BILLING_QUOTA_POLL_INTERVAL` / `--quota-poll-interval` | Idle outbox scan cadence; default `500ms`. |
| `SNAPLINK_BILLING_QUOTA_MAX_LAG` / `--quota-max-lag` | Oldest independent pending cursor age that changes Billing readiness to `tenant_quota_projection: error`; default `5m`. |
| `SNAPLINK_BILLING_QUOTA_ERROR_PAUSE` / `--quota-error-pause` | Worker-level pause after claim/storage/authorization errors; default `5s`. The persisted event backoff remains authoritative and the worker retries indefinitely. |

SSO must cold-enable `tenant.resource_quota.backend` and
`tenant.resource_quota.projection_ingress`, then configure a revisioned source
for every commercial tenant. Each source's `client_id` equals the dedicated
Billing quota client, `source_system` equals the derived value, and
`tenant_id` is immutable. Only source records support safe SIGHUP updates;
route enablement, backend and audience remain cold. Inactive, expired or
`core_sso`-disabled Entitlements are deliberately delivered as an explicit
hard-zero projection with all four `*Limited` flags set, preserving the
difference from legacy zero-as-unlimited seeds.

## Standalone Billing Audit Retention Projection

This optional cold configuration extends the same leased Entitlement cursor;
it is enabled only together with SSO quota projection. A delivery is complete
only after both SSO quota and Audit Governance retention policy accept the
latest revision.

| Environment / flag | Effect |
|---|---|
| `SNAPLINK_BILLING_RETENTION_BASE_URL` / `--retention-base-url` | Audit Governance control base URL. Empty disables retention projection. HTTPS is required except explicit loopback development. |
| `SNAPLINK_BILLING_RETENTION_TOKEN_URL` / `--retention-token-url` | Snaplink client-credentials endpoint; defaults to issuer plus `/token` when enabled. |
| `SNAPLINK_BILLING_RETENTION_CLIENT_ID` / `--retention-client-id` | Dedicated platform policy client. Runtime rejects reuse of either Billing event-relay or SSO quota client identity. |
| `SNAPLINK_BILLING_RETENTION_CLIENT_SECRET` | Environment-only secret with no command-line flag. Runtime also rejects reuse of either other relay secret. |
| `SNAPLINK_BILLING_RETENTION_RESOURCE` / `--retention-resource` | Exact Audit Governance RFC 8707 resource; defaults to `audit-governance` when enabled. |
| `SNAPLINK_BILLING_RETENTION_HTTP_TIMEOUT` / `--retention-http-timeout` | Bounded token and policy request timeout; default `5s`, positive. |

The client requests exactly
`audit:platform:cross_tenant audit:policy:write`. Each current finite
`audit_retention_days` hard grant becomes an idempotent policy: hot is capped at
7 days, warm at 30 days, and `standard`-class archive eligibility uses the full grant. Missing,
unlimited, non-positive or over-100-year grants are rejected and retried rather
than acknowledged. The policy never deletes Audit Governance's immutable
ledger, legal holds remain authoritative, and `security`, `billing_7y`,
`account_7y` or other compliance classes are not shortened.

## Standalone Stripe Payment Adapter

These environment variables configure the optional, independently deployed
`snaplink-stripe-adapter`; they are not `sso-server` YAML and are not loaded
into `snaplink-billing`. See
[`stripe-payment-adapter.md`](stripe-payment-adapter.md) for the complete trust,
replay, deployment, and disaster-recovery model.

| Environment | Effect |
|---|---|
| `SNAPLINK_STRIPE_LISTEN` | Listener address; default `127.0.0.1:8091`. A non-loopback address is rejected unless both TLS file settings are present. |
| `SNAPLINK_STRIPE_TLS_CERT_FILE` / `SNAPLINK_STRIPE_TLS_KEY_FILE` | Built-in server TLS pair. They must be configured together. |
| `SNAPLINK_STRIPE_POSTGRES_DSN` | Required durable PostgreSQL DSN for checkout mappings, minimal event facts, retries, and claim fencing. There is no memory production mode. |
| `SNAPLINK_STRIPE_ISSUER` / `SNAPLINK_STRIPE_JWKS_URL` / `SNAPLINK_STRIPE_AUDIENCE` | Required Snaplink issuer, JWKS source, and exact checkout API audience used by the local resource-server verifier. |
| `SNAPLINK_STRIPE_BILLING_BASE_URL` / `SNAPLINK_STRIPE_TOKEN_URL` / `SNAPLINK_STRIPE_BILLING_RESOURCE` | Required Billing API, Snaplink client-credentials token endpoint, and exact Billing OAuth resource. Order reads and event delivery request separate fixed scopes. |
| `SNAPLINK_STRIPE_BINDINGS_FILE` | Required strict desired-state JSON mapping checkout clients and Billing clients to tenants. Maximum 2 MiB; must be a regular non-symlink file and not group/world writable. |
| Binding `billing_client_secret_env` | Names the environment variable containing that tenant binding's Billing OAuth secret. Names must be uppercase environment identifiers; secret values are never accepted in the file. |
| `SNAPLINK_STRIPE_API_BASE_URL` | Stripe API base; default `https://api.stripe.com`. |
| `SNAPLINK_STRIPE_API_VERSION` | Required explicitly pinned Stripe API version sent on checkout requests. |
| `SNAPLINK_STRIPE_API_KEY` | Required Stripe API key. Supply through a secret manager/environment, never a desired-state file or flag. |
| `SNAPLINK_STRIPE_WEBHOOK_SECRETS` | Required comma-separated Stripe endpoint secrets. Multiple values provide overlap during rotation; every value is checked against every accepted `v1` signature. |
| `SNAPLINK_STRIPE_RETURN_ORIGINS` | Required comma-separated exact Console return origins. Caller URLs may add paths under an origin but cannot change scheme/host or include userinfo/control characters. |
| `SNAPLINK_STRIPE_HTTP_TIMEOUT` | Hard timeout for Stripe, Billing, token, and JWKS HTTP calls; default `10s`, minimum `1s`. Redirects are rejected. |
| `SNAPLINK_STRIPE_READY_TIMEOUT` | Dependency readiness deadline; default `2s`, minimum `100ms`. |
| `SNAPLINK_STRIPE_POLL_INTERVAL` | Durable inbox claim cadence; default `1s`, minimum `100ms`. |
| `SNAPLINK_STRIPE_CLAIM_LEASE` | Per-claim lease; default `45s` and must be at least twice the HTTP timeout plus two seconds. |
| `SNAPLINK_STRIPE_SHUTDOWN_DRAIN` | Separate HTTP and relay drain bound; default `50s` and must be at least the claim lease. |
| `SNAPLINK_STRIPE_BATCH_SIZE` | Maximum facts claimed per scan; default `50`, valid range `1..500`. |
| `SNAPLINK_STRIPE_DELIVERY_CONCURRENCY` | Per-replica in-flight delivery bound; default `8`, valid range `1..100`. |
| `SNAPLINK_STRIPE_MAX_BACKLOG` / `SNAPLINK_STRIPE_MAX_BACKLOG_AGE` | Readiness safety thresholds; defaults `10000` undelivered facts and `15m` oldest age. |
| `SNAPLINK_STRIPE_ALLOW_INSECURE_LOOPBACK` | Default `false`. When true, permits HTTP only for explicit loopback service URLs and return origins; it never permits non-loopback plaintext. |

Every service URL must otherwise use HTTPS and cannot contain userinfo, query,
or fragment. Binding identities reject whitespace, control characters, slash,
and backslash. Startup performs the database migration before listening and
fails closed on any invalid trust/configuration boundary.

## Standalone Audit Governance Provisioner

These variables configure the independently deployed
`snaplink-audit-provisioner`; they are not `sso-server` YAML and are separate
from every event relay credential.

| Environment / flag | Effect |
|---|---|
| `SNAPLINK_AUDIT_PROVISIONER_MANIFEST_FILE` / `--manifest-file` | Strict create-only tenant/source/schema desired-state JSON. The regular file is limited to 1 MiB, rejects unknown fields, and cannot be writable by group/other. |
| `SNAPLINK_AUDIT_PROVISIONER_BASE_URL` / `--audit-base-url` | Audit Governance HTTPS base URL. Redirects are rejected. |
| `SNAPLINK_AUDIT_PROVISIONER_TOKEN_URL` / `--token-url` | Snaplink OAuth token endpoint. HTTPS is mandatory except explicit loopback development. |
| `SNAPLINK_AUDIT_PROVISIONER_CLIENT_ID` / `--client-id` | Dedicated platform-control client; do not reuse an ingestion relay client. |
| `SNAPLINK_AUDIT_PROVISIONER_CLIENT_SECRET` | Direct secret environment source. Mutually exclusive with the file source; there is deliberately no secret flag. |
| `SNAPLINK_AUDIT_PROVISIONER_CLIENT_SECRET_FILE` | Regular secret file up to 64 KiB, not group/other writable, with optional single trailing newline. |
| `SNAPLINK_AUDIT_PROVISIONER_RESOURCE` / `--resource` | Exactly one Audit Governance OAuth resource. |
| `SNAPLINK_AUDIT_PROVISIONER_LISTEN` / `--listen` | Operations-only probe/metrics listener; default `:8092`. |
| `SNAPLINK_AUDIT_PROVISIONER_POLL_INTERVAL` / `--poll-interval` | Reconciliation interval, minimum `1s`, default `30s`; SIGHUP also reloads immediately. |
| `SNAPLINK_AUDIT_PROVISIONER_REQUEST_TIMEOUT` / `--request-timeout` | Bounded OAuth and control request timeout; default `5s`, maximum `1m`. |
| `SNAPLINK_AUDIT_PROVISIONER_ONE_SHOT` / `--one-shot` | Apply once and return an explicit automation exit code. |
| `SNAPLINK_AUDIT_PROVISIONER_ALLOW_INSECURE_LOOPBACK` / `--allow-insecure-loopback` | Permit HTTP only for an explicit loopback host; never permits non-loopback plaintext. |

The OAuth scope is intentionally not configurable. It is exactly
`audit:platform:cross_tenant audit:policy:read audit:policy:write` and is sent
with exactly the configured resource. See the command README for revision and
exit-code semantics.

## sso-ctl Admin API Client

`sso-ctl` subcommands that talk to the admin REST API (`tenants`, `users`,
`clients`, `tokens`, `sessions`, `tui`) read their connection settings from
these environment variables — there are no `--addr`/`--token` flags, so the
env vars are the only knobs. `audit-verify --from-url` instead takes the
`--from-url`/`--bearer` flags directly.

| Environment | Effect |
|---|---|
| `SSO_ADMIN_ADDR` | Base URL of the admin API (`http://127.0.0.1:8443` by default). Point it at the canonical admin origin — since the no-redirect change, a 3xx response fails the command (exit 1) rather than forwarding the bearer token to the redirect target. |
| `SSO_ADMIN_TOKEN` | Admin bearer token sent as `Authorization: Bearer <token>` on every admin API request. The `WithToken` option (programmatic use of the apiclient package) wins over this variable. |
