# Senior Architect Expansion Directions v7 — Genuinely Uncovered High-Value Gaps

> **Analyst:** Architect Agent + Product Manager  
> **Date:** 2026-07-11  
> **Method:** Exhaustive global scan of the entire codebase (2241 `.go` files, 1114 test files,  
>   14 nested `go.mod` modules, 4 embedded SPAs, 200+ packages). Systematically read:
>   - All 30+ existing `docs/requirements/*.md` analysis documents
>   - `docs/deferred-backlog.md` (current consolidated gap index)
>   - `docs/feature-matrix.md`, `docs/config-reference.md`, `docs/observability.md`
>   - `AGENTS.md`, `DIRECTORY_MAP.md`, `ARCHITECTURE.md`
>   - All ADRs in `docs/adr/`
>   
>   Every proposed direction below was verified by:
>   1. Full grep across the entire codebase for the concept (zero implementation = genuine gap)
>   2. Full grep across ALL 30+ `docs/requirements/*.md` files (zero mention = genuinely not yet analyzed)
>   3. Manual code inspection of related packages to confirm no partial overlap
>
> **Positioning:** After 30+ rounds of expansion analysis covering protocol completeness,  
>   security hardening, productization, SaaS operations, infrastructure resilience,  
>   privacy engineering, performance optimization, developer experience, and business analytics —  
>   this project has achieved an exceptional level of coverage in every conventional dimension.  
>   
>   **This report does not repeat any direction already scoped in existing analyses.**  
>   It focuses on 5 **truly novel, high-value expansion directions** that exist at the  
>   intersection of identity security, distributed systems governance, cloud-native operations,  
>   and cross-protocol integrity — areas that standard identity-platform analysis suites  
>   systematically overlook.

---

## Preamble: Project Maturity Assessment

After a full global scan, the project's capability coverage has reached an exceptional level. The following domains are confirmed **fully covered** (not restated in this report):

| Domain | Key capabilities verified present |
|---|---|
| **Protocols** | OAuth 2.0 (7 grants + PAR/JAR/JARM/RAR/DPoP/mTLS/PKCE/CIBA/Step-Up/Transaction Token), OIDC (Core/Discovery/Logout/BCL/FCL/Form Post/Session Management/Silent Renewal/JWE), SAML 2.0 (SP+IdP+SLO), SCIM 2.0 (bidirectional + push provisioning), CAEP/SSF (bidirectional), FAPI 2.0, OpenID Federation 1.0, LDAP, Kerberos, RADIUS, WebAuthn, SPIFFE JWT-SVID, Workload Identity (GCP/AWS/Azure) |
| **Storage** | Memory + SQLite + PostgreSQL + Redis + etcd + 14 nested modules (KMS×5, SAML×4, LDAP, Kerberos, RADIUS, ext_authz, Kafka, MQTT, Vault Transit) |
| **Security** | Anti-enumeration (9 endpoint patterns), Oracle-leak hardening (10 scenarios), DPoP/mTLS/JKT, FAPI 2.0 enforce, Break-Glass (2-person control + impersonation), Per-tenant signing isolation, Data residency, FIPS 140-3, Session trust decay, Step-Up Auth (RFC 9470), Account lockout, Conditional Access, Anomaly Detection (4 detectors + Threat Action engine), Credential Health, Rate limiting, CSP Level 3 |
| **Product** | Hosted Login SPA, Admin Console SPA (full CRUD), Developer Portal SPA, User Portal (`/me`), Consent Store, B2B Enterprise Connections + HRD, Org-admin self-service, API Docs Viewer, SDK generation (TS + Python), MCP Server |
| **Operations** | DR framework (snapshot/RPO/RTO/replication/recovery timing), Config SIGHUP hot-reload (7 feature gates), Prometheus/Grafana (80+ metrics + 16 alert rules), Audit chain (hash-chain + OCSF/CEF/Syslog/Webhook/Kafka sinks), OpenTelemetry tracing, pprof, k6 load test suite, Chaos tests (×4), Benchmark gate, K8s operator (SSOConfigDrift CRD), Terraform config, Helm chart, Bare-metal HA runbook |
| **Governance** | SOC2 report generation, GDPR Art.15/17/20/30 compliance, Data retention, ReBAC engine, RBAC (wildcard + ConformanceSuite), Session hub, Webhook engine (subscription + dead-letter), User lifecycle state machine (invite/activate/suspend/delete), Change approval workflow, Token policies, Config audit + drift detection |
| **Quality** | Architecture layer import boundaries (hard gate), File ≤ 500 / func ≤ 50 / cyclo ≤ 15 (hard gates), Directory depth ≤ 3 (hard gate), 500+ maintainability tests, golangci-lint/govulncheck/gosec/CodeQL/Trivy/Dependabot (all 14 modules), 10+ fuzz tests, Race CI, Benchmark regression gate |

> **Conclusion:** The project has saturated the conventional identity-platform expansion space.  
> The remaining high-value directions lie at the **intersections** that cross-cutting  
> analysis frameworks miss: distributed identity governance, cross-protocol integrity,  
> cloud-native IAM integration, machine-identity operations, and identity-driven infrastructure.

---

## Direction 1: Principal Propagation Framework & Cross-Protocol Identity Audit

> **Cross-validation:** Zero matches in ALL 30+ `docs/requirements/*.md` for:  
> `principal.propagat`, `identity.propagat`, `cross.protocol.identity.audit`,  
> `token.chain.audit`, `act.chain.visualize`, `distributed.identity.audit`,  
> `identity.chain.of.custody`, `delegation.chain.audit`.  
> **Code evidence:** Zero Go implementation matches for any of the above.

### Why Now

The project already supports token exchange (RFC 8693) with act-chain propagation, SAML 2.0 identity federation (with NameID), SCIM 2.0 provisioning, and cross-tenant collaboration. Each protocol maintains its own identity chain independently. **However, no framework exists to systematically propagate the ORIGINAL caller identity across protocol boundaries**:

| Real-world scenario | Current behavior | Gap |
|---|---|---|
| OAuth token → SAML assertion → downstream SP | The SAML assertion carries a new NameID; no link back to the original OAuth subject | Cross-protocol identity chain broken |
| Token exchange (3 hops) → SCIM PATCH to downstream app | SCIM operation uses the final token's `sub`; the `act` chain is OAuth-only | The SCIM audit trail shows the last hop, not the original user |
| Cross-tenant collaboration (OAuth → SAML) | Each tenant sees only its own side of the identity | No end-to-end accountability for cross-tenant operations |
| AI agent delegation (human → agent → API) | The `act` chain is visible in the OAuth token but lost when the agent calls non-OAuth APIs | Agent actions are not auditable back to the delegating human |

This is NOT a protocol extension — it's a **governance and audit infrastructure** that cross-cuts every protocol the server already supports. Without it, the answer to "who originally ordered this action" is always incomplete.

### Code-level Evidence

| Location | What exists | What's missing |
|---|---|---|
| `protocols/oauth/token_exchange_helpers.go` | `act` chain for OAuth token exchange | No mechanism to propagate act into SAML NameID, SCIM `externalId`, or HTTP headers |
| `protocols/saml/idp/` | SAML assertion generation (NameID from local subject) | No `OriginalSubject` / `OriginalIdP` attribute propagation |
| `protocols/scim/` | SCIM `/Users` and `/Groups` operations | No cross-protocol `X-Original-Subject` header or similar propagation |
| `protocols/scimprovision/` | Outbound SCIM push provisioning | Provisions as the mapped SCIM user, not as the original OAuth subject |
| `platform/audit/` | Rich audit events per operation | No `original_actor` / `propagation_chain` metadata on cross-protocol operations |
| `domains/tokenexchange/agentidentity/` | AI agent delegation with entitlement resolution | Agent's downstream non-OAuth calls lose the human's identity |

### Scope

| Deliverable | Description | Effort |
|---|---|---|
| **1. Propagation context SPI** | `shared/spi/propagation.go`: a `PropagationContext` carrying `OriginalSubject`, `OriginalTenant`, `ProtocolChain` (ordered list of `{protocol, subject, issuer}`), `AuthMethod`, `AuthTime`. Immutable, append-only. | 2 days |
| **2. OAuth→SAML bridge** | Extend SAML IdP's assertion builder to accept a `PropagationContext` and stamp `OriginalSubject` / `OriginalAuthMethod` as SAML attributes. Wired via `sso.WithPropagationContextInjector`. | 2 days |
| **3. OAuth→SCIM bridge** | Extend SCIM outbound provisioner to carry `PropagationContext` as `X-Original-Subject` / `X-Propagation-Chain` headers on outbound HTTP calls. Wired via `sso.WithSCIMPropagation`. | 1 day |
| **4. Cross-tenant propagation** | Extend cross-tenant collaboration token exchange to include the home tenant's identity in the `PropagationContext` of the guest tenant's issued token. | 2 days |
| **5. Audit chain integration** | Extend `audit.Event` with optional `OriginalActor` / `PropagationChain` fields. Populate on every cross-protocol auditable action. | 1 day |
| **6. Admin governance view** | `GET /api/v1/admin/operations/:id/propagation-chain` — reconstruct the full chain from a single operation's audit event. | 1 day |

**Total:** ~9 days for a first cut connecting OAuth → SAML → SCIM.

### Edge Cases

| Edge case | Handling strategy |
|---|---|
| Propagation chain exceeds maximum length (e.g., 10 hops) | Truncate oldest hops; emit `propagation_chain_truncated` audit event |
| Downstream receiver doesn't understand propagation headers | Graceful degradation — headers are additive, never required |
| Protocol transition loses semantics (e.g., SAML NameID format ≠ OAuth `sub`) | Use `OriginalSubject` as the canonical reference; protocol-specific mapping is the downstream's responsibility |
| Tenant isolation boundary (cross-tenant propagation) | NEVER propagate the raw token; only propagate `OriginalSubject` + `OriginalTenant` as opaque identifiers |
| GDPR erasure of original subject | `PropagationContext` must reference erasure-safe identifiers (pairwise when configured), never raw PII |
| AI agent delegation chain | Agent's own identity is `sub`; `act` chain shows human → agent; each agent-to-API call MUST carry the full chain |

---

## Direction 2: Machine Identity & Workload Entitlement Lifecycle Management

> **Cross-validation:** Zero matches in ALL 30+ `docs/requirements/*.md` for:  
> `machine.identity.lifecycle`, `workload.identity.lifecycle`, `service.account.lifecycle`,  
> `workload.entitlement`, `machine.entitlement`, `non.human.identity`, `robot.account`.  
> **Code evidence:** SPIFFE JWT-SVID exists only as an authN mechanism at `/token`  
> (`shared/security/spiffe_svid.go`); there is ZERO lifecycle management.

### Why Now

The project supports workload identity AUTHENTICATION (GCP/AWS/Azure workload identity at `/token`, SPIFFE JWT-SVID token-exchange). However, there is **no framework for managing machine identities throughout their lifecycle**:

| Lifecycle stage | Current state | Gap |
|---|---|---|
| **Provisioning** | Workload identity is configured out-of-band (cloud IAM, SPIRE) | No programmatic machine identity provisioning API |
| **Entitlement mapping** | Machine identities get `client_credentials` scopes from static `Client.AllowedScopes` | No dynamic entitlement resolution based on workload attributes |
| **Rotation** | Client secrets can be rotated via admin API | No automated, scheduler-driven rotation for machine credentials |
| **Monitoring** | Token usage recording exists for human tokens | No machine-identity-specific monitoring (credential age, usage patterns, anomaly) |
| **Deprovisioning** | Machine identities live as long as the `Client` record exists | No automated deprovisioning when the workload is decommissioned |
| **Audit** | All token issuance is audited | No machine-identity-specific audit trail (which workload accessed what, when) |

Enterprise adoption requires treating machine identities with the same rigor as human identities — SOC 2, PCI DSS, and ISO 27001 all require lifecycle governance for non-human principals.

### Code-level Evidence

| Location | What exists | What's missing |
|---|---|---|
| `shared/security/securityverify/spiffe_svid.go` | SPIFFE JWT-SVID validation for token-exchange | No SPIFFE identity provisioning, no SPIRE integration, no workload registration |
| `shared/security/securityverify/workload_identity.go` | Cloud workload identity validation (token verification) | No lifecycle management (revocation, rotation, entitlement) |
| `domains/userlifecycle/` | Full user lifecycle state machine (invite→active→suspend→delete) | No analogous machine identity lifecycle |
| `platform/lifecycle/rotation/` | Credential rotation scheduler (for webhook secrets) | No machine-credential-specific rotation policies |
| `domains/tokenanomaly/` | Token usage anomaly detection for human tokens | No machine-identity-specific anomaly detection (e.g., credential abuse, unexpected API calls) |
| `interfaces/admin/users.go` | Full user lifecycle admin RPCs | No machine identity admin surface |

### Scope

| Deliverable | Description | Effort |
|---|---|---|
| **1. Machine Identity data model** | `domains/machineidentity/` — `MachineIdentity` type (id, type[spiffe|workload|apikey], status, attributes, last_seen, expires_at). Analogous to `core.User` but for non-human principals. | 3 days |
| **2. Lifecycle state machine** | States: `provisioning → active → suspended → decommissioned`. Events: `register`, `activate`, `suspend`, `resume`, `rotate`, `deprovision`. Transitions audited. | 3 days |
| **3. SPIFFE/SPIRE integration** | `infrastructure/spire/` — optional SPIRE workload registration via SPIRE API. Registers/deregisters workloads as machine identities in the SSO. | 3 days |
| **4. Machine identity admin API** | `POST /api/v1/admin/machines` (register), `GET /...` (list/filter), `POST .../rotate` (credential rotation), `POST .../deprovision`. Analogous to user admin surface. | 2 days |
| **5. Rotation scheduler** | Extend `platform/lifecycle/rotation` to support machine credential classes. `rotation.machine_identity.interval` / `overlap` in config. | 2 days |
| **6. Machine identity monitoring** | New metrics: `sso_machine_identities_total{type,status}`, `sso_machine_credential_age_seconds{type}`, `sso_machine_auth_total{type,outcome}`. Grafana dashboard panel. | 2 days |

**Total:** ~15 days for a first cut covering the core lifecycle.

### Edge Cases

| Edge case | Handling strategy |
|---|---|
| SPIFFE workload disappears without deprovisioning | Sweeper marks identities with no recent SPIRE heartbeats as `suspected_deprovisioned`; operator confirms before decommission |
| Cloud workload identity changes (e.g., GCP service account deleted) | No automatic detection — admin must deprovision manually; fail-safe: credential rotation refuses to issue new tokens for decommissioned identities |
| Machine identity with active tokens at deprovision time | Revoke ALL outstanding tokens atomically as part of the decommission transition (same pattern as user deprovision) |
| Machine identity vs. client distinction | A machine identity is a runtime principal; a client is a registered application. One machine may use multiple clients; one client may be accessed by multiple machines. The lifecycle models are orthogonal. |
| Long-lived vs. short-lived machine credentials | Support both: SPIRE-issued SVIDs (short-lived, auto-refreshed) and API keys (long-lived, rotation-mandatory). Different lifecycle policies per credential type. |
| Cross-region machine identity | Machine identities are local to a region (the workload runs in one region). Cross-region authentication uses token exchange with propagation context. |

---

## Direction 3: Cloud IAM Role/Policy Federation & Cross-Cloud Authorization Integration

> **Cross-validation:** Zero matches in ALL 30+ `docs/requirements/*.md` for:  
> `aws.iam.federat`, `gcp.iam.federat`, `azure.rbac.federat`, `cloud.iam.authorization`,  
> `cross.cloud.authorization`, `cloud.policy.sync`, `iam.role.mapping`.  
> **Code evidence:** Zero Go implementation matches for any cloud IAM integration  
> (cloud workload identity client auth handles AUTHENTICATION only, not authorization).

### Why Now

The project's workload identity support (GCP workload identity, AWS EKS OIDC, Azure workload identity) is limited to **authentication** — verifying that a cloud workload is who it claims to be. **Authorization** — determining what that workload is allowed to do — is entirely disconnected from cloud IAM:

| Scenario | Current behavior | Desired behavior |
|---|---|---|
| "This GCP service account has `roles/storage.admin` in GCP IAM" | The SSO has no awareness of this role | The SSO could automatically map GCP IAM roles to application permissions |
| "This EKS pod runs under `system:serviceaccount:prod:payment-svc` with specific RBAC" | The SSO only verifies the workload identity token | The SSO could synchronize K8s RBAC roles as application-level roles |
| "Grant this Azure managed identity access to the finance API" | Requires manually configuring scopes on the client | The SSO could discover Azure RBAC role assignments and project them as OAuth scopes |
| "Which cloud IAM roles entitle a workload to call my API?" | Impossible to answer — no bridge exists | A policy bundle could reference cloud IAM conditions in authorization decisions |

This is a fundamental gap for enterprise customers who manage authorization through their cloud provider's IAM and expect their SSO to be IAM-aware rather than creating a parallel, disconnected authorization model.

### Code-level Evidence

| Location | What exists | What's missing |
|---|---|---|
| `shared/security/securityverify/workload_identity.go` | Cloud workload identity TOKEN VERIFICATION | No cloud IAM API client, no role/policy discovery |
| `shared/security/securityverify/workload_identity_presets.go` | GCP/AWS/Azure presets for authentication | No authorization presets (role → scope mapping tables) |
| `domains/permissions/` | Permission provider SPI with role → permission mapping | No cloud IAM adapter/proxy for this SPI |
| `platform/lifecycle/rebac/` | Relationship-based access control (ReBAC) engine | No cloud IAM relationship sources (e.g., GCP IAM policy bindings as ReBAC tuples) |
| `config/config_sec.go` | `workload_identity` config block for auth | No `cloud_authorization` config block for IAM federation |

### Scope

| Deliverable | Description | Effort |
|---|---|---|
| **1. Cloud IAM role discovery SPI** | `shared/spi/cloud_iam.go`: `CloudIAMRoleProvider` interface — `ListRoles(ctx, workloadIdentity) → []Role`. GCP + AWS + Azure implementations. | 5 days |
| **2. Role-to-scope mapping engine** | `domains/cloudauthz/mapper.go`: maps discovered cloud IAM roles to OAuth scopes / application permissions. Configurable via YAML `cloud_authorization.role_mappings[]`. | 3 days |
| **3. GCP IAM adapter** | `infrastructure/cloudauthz/gcp/`: calls GCP `Cloud Asset Inventory` / `IAM API` to discover policy bindings for a workload identity. Cached, fail-open. | 3 days |
| **4. AWS IAM adapter** | `infrastructure/cloudauthz/aws/`: calls AWS `IAM` / `STS` APIs to discover role policies and trust relationships for the workload. | 3 days |
| **5. Azure RBAC adapter** | `infrastructure/cloudauthz/azure/`: calls Azure `Resource Graph` / `RBAC` API to discover role assignments for a managed identity. | 3 days |
| **6. Dynamic scope injection** | When a cloud-authenticated workload requests scopes at `/token`, inject mapped cloud IAM roles as `client_credentials` scopes automatically (narrowed by the intersection with `Client.AllowedScopes`). | 2 days |
| **7. Admin governance view** | `GET /api/v1/admin/cloud-authorization/:workload_id` — show discovered cloud IAM roles, mapped scopes, last sync time, and any mapping errors. | 1 day |

**Total:** ~20 days for a first cut covering GCP + AWS + Azure.

### Edge Cases

| Edge case | Handling strategy |
|---|---|
| Cloud IAM API is unavailable | Fail-open: role discovery failure returns empty role set (workload authenticates with only statically-configured scopes) |
| Cloud IAM role changes between token issuances | Role cache TTL (default 5m); `client_credentials` issuance re-resolves roles on every request |
| Workload has hundreds of cloud IAM roles | Cap the number of mapped scopes (configurable, default 50); log warning and truncate |
| Cloud IAM role doesn't map to any application scope | Role is silently ignored (no scope injection); audit event for unmapped roles |
| Cross-cloud workload (GCP service account calls AWS API) | Identity is per-cloud; cross-cloud calls use token exchange with propagation context (Direction 1) |
| Workload deprovisioned in cloud IAM but client remains | Next role discovery returns empty set → no scopes injected → workload cannot mint meaningful tokens; admin alert |

---

## Direction 4: Identity-Aware Network Policy & Dynamic Segmentation Framework

> **Cross-validation:** Zero matches in ALL 30+ `docs/requirements/*.md` for:  
> `identity.aware.network`, `identity.fw`, `identity.firewall`, `identity.segment`,  
> `identity.network.policy`, `ident.segment`, `ident.microsegment`, `network.identity`.  
> **Code evidence:** Envoy ext_authz exists (`mesh_authz.go` + `infrastructure/extauthz/`)  
> but there is zero integration with network policy systems, SDN controllers, or  
> identity-based firewall rules.

### Why Now

The project has comprehensive application-level authorization (permissions, ReBAC, conditional access, mesh ext_authz). However, **network-level access decisions are entirely disconnected from identity**:

| Scenario | Current behavior | Desired behavior |
|---|---|---|
| "Only users with role=admin should reach port 8443" | Requires configuring a separate network policy (K8s NetworkPolicy, cloud SG) | Network policy automatically derived from identity attributes |
| "Revoked users should be immediately blocked at the network edge" | Token revocation affects app-level auth but the network connection may persist for minutes | Network-level session termination on identity revocation |
| "This API should only be callable from workloads with SPIFFE id spiffe://trust/prod/*" | No integration between SPIFFE identity and network policies | SPIFFE-aware network policy enforcement at the L4/L7 proxy |
| "Enforce that all traffic to /admin must originate from corporate VPN" | Application-level geo/network check (if wired) | Network-level enforcement BEFORE the request reaches the application |

The project's existing Envoy ext_authz integration demonstrates the architecture exists for proxy-level authorization — but it is limited to a single-request `ALLOW/DENY` decision and does not integrate with network policy orchestration (K8s NetworkPolicy, cloud security groups, service mesh RBAC).

### Code-level Evidence

| Location | What exists | What's missing |
|---|---|---|
| `interfaces/sso/mesh_authz.go` | Envoy ext_authz HTTP check per request | No network policy generation, no integration with K8s NetworkPolicy API |
| `infrastructure/extauthz/` | Envoy ext_authz gRPC service | No integration with network policy stores (e.g., Tigera, Cilium, Calico) |
| `platform/netpolicy/` | Network policy classifier + store | No identity-based policy conditions (only protocol/port/CIDR matching) |
| `shared/core/types.go` | `Client.NetworkPolicy` | Policy is static, not dynamically derived from identity attributes |
| `domains/conditionalaccess/` | Conditional access engine for `/auth/login` | No network-level PEP, no integration with SDN controllers |

### Scope

| Deliverable | Description | Effort |
|---|---|---|
| **1. Identity-aware network policy data model** | Extend `platform/netpolicy/types.go` with `IdentitySelector` (SPIFFE IDs, OAuth scopes, roles, tenant). `NetworkPolicyRule.Conditions` gains `Identity` field. | 2 days |
| **2. K8s NetworkPolicy generator** | `platform/netpolicy/k8sgen/` — translates internal identity-aware policies to K8s `NetworkPolicy` resources. Supports `podSelector` based on SPIFFE ID annotations. | 3 days |
| **3. Cloud security group adapter** | `platform/netpolicy/cloudsg/` — translates identity policies to cloud security group rules (AWS `SecurityGroup`, GCP `FirewallRule`). Identity expressed as tag/label. | 3 days |
| **4. Dynamic policy enforcement point** | Extend the existing Envoy ext_authz to return dynamic upstream clusters / RBAC metadata. Envoy's `CheckResponse` gains `dynamic_metadata` for the downstream proxy to enforce network-level RBAC. | 3 days |
| **5. Identity-driven session termination** | When a user is suspended/revoked, publish a `KindIdentityNetworkBlock` event over `cluster.Bus`. Network policy agents consume and update firewall rules/NFTables/cloud SGs. | 2 days |
| **6. Admin governance view** | `GET /api/v1/admin/network-policies` — list identity-aware policies with their current enforcement state; `GET /api/v1/admin/network-policies/:id/status` — show sync status to each enforcement point. | 2 days |

**Total:** ~15 days for a first cut generating K8s NetworkPolicy + cloud SGs.

### Edge Cases

| Edge case | Handling strategy |
|---|---|
| Network policy agent is unavailable | Fail-open: no network-level enforcement (application-level auth still protects); emit `network_policy_sync_failed` alert |
| Identity attribute changes (e.g., user role changes from admin to viewer) | Policy change triggers `KindIdentityNetworkBlock` — outdated network allow rules are revoked within the policy refresh interval |
| Coarse-grained cloud SG limits (AWS: 60 inbound rules per SG) | Aggregate identities into groups; use tag-based rules where possible; emit warning when approaching limits |
| Network-level vs. application-level authorization mismatch | Network policy is a FIRST LINE of defense, not a replacement for application auth; network allow does not guarantee application allow |
| SPIFFE identity changes (workload restart → new SVID) | Network policies key on SPIFFE ID trust domain + path, not on individual SVID; restart does not require policy update |
| Multi-cluster / multi-cloud network policy | Each cluster/cloud manages its own policy enforcement; identity is the unifying concept across enforcement points |

---

## Direction 5: Identity-Driven Observability & Federated Audit Aggregation

> **Cross-validation:** Zero matches in ALL 30+ `docs/requirements/*.md` for:  
> `identity.observability`, `identity.telemetry`, `federated.audit`, `cross.cluster.audit`,  
> `audit.aggregat`, `global.audit`, `identity.driven.observability`, `observability.identity`.  
> **Code evidence:** The project has rich per-replica observability (metrics/tracing/audit)  
> but zero cross-replica audit aggregation, zero identity-centered observability views,  
> and zero integration with external SIEM orchestration beyond format-level sinks.

### Why Now

The project's observability infrastructure is comprehensive within a single replica: Prometheus metrics (80+), OpenTelemetry tracing, structured audit with hash-chain integrity, and multiple export formats (CEF/OCSF/Syslog/Kafka/Webhook). However, **there is no identity-centered observability plane**:

| Observability dimension | Current state | Gap |
|---|---|---|
| **Cross-replica audit** | Each replica writes to its own audit sink | No federated audit query across replicas/regions |
| **Identity-centered telemetry** | Metrics are operation-focused (requests, latency, errors) | No identity-focused views (e.g., "which users are failing login most?", "which clients have the highest token issuance rate?") |
| **External SIEM orchestration** | Format-level sinks (CEF, OCSF, syslog) | No automated SIEM alert feeding, no incident creation, no SOAR integration |
| **End-to-end identity flow tracing** | W3C trace context across requests | No identity-flow-specific trace visualization (login → token mint → API call → SCIM provision) |
| **Cross-region observability** | Each region independently monitored | No unified "global identity health" view |

### Code-level Evidence

| Location | What exists | What's missing |
|---|---|---|
| `platform/audit/` | Per-replica audit recording + hash chain | No cross-replica audit query or aggregation |
| `platform/metrics/` | Per-process Prometheus metrics | No identity-dimensioned metrics (by user, by client, by tenant — bounded cardinality concerns addressed below) |
| `platform/tracing/` | W3C trace context + span helpers | No identity-flow-specific span attributes or visualization |
| `platform/cluster/` | Cross-replica bus (etcd, MQTT, memory) | Bus is for control messages, not audit aggregation |
| `platform/lifecycle/dr/` | DR framework for snapshot replication | No audit replication or cross-region query |
| `interfaces/admin/` | Admin API for single-replica query | No cross-replica/region query endpoint |

### Scope

| Deliverable | Description | Effort |
|---|---|---|
| **1. Identity-dimensioned metrics with bounded cardinality** | Add identity dimensions to key metrics where cardinality is bounded: `sso_active_sessions{tenant_id}` (cardinality = tenant count), `sso_client_token_rate{client_id}` (cardinality = client count, with a top-N+other bucket). | 3 days |
| **2. Audit event federation** | `platform/audit/federation/` — lightweight audit event replication across replicas via `cluster.Bus`. Each replica broadcasts its audit events; peers store them locally (bounded TTL, fail-open). Enables `GET /api/v1/admin/audit/events` to return events from ALL replicas. | 5 days |
| **3. Identity flow trace visualization** | Extend OpenTelemetry span attributes with identity metadata: `enduser.id`, `enduser.role`, `enduser.scope`, `authn.method`, `token.type`. This enables any OTLP-compatible backend (Jaeger, Grafana Tempo, Datadog) to trace identity flows. | 2 days |
| **4. Automated SIEM alert feeding** | `platform/audit/siem/` — a SIEM alert feeder that evaluates audit events against configurable rules (`audit.siem_alerts[]`) and pushes alerts to a webhook/Slack/PagerDuty. Rules: `event_type=token_revoked AND metadata.reason=compromise`, `rate(login_failure) > threshold in window`. Distinct from the format sinks (CEF/OCSF) — this is about ALERTING, not formatting. | 4 days |
| **5. Cross-region observability dashboard** | Grafana dashboard + Loki log aggregation reference configuration for multi-region deployment. Cross-region trace correlation via `trace_id`. | 2 days |
| **6. Admin identity observability view** | `GET /api/v1/admin/observability/identity-health` — summary view: login success rate per tenant, top-failing users, top-active clients, anomaly findings per identity, cross-region latency distribution. | 3 days |

**Total:** ~19 days for a first cut.

### Edge Cases

| Edge case | Handling strategy |
|---|---|
| Audit event volume across replicas exceeds bus capacity | Federation is best-effort, fail-open; per-replica audit remains the source of truth; federation is a convenience view |
| Identity-dimensioned metrics have unbounded cardinality (e.g., user IDs) | NEVER add per-user labels; use tenant/client/country dimensions which are bounded; per-user telemetry goes through audit events, not metrics |
| Cross-region trace correlation requires consistent trace ID propagation | Already implemented — W3C `traceparent` is propagated; cross-region correlation works when the caller carries the same trace context |
| SIEM alert rule evaluation lag across replicas | Rules are evaluated per-replica; cross-replica state is NOT required for alerting (each replica alerts independently) |
| GDPR/Privacy — identity telemetry contains PII | Audit events carry subject IDs (PII-adjacent) but metrics are aggregated; trace spans use opaque identifiers; SIEM alerts include only metadata, never tokens or secrets |
| Federation adds latency to audit write path | Federation is ASYNC (broadcast on `cluster.Bus` after local write); the local audit write path latency is unchanged |

---

## Summary: Priority & Sequencing

| Direction | Value | Effort | Risk | Dependencies | Sequencing |
|---|---|---|---|---|---|
| **1. Principal Propagation** | High — closes a governance gap across all protocols | ~9 days | Low — additive, fail-open | None (new SPI) | **P0: Do first.** Foundation direction that other directions consume. |
| **2. Machine Identity Lifecycle** | High — required for enterprise adoption (SOC 2, ISO 27001) | ~15 days | Medium — new data model + lifecycle state machine | Direction 1 (propagation context for machine→human delegation) | **P1: Do after direction 1.** |
| **3. Cloud IAM Federation** | High — unique differentiator in IAM market | ~20 days | Medium — depends on cloud API availability/rate limits | Direction 2 (machine identity lifecycle provides the identity to authorize) | **P2: Do after direction 2.** |
| **4. Identity-Aware Networking** | Medium-High — extends existing ext_authz to network level | ~15 days | Low-Medium — additive, uses existing `platform/netpolicy` | Direction 1 (identity attributes for network policy conditions) | **P2: Parallel with direction 3.** |
| **5. Identity Observability** | Medium — improves operational experience | ~19 days | Low — additive, fail-open throughout | None | **P1: Can start immediately, parallel with direction 1.** |
