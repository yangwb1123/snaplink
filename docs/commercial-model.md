# Snaplink commercial model

Snaplink separates three decisions that must not be conflated:

1. a **build profile** decides which code and dependencies are in an artifact;
2. a **tenant plan** decides entitlements and quotas for one customer tenant;
3. a **deployment topology** decides persistence, isolation, availability and
   support obligations.

A `full` binary does not grant an Enterprise subscription, and an Enterprise
subscription does not make a memory-backed deployment highly available.

## Product packaging

| Build artifact | Intended use | Commercial boundary |
|---|---|---|
| `prototype` | Evaluation and protocol experiments | No production SLA |
| `minimal` | Embeddable OAuth/OIDC SSO | Community/developer distribution |
| `full` | Complete Snaplink authentication and authorization server | Production identity runtime |
| `snaplink-billing` | Plans, subscriptions, entitlements, wallet, payment facts and usage ledger | Deploy separately or on the same private network |
| Audit Governance | Immutable governance ledger, query, retention and export | Separate service and data-retention boundary |
| Aero ID / IM / Vault | Account, notification/chat and file products | Optional resource services using Snaplink tokens and entitlements |

The Go SSO server remains API-only. `snaplink-console` and the Aero browser
applications are independently built and deployed behind the same trusted
edge when a single origin is desired.

## Recommended hosted tenant plans

Prices below are public-list starting points in USD, not constants in the
authentication kernel. The shipped catalog provides Team at $490/year and
Business at $2,990/year as separate immutable rows (about two monthly periods
free). Taxes, payment fees, SMS, egress and dedicated-region costs are separate.

| Tenant plan | Monthly list | Primary buyer | Included product boundary |
|---|---:|---|---|
| Developer | $0 | Evaluation, hobby and pre-production | Core SSO, one organization, Aero ID, basic notifications and 7-day tenant-visible audit |
| Team | $49 | Small production SaaS teams | Developer plus IM, Vault, tenant audit governance, branding and standard support |
| Business | $299 | B2B SaaS and regulated growth teams | Team plus SCIM/federation, longer audit retention, higher limits and priority support |
| Enterprise | Contract | Large, regulated or sovereign deployments | Negotiated limits, dedicated/private topology, HA/DR evidence, long retention and support SLA |

Suggested starting quotas are deliberately explicit. For resource quotas,
`soft` is the included threshold used for warnings and commercial review;
`hard` is the safety limit enforced atomically by the service that owns the
resource. An operator may publish a new plan version without changing existing
subscriptions.

| Dimension | Developer soft/hard | Team soft/hard | Business soft/hard | Enterprise |
|---|---:|---:|---:|---|
| Stored tenant users | 8,000 / 10,000 | 50,000 / 60,000 | 250,000 / 300,000 | Contract |
| OAuth clients | 2 / 3 | 20 / 25 | 80 / 100 | Contract |
| Concurrent sessions | 16,000 / 20,000 | 80,000 / 100,000 | 400,000 / 500,000 | Contract |
| Token issue rate | 16 / 20 per second | 80 / 100 per second | 400 / 500 per second | Contract |
| Notifications / month | 8,000 / 10,000 | 200,000 / 250,000 | 1.6M / 2M | Contract |
| IM messages / month | disabled | 800,000 / 1M | 8M / 10M | Contract |
| Vault storage | 0.8 / 1 GiB | 80 / 100 GiB | 0.8 / 1 TiB | Contract |
| Vault objects | 8,000 / 10,000 | 800,000 / 1M | 8M / 10M | Contract |
| Tenant-visible audit retention | 7 days | 30 days | 365 days | Up to 2,555 days by contract |

The shipped catalog only publishes a finite quota when an implementation owns
the complete decision and mutation boundary. The current control ownership is:

| Commercial contract | Runtime owner | Enforcement form |
|---|---|---|
| Users | Aero ID | Durable local gauge in the account mutation transaction |
| OAuth clients, sessions, token rate | Snaplink SSO | Versioned local quota projection; durable leases/CAS for gauges |
| Messages and notifications | Aero IM | Billing reservation/commit around the durable send mutation |
| Vault bytes and objects | Aero Vault | Durable local gauges in the object mutation transaction |
| Tenant-visible audit retention | Billing entitlement projector + Audit Governance | Latest versioned entitlement is delivered through a fenced outbox cursor to an idempotent `standard`-class archive policy; immutable/security/compliance classes and legal holds remain authoritative |
| SCIM, federation and other feature flags | Deployment operator | Licensed grant mapped to precompiled modules/configuration |

MAU, number of organizations, enterprise connections and monthly audit-event
volume are useful future pricing metrics, but are deliberately absent from the
shipped catalog until their owning services implement durable, tenant-isolated
measurement and enforcement. A quote may refer to them contractually only as
externally reconciled terms, never as runtime-enforced Snaplink quotas.

Security audit collection is never disabled by a tenant entitlement. The
`audit_governance` feature controls tenant-facing governance, export and
retention services; the platform still records security events required for
incident response.

## Self-hosted and OEM packaging

Use annual contracts because the operator, not Snaplink, controls the actual
MAU and infrastructure:

| Offer | Suggested annual starting point | Includes |
|---|---:|---|
| Community minimal | $0 | Minimal artifact, community support, no SLA |
| Production full | $12,000 | Full identity runtime, signed releases, upgrades and business-hours support |
| Enterprise suite | $36,000 | Full + Billing + Audit Governance + Aero service rights, HA/DR review and priority support |
| OEM / platform | Contract | Redistribution, tenant-volume bands and dedicated engineering/support terms |

These are packaging terms, not runtime phone-home checks. Offline/private
deployments use a signed commercial entitlement file or operator-provisioned
catalog; authentication must not call a vendor licensing service on a login
path.

## Charging and quota rules

- Subscription price, usage price and deployment/support price are separate
  line items. Do not hide infrastructure cost inside an OAuth token count.
- Subscription creation is an administrator-granted contract boundary, not a
  public purchase endpoint and not an implicit first-period debit. Complete or
  record first-period settlement before granting it. Wallet renewal pre-funds
  the next period at the current boundary; a configured trial ends at that
  first settlement boundary. Plan changes require an explicit, referenced
  adjustment when proration is desired.
- Money uses integer ISO-4217 minor units. A plan version and subscription
  period are immutable billing evidence.
- Top-ups become immutable wallet credits only after an authenticated,
  idempotent normalized provider event. Refunds and chargebacks are separate
  negative ledger entries. A provider-confirmed chargeback reversal is a
  distinct positive entry that reduces the order's refunded total and can
  restore a non-negative frozen wallet; payment credentials never enter
  Snaplink.
- Durable cumulative usage (currently messages and notifications) uses the
  usage ledger. Reservation/commit is required when work must not oversell a
  hard limit. Audit events are always collected for security and are not a
  finite metered dimension in the shipped catalog.
- Durable gauges such as Vault bytes and current users are enforced in the
  resource owner's database transaction. A remote pre-check alone is not a
  hard quota.
- Vault capacity uses `storage_bytes`/`storage_objects` as local current-value
  gauges. Its positive-only central ledger uses distinct
  `storage_*_allocated|created|reclaimed|deleted` event dimensions; those
  counters are observability evidence and never substitute for the local
  capacity gauge.
- Unknown, disabled or ambiguous machine-source bindings fail closed. Request
  bodies never choose their own tenant or source system.
- Entitlement snapshots are local, versioned projections. Login and token
  issuance never call a payment provider.
- Catalog feature flags are licensed grants, not dynamic request-path switches.
  The deployment controller may map a grant to already compiled modules and
  configuration; the SSO authentication path never calls Billing and security
  audit collection is never disabled by a commercial flag.
- A finite entitlement with `hard: 0` means no resources are allowed; it is
  not collapsed into the legacy operator-config value `0 = unlimited`.
  Snaplink's versioned quota projection carries explicit limited flags and a
  monotonic revision, rejecting same-revision equivocation and stale updates.
- Snaplink client gauges use durable resource-ID leases and generation/CAS
  absolute reconciliation. This prevents duplicate DCR retries or a stale
  multi-replica scanner from consuming/overwriting the counter twice.
- Until a versioned rate card and settlement job are configured, exceeding a
  soft limit is an alert, not an automatic wallet debit. Hard limits remain
  enforceable and operators must not advertise unimplemented overage billing.

## Market positioning snapshot

The recommended prices were calibrated on 2026-08-04 against official public
pricing: [Clerk](https://clerk.com/pricing) lists low-cost Pro and a higher
Business tier; [WorkOS](https://workos.com/pricing) makes base AuthKit usage
free and charges per enterprise connection and retained audit volume; and
[Auth0](https://auth0.com/pricing) prices higher production/security tiers by
MAU and feature set. Recheck these references before each public price change.

Snaplink's differentiation is therefore not a low per-user headline alone. It
is portable deployment, strict tenant isolation, auditable authorization,
optional private operation, and one entitlement contract shared by identity,
IM, notifications and file services.
