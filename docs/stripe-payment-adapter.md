# Stripe payment adapter

`snaplink-stripe-adapter` is an optional, independently scalable process that
keeps Stripe-specific credentials, signatures, payloads, and checkout calls out
of the Snaplink authentication kernel and `snaplink-billing`. It provides:

- `POST /api/v1/checkout/sessions`, protected by an exact Snaplink audience and
  either the machine `billing:checkout:create` or user `admin:write` scope;
- `POST /webhooks/stripe`, protected by Stripe's raw-body HMAC signature;
- `/livez`, dependency-aware `/readyz`, and bounded-cardinality `/metrics`.

The Go SSO server remains API-only and never hosts Console assets. Console calls
the checkout endpoint through its normal TLS edge; Stripe calls only the webhook
endpoint. The adapter calls Billing through least-privilege client credentials.

## Trust and authorization flow

```text
Console client token ──JWT/JWKS + audience + scope──> Stripe adapter
       │                                                   │
       │ client_id maps to one tenant                      │ read scope
       │                                                   ▼
       └──────── no amount/currency in request ─────> snaplink-billing order
                                                           │
                                                           ▼
                                                    Stripe Checkout

Stripe raw webhook ──HMAC + ±5 minute window──> durable minimal-fact inbox
                                                           │ retry/lease
                                                           ▼
                                      snaplink-billing normalized payment fact
                                                           │
                                                           ▼
                                              Audit Governance durable relay
```

For machine tokens, `sub` must equal `client_id`, the desired-state binding file
maps that client to exactly one tenant, and an optional request `tenant_id` must
match. User-shaped tokens (including tokens without `client_id`) require exact
`admin:write`, an explicit `tenant_id`, and an existing server-owned tenant
binding. Each tenant has a dedicated Billing OAuth client. Billing separately
binds that client to the same tenant and `payment:stripe` source with no allowed
dimensions. Both checks must agree. No caller can choose provider, amount, or
currency.

Checkout accepts `tenant_id`, `order_id`, `success_url`, and `cancel_url`, with
the conditional tenant rules above. The adapter
reads a pending Stripe order from Billing using
`billing:payment:order:read`, then sends the authoritative amount/currency and
server-owned tenant/order metadata to Stripe. The returned session is stored
under a stable idempotency key. Repeating the exact request returns the stored
session; changing its return URLs or trusted order facts produces a conflict.
For the same immutable request, an expired persisted session is atomically
advanced to a new checkout generation and Stripe idempotency key. Concurrent
replicas converge on that key, stale generation responses are fenced, and the
adapter returns the newly persisted session without ever returning the old URL.

The relay obtains a separate `billing:payment:write` token. Raw Stripe JSON,
signature headers, API keys, OAuth secrets, PAN, and card data are never stored
or forwarded. Only event id/type, SHA-256 payload digest, provider object ids,
amount/currency, occurrence time, and trusted mapping/fencing fields are durable.
Billing records the resulting financial mutation and relays its audit outbox to
Snaplink Audit Governance.

## Webhook and replay behavior

The adapter accepts only these Stripe event types:

| Stripe event | Billing fact |
|---|---|
| `payment_intent.succeeded` | `captured` |
| `refund.created`, `refund.updated` with `status=succeeded` | `refunded` |
| `charge.dispute.funds_withdrawn` | `chargeback` |
| `charge.dispute.funds_reinstated` | `chargeback_reversed` |

`payment_intent.payment_failed`, non-succeeded refunds, and signed unsupported
events return `204` because they do not prove a final financial mutation.
Invalid signatures, configured live/test mode, account, or webhook API-version
mismatches, and malformed supported events return 4xx. A valid supported event
is projected and inserted before 2xx. The same event id and digest is an
idempotent replay; the same id with a different digest is a 409 security
conflict. A separate unique normalized effect key (`type:provider_object_id`)
prevents two distinct Stripe Event objects from applying the same provider
effect while retaining both event receipts.

Delivery is at least once. PostgreSQL workers use `FOR UPDATE SKIP LOCKED`, a
unique owner, generation fencing, and expiring leases. Temporary dependency or
ordering failures retry indefinitely with deterministic bounded backoff.
Immutable mapping/fact conflicts are quarantined so one poison event cannot
consume every worker cycle; quarantine is observable and preserved for operator
reconciliation rather than deleted. Schema migration is serialized across
replicas with a transaction-scoped PostgreSQL advisory lock.
During the v1-to-v2 migration, legacy `payment_intent.payment_failed` and
`charge.dispute.created` projections are quarantined. Old `refund.created` rows
also lacked the status needed to prove success, so they are retained with their
receipts under `legacy_refund_status_unverified` for reconciliation. Their
suffixed historical effect keys do not block a later authoritative succeeded
refund or funds-withdrawn event.
Refunds or disputes that arrive before their payment intent mapping are parked,
then resolve after the capture event establishes that mapping. Before every
delivery the adapter re-reads Billing and cross-checks tenant, order, provider id,
currency, amount, and legal state. Billing's event-id idempotency makes an
acknowledgement loss safe.

## Configuration and secret handling

Start from
[`config.example.env`](../cmd/snaplink-stripe-adapter/config.example.env) and
[`bindings.example.json`](../cmd/snaplink-stripe-adapter/bindings.example.json).
The binding file is strict JSON, at most 2 MiB, a regular file (not a symlink),
and must not be group/world writable. It contains only environment-variable
names for Billing secrets; secret values remain in the process environment or
the orchestrator secret store.

All upstream URLs require HTTPS. Plain HTTP is accepted only when
`SNAPLINK_STRIPE_ALLOW_INSECURE_LOOPBACK=true` and every such URL is loopback.
A non-loopback listener requires the built-in TLS certificate/key pair. The
outbound HTTP client has a hard timeout and refuses redirects. Checkout return
URLs must match an exact configured origin, cannot contain userinfo or control
characters, and require HTTPS outside explicit loopback development.

Webhook secret rotation is overlap-based: configure old and new `whsec` values
as a comma-separated list, update the Stripe endpoint, observe traffic using the
new secret, then remove the old value. The verifier evaluates all presented
`v1` signatures against all configured secrets and enforces a bidirectional
five-minute timestamp window. Keep hosts NTP synchronized.

`SNAPLINK_STRIPE_LIVE_MODE` is mandatory and the API key prefix must match that
mode (`sk_test_`/`rk_test_` or `sk_live_`/`rk_live_`).
`SNAPLINK_STRIPE_ACCOUNT` is exactly `platform` or one `acct_*` identifier. A
connected-account value is also sent as the `Stripe-Account` header when the
adapter creates Checkout Sessions, so the API operation and accepted webhook
events are bound to the same Stripe account. The
`SNAPLINK_STRIPE_WEBHOOK_API_VERSION` must exactly match each received Event.
`SNAPLINK_STRIPE_HANDLER_TIMEOUT` bounds checkout and webhook database/upstream
work and must exceed two outbound HTTP timeouts plus one second.

## Build and deployment

Build the root-module binary or the distroless image target:

```sh
go build ./cmd/snaplink-stripe-adapter
docker build --target snaplink-stripe-adapter -t snaplink/stripe-adapter:prod .
```

Kubernetes assets live under
[`ops/deploy/billing/stripe-adapter`](../ops/deploy/billing/stripe-adapter/README.md).
They use three replicas, topology spreading, a disruption budget, autoscaling,
read-only mounts, non-root execution, and built-in TLS. All replicas share one
PostgreSQL database. Scale HTTP and relay capacity together; tune batch size and
delivery concurrency so aggregate Billing/Stripe traffic stays within their
limits. Readiness fails only when PostgreSQL or JWKS is unavailable. A transient
or out-of-order inbox backlog therefore does not evict every healthy replica.
`/metrics` publishes pending/quarantined gauges, a backlog-threshold signal, and
fixed-name checkout/webhook/relay counters without tenant, event, or order
labels; alerting handles backlog degradation independently from traffic routing.

## Disaster recovery and operations

The adapter is stateless except for PostgreSQL. Protect that database with PITR,
encrypted cross-zone backups, and restore drills. The minimum recoverable set is
all three adapter tables (checkout mappings, event inbox, and event receipts)
plus Billing's commerce/ledger/outbox tables; use one
consistent recovery point when databases share a cluster. If they are separate,
restore the adapter first to a point no newer than Billing, then allow idempotent
provider/Billing replay to converge.

Recovery procedure:

1. Stop public webhook/checkout traffic or route it to the surviving region.
2. Restore PostgreSQL and the immutable binding/TLS/secret configuration.
3. Start one adapter replica and require `/readyz` success.
4. Confirm `/metrics` pending count decreases, quarantine is reconciled, and
   Billing order totals match.
5. Scale out, restore Stripe webhook delivery, then restore checkout traffic.

Do not delete undelivered inbox rows during recovery. Stripe event redelivery and
Billing event idempotency are the reconciliation tools. If a lease owner was lost,
its claims become eligible after `SNAPLINK_STRIPE_CLAIM_LEASE`. Rotate the Stripe
API key, webhook secret, and Billing OAuth secrets after suspected compromise;
changing bindings must preserve the same tenant/client ownership on both sides.

Operational logs contain event ids and bounded error categories, never request
bodies or secrets. Alert on readiness failure, backlog threshold, quarantine,
`mapping_conflict`, signature failures at the edge, PostgreSQL saturation, and
Billing 401/403 responses. Retain normalized inbox/mapping rows according to the
financial and audit retention policy only after deliveries are acknowledged and
the Billing/Audit Governance records have passed backup verification.
