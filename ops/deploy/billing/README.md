# Snaplink Billing Kubernetes deployment

This bundle deploys `snaplink-billing` as an independently scalable API-only
service. Every Pod contains a loopback-only billing process and a trusted TLS
edge. The Service selects only the TLS port; plaintext port 8090 is never
reachable through the Pod IP or Service.

Before applying it, pin both images to immutable digests and replace the public
URLs in `settings.env`. Create the required runtime objects without committing
their values:

```sh
kubectl -n snaplink-sso create secret generic snaplink-billing-secrets \
  --from-literal=postgres-dsn='postgres://...' \
  --from-literal=audit-client-secret='...' \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n snaplink-sso create secret generic snaplink-billing-quota-secrets \
  --from-literal=client-secret='distinct-quota-relay-secret' \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n snaplink-sso create secret generic snaplink-billing-retention-secrets \
  --from-literal=client-secret='distinct-retention-projector-secret' \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n snaplink-sso create secret tls snaplink-billing-tls \
  --cert=./tls.crt --key=./tls.key \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n snaplink-sso create configmap snaplink-billing-catalog \
  --from-file=catalog.json=ops/product/catalog.v1.json \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n snaplink-sso create configmap snaplink-billing-bindings \
  --from-file=bindings.json=./production-source-bindings.json \
  --dry-run=client -o yaml | kubectl apply -f -
```

The namespace must already exist (the SSO base creates `snaplink-sso`). Render
and inspect the result before applying:

```sh
kubectl kustomize ops/deploy/billing
kubectl apply -k ops/deploy/billing
```

Use a managed or operator-owned PostgreSQL cluster with synchronous multi-AZ
replication and PITR. Every replica shares the same database; outbox and renewal
leases make background work safe under horizontal scaling. The HPA requires a
resource metrics provider. The PDB protects voluntary disruption, while zone
and node spread reduce correlated replica loss; neither substitutes for a
tested database restore and reconciliation drill.

Automatic subscription settlement remains disabled in the committed
`settings.env`. Review the immutable catalog, existing subscription term
snapshots, wallet balances, Audit Governance tenant-source registrations and a
database backup before changing `SNAPLINK_BILLING_RENEWALS_ENABLED` to `true`.
All replicas may run the worker: PostgreSQL leases and serializable settlement
prevent double charging. Leave `SNAPLINK_BILLING_RENEWALS_OWNER` unset to use
the unique Pod hostname/PID identity, or inject a unique Pod name explicitly.
Configure the cluster Prometheus to scrape HTTPS `/metrics` on the
`snaplink-billing` Service with the private edge CA, and import the
`snaplink-billing-renewals` group from `ops/deploy/grafana/alerts.yaml`.
Single-cycle errors warn without evicting Pods. If
`subscription_renewals: error` appears, inspect due count, oldest age,
observation timestamp and PostgreSQL before changing worker configuration; the
15-minute fence withdraws API traffic but intentionally leaves settlement
running so recovery can clear the durable backlog.

The fixed-name `snaplink-billing-audit-runtime` ConfigMap controls only the
precompiled Audit Governance relay. Publish a strictly higher `revision` with
`enabled: false` or `true`; kubelet's projected-volume update plus the Billing
five-second poll applies it without restarting Pods. Update all replicas from
one ConfigMap and wait until every `/readyz` reports `audit_relay_module: ok`.
Never add endpoints or credentials to this file. Catalog, source bindings,
OAuth credentials and TLS remain restart/rollout changes.

Quota projection is a separate, cold-configured relay and never reuses the
Audit Governance or payment-adapter credential. Before Billing starts, register
OAuth client `snaplink-billing-quota-relay` in SSO with exactly
`tenant-quota:projection:write` and allowed resource `snaplink-sso-quota`, then
enable the SSO PostgreSQL quota backend and projection ingress. For the
committed `tenant-example` sample, the exact receiver record is:

```yaml
tenant:
  enabled: true
  resource_quota:
    backend: postgres
    projection_ingress:
      enabled: true
      audience: snaplink-sso-quota
      sources:
        - id: billing-quota-tenant-example
          client_id: snaplink-billing-quota-relay
          tenant_id: tenant-example
          source_system: snaplink-billing-quota.YJnQgZ29gnt3CF3TKG-8HZ1HLwSmNkYR9MmjuWPZfNg
          enabled: true
          revision: 1
```

Generate one source per tenant with
`snaplink-billing audit-source-id --prefix snaplink-billing-quota --tenant <id>`.
The Billing client ID, resource, scope, prefix, and SSO source records must be
deployed in one reviewed release. Every Pod gets its own quota lease owner from
its name; PostgreSQL fencing makes concurrent replicas safe. `/readyz` reports
`tenant_quota_projection: error` only after the oldest independent quota cursor
exceeds `SNAPLINK_BILLING_QUOTA_MAX_LAG`; disabling or losing SSO never consumes
the Audit Governance cursor.

The same leased entitlement cursor also projects `audit_retention_days` to
Audit Governance. Register `snaplink-billing-retention-projector` as a third,
dedicated client with exactly `audit:platform:cross_tenant audit:policy:write`
and resource `audit-governance`; it must not reuse the event-ingest or SSO quota
client ID or secret. For each latest entitlement Billing writes an idempotent
tenant policy whose archive window is the catalog's finite 7/30/365-day grant.
The worker acknowledges the cursor only after both SSO quota and retention
policy succeed, so `/readyz` applies the same maximum-lag fence to both sinks.
Audit Governance's immutable ledger and legal holds remain authoritative; this
policy changes archive eligibility and never deletes ledger records.

The committed edge image tag is only a portable template default. Production
release automation must replace both image references with reviewed digests.
Catalog and binding changes use immutable/versioned product data and the
revision rules documented by `cmd/snaplink-billing`; update their ConfigMaps and
perform a rolling restart rather than editing files inside a Pod. The same
restart requirement applies after referenced Secret or TLS certificate
rotation: the startup importer and nginx TLS context do not reload those
external objects in place.
