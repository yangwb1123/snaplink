# Snaplink Billing Helm chart

This chart installs the API-only commercial runtime independently from
`sso-server`. Billing remains loopback-only; an unprivileged TLS edge in the
same Pod owns the only Service port. PostgreSQL, TLS, catalog, machine bindings,
and Audit Governance registrations are external control-plane prerequisites.

Create the namespace and referenced objects first:

```sh
kubectl create namespace snaplink-sso
kubectl -n snaplink-sso create secret generic snaplink-billing-secrets \
  --from-literal=postgres-dsn='postgres://...' \
  --from-literal=audit-client-secret='...'
kubectl -n snaplink-sso create secret generic snaplink-billing-quota-secrets \
  --from-literal=client-secret='distinct-quota-relay-secret'
kubectl -n snaplink-sso create secret generic snaplink-billing-retention-secrets \
  --from-literal=client-secret='distinct-retention-projector-secret'
kubectl -n snaplink-sso create secret tls snaplink-billing-tls \
  --cert=./tls.crt --key=./tls.key
kubectl -n snaplink-sso create configmap snaplink-billing-catalog \
  --from-file=catalog.json=ops/product/catalog.v1.json
kubectl -n snaplink-sso create configmap snaplink-billing-bindings \
  --from-file=bindings.json=./production-source-bindings.json
```

Render, review, and install with environment-specific HTTPS URLs and immutable
image digests:

```sh
helm lint ops/deploy/helm/snaplink-billing
helm template billing ops/deploy/helm/snaplink-billing \
  --namespace snaplink-sso > billing-rendered.yaml
helm upgrade --install billing ops/deploy/helm/snaplink-billing \
  --namespace snaplink-sso --values ./billing-production-values.yaml
```

The chart cannot hash external Secrets or ConfigMaps. Set `externalRevision` to
the reviewed content digest (or another monotonic release revision) whenever
TLS, PostgreSQL/Audit secrets, catalog, or source bindings change; this updates
the Pod template and performs a controlled rollout. Without it, projected files
may change while the startup-only catalog/binding importer and nginx TLS context
remain on the old generation.

To hot-enable or drain only the precompiled Audit Governance relay, create an
external ConfigMap whose `desired.json` contains exactly
`{"revision":1,"enabled":true}`, then set
`settings.audit.runtimeConfigMap` to its name. Update it with strictly
increasing revisions; the projected volume is polled every five seconds, so a
Helm rollout is not required. Audit endpoint and credentials remain cold and
must use a normal rollout. Do not include this external ConfigMap in
`externalRevision` when only its relay desired state changes.

The chart defaults automatic renewal to off. Enabling it on every replica is
safe only because the service uses PostgreSQL leases and serializable financial
settlement; first verify wallet reconciliation, immutable renewal terms, Audit
Governance sources, and a restorable database backup. HPA and PDB defaults
assume at least three schedulable replicas and a resource metrics provider.
Import the `snaplink-billing-renewals` group from
`ops/deploy/grafana/alerts.yaml` into your Prometheus rules and scrape the
Service HTTPS `/metrics` endpoint with the deployment CA. The
`subscription_renewals` readiness check tolerates individual cycle errors and
vetoes only after 15 minutes of oldest-due or successful-cycle lag; the worker
continues processing while the Pod is withdrawn. `podAnnotations` can carry
your platform's bounded scrape-discovery annotations, but CA verification must
be configured in the Prometheus scrape/ServiceMonitor rather than disabled.

Quota projection is compiled into the independent Billing profile but is
cold-enabled by `settings.quota.enabled`. Its OAuth client and Secret are
separate from Audit Governance and payment adapters. Register
`snaplink-billing-quota-relay` with exactly
`tenant-quota:projection:write` and resource `snaplink-sso-quota`, then apply
`sso-quota-values.example.yaml` to the separately installed SSO chart together
with normal production values. Add one revisioned source record per tenant;
derive it with
`snaplink-billing audit-source-id --prefix snaplink-billing-quota --tenant <id>`.
The client ID, source prefix, resource/audience, and generated source ID must
match on both charts. Quota cursor lag appears as
`tenant_quota_projection` in Billing readiness and does not affect the
independent Audit Governance cursor.

`settings.retention.enabled` adds the second half of that atomic delivery
contract. Register its dedicated client with exactly
`audit:platform:cross_tenant audit:policy:write` and resource
`audit-governance`; never reuse either quota or event-ingest credentials. The
latest entitlement's finite `audit_retention_days` grant becomes an idempotent
Audit Governance archive policy, and the cursor is acknowledged only after
both SSO and Audit Governance accept it. The ledger remains immutable and legal
holds still override archive eligibility.
