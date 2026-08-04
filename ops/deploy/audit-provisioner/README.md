# Audit Governance desired-state provisioner

This overlay deploys the create-only `snaplink-audit-provisioner` separately
from `sso-server`, Audit Governance, and every event relay. It registers exact
tenant, source allow-list, and schema records. It never updates or deletes an
existing governance record.

Before rendering, replace the example tenant and client IDs in
`desired-state.example.json`, increment `revision`, and set the HTTPS endpoints
in `settings.env`. Create the dedicated secret without committing it:

```bash
kubectl -n snaplink-sso create secret generic snaplink-audit-provisioner \
  --from-file=client-secret=/secure/path/client-secret
kubectl apply -k ops/deploy/audit-provisioner
```

The OAuth client is a platform-control client, not a relay client. Grant exactly
`audit:platform:cross_tenant audit:policy:read audit:policy:write` for the one
configured `audit-governance` resource. `/readyz` becomes non-ready on stale
revisions, same-revision drift, remote drift, or control-plane failure while
retaining the last successfully applied revision.

The Pod reads projected volumes through Kubernetes' `..data` directory so the
final path component is a regular file (the loader rejects a final symlink)
while ConfigMap/Secret atomic generation switches remain observable.

The Billing schemas enumerate every event emitted by the current outbox relay.
Aero ID uses `aero.id.audit-fact`/`personal`; Aero IM uses
`aero.im.security`/`confidential`; Aero Vault uses
`aero.vault.security`/`confidential`. Enable each source and schema in the same
rollout as its relay credential and keep the fixed schema/event pair exact.
