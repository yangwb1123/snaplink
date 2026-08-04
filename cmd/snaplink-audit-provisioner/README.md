# snaplink-audit-provisioner

`snaplink-audit-provisioner` is an independently deployed, create-only
controller for Audit Governance tenants, tenant-derived sources, and event
schemas. It does not carry event-relay credentials and is not part of
`sso-server` request handling.

## Security contract

Register a dedicated OAuth client with exactly this scope string:

```text
audit:platform:cross_tenant audit:policy:read audit:policy:write
```

Authorize exactly the configured Audit Governance resource. The scope is fixed
in code and cannot be widened by configuration. OAuth and control endpoints
must use HTTPS; `--allow-insecure-loopback` permits explicit loopback HTTP only.
Redirects are rejected. Supply the client secret only through
`SNAPLINK_AUDIT_PROVISIONER_CLIENT_SECRET` or a safe regular file named by
`SNAPLINK_AUDIT_PROVISIONER_CLIENT_SECRET_FILE`, never both.

## Desired state

The strict JSON manifest is limited to 1 MiB, rejects unknown fields and
trailing JSON, and must be a non-symlink regular file without group/other write
permissions. Its positive `revision` is monotonic. Sources contain a prefix,
not a caller-supplied source ID; IDs are derived with
`auditgovernance.TenantSourceID(prefix, tenant_id)`. Client allow-lists are
sorted, unique, non-empty, and exact. Every record must be active.

Reconciliation only lists and creates. Existing records must match every
desired field; a 409 is followed by GET/list and the same exact comparison.
There is no PUT, DELETE, omission-based deletion, or allow-list expansion.
Stale revisions and different content at the current revision make readiness
fail while the last successful revision remains visible. Restoring the applied
manifest or applying a higher valid revision recovers readiness.

## Operation

Build a host-native static binary with:

```bash
CGO_ENABLED=0 go build -trimpath -o bin/snaplink-audit-provisioner ./cmd/snaplink-audit-provisioner
```

The command accepts matching non-secret flags for the following environment
variables:

| Variable | Meaning |
|---|---|
| `SNAPLINK_AUDIT_PROVISIONER_MANIFEST_FILE` | Desired-state JSON path |
| `SNAPLINK_AUDIT_PROVISIONER_BASE_URL` | Audit Governance HTTPS base URL |
| `SNAPLINK_AUDIT_PROVISIONER_TOKEN_URL` | Snaplink OAuth token URL |
| `SNAPLINK_AUDIT_PROVISIONER_CLIENT_ID` | Dedicated platform-control client |
| `SNAPLINK_AUDIT_PROVISIONER_CLIENT_SECRET[_FILE]` | Exactly one secret source |
| `SNAPLINK_AUDIT_PROVISIONER_RESOURCE` | One OAuth resource |
| `SNAPLINK_AUDIT_PROVISIONER_LISTEN` | Probe/metrics address; default `:8092` |
| `SNAPLINK_AUDIT_PROVISIONER_POLL_INTERVAL` | Reload interval; default `30s` |
| `SNAPLINK_AUDIT_PROVISIONER_REQUEST_TIMEOUT` | Per-request timeout; default `5s` |
| `SNAPLINK_AUDIT_PROVISIONER_ONE_SHOT` | Reconcile once and exit |
| `SNAPLINK_AUDIT_PROVISIONER_ALLOW_INSECURE_LOOPBACK` | Local loopback HTTP only |

Continuous mode reconciles initially, periodically, and on SIGHUP. `/livez`
reports process liveness, `/readyz` reports the last reconciliation state, and
`/metrics` exposes bounded-cardinality counters and the applied revision.
SIGHUP reloads desired state only; rotate the client secret with a controlled
process/Pod restart so the startup-only credential and token cache are replaced.
One-shot exit codes are `0` success, `1` control/OAuth failure, `2` invalid
configuration or manifest, and `3` stale/conflicting desired or remote state.

Deployment examples live in `ops/deploy/audit-provisioner`,
`ops/deploy/helm/snaplink-audit-provisioner`, `ops/deploy/compose`, and
`ops/deploy/baremetal-ha/systemd`.
