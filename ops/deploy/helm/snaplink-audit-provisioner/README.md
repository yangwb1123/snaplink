# snaplink-audit-provisioner Helm chart

Create a Secret containing only the dedicated platform-control OAuth client
secret, then install with a reviewed desired-state file:

```bash
kubectl -n snaplink-sso create secret generic snaplink-audit-provisioner \
  --from-file=client-secret=/secure/path/client-secret
helm upgrade --install audit-provisioner \
  ops/deploy/helm/snaplink-audit-provisioner \
  --namespace snaplink-sso --create-namespace \
  --set-file desiredState=ops/deploy/audit-provisioner/desired-state.example.json
```

If `desiredState` is empty, `config.existingDesiredConfigMap` must expose the
key `desired-state.json`. Never place OAuth credentials in values or desired
state. Use one replica; the controller is idempotent and 409-safe, but a single
writer gives the clearest revision and readiness signal.
