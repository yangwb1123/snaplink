# Legacy Kubernetes base

> Deprecated compatibility copy. New deployments use
> [`ops/deploy/kustomize/`](../kustomize/); that tree wins on conflict.

This directory contains an API-only `sso-server` base: namespace, Deployment,
Service, and a generated ConfigMap. It currently declares two replicas with
memory-backed OAuth state, which is unsafe for authorization codes, sessions,
refresh families, PAR, device/CIBA state, replay protection, and MFA
challenges.

Use it for render inspection only:

```bash
kubectl kustomize ops/deploy/k8s/
```

For an isolated development deployment, use the canonical dev overlay and one
replica. For multiple replicas, use the production overlay only after every
enabled stateful feature selects shared Redis/Postgres/etcd-backed storage.

Configuration precedence and supported keys are documented in
[`docs/config-reference.md`](../../../docs/config-reference.md); do not copy
that reference into this legacy directory.
