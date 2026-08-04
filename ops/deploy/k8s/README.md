# Legacy Kubernetes base

> Deprecated compatibility copy. New deployments use
> [`ops/deploy/kustomize/`](../kustomize/); that tree wins on conflict.

This directory contains an API-only `sso-server` base: namespace, Deployment,
Service, and a generated ConfigMap. It declares one replica with
`server.topology.mode: single`; memory-backed OAuth state is not safe to scale
horizontally.

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
