# Legacy production Kubernetes overlay

> Deprecated compatibility copy. New deployments use
> [`ops/deploy/kustomize/overlays/prod/`](../kustomize/overlays/prod/); that
> overlay wins on conflict.

Do not apply this directory as-is. Its secrets are placeholders.

Render for inspection:

```bash
kubectl kustomize ops/deploy/k8s-prod/
```

Before any production rollout:

- pin the image by digest;
- validate configuration and replace placeholder secrets with a managed secret
  source;
- externalize every enabled stateful feature to shared storage;
- keep Redis auth state on `noeviction` masters;
- configure Postgres HA, etcd-backed invalidation/registry, and a
  TLS-terminating trusted edge;
- verify `/readyz` covers Redis, Postgres, etcd, and signing-key aggregation;
  and
- deploy browser frontends separately.

The current topology and safety rationale live in
[`docs/deployment.md`](../../../docs/deployment.md).
