# Kubernetes manifests for snaplink/sso

> **⚠️ DEPRECATED**: This directory is maintained for backward compatibility.
> New deployments should use the canonical structure at
> **[ops/deploy/kustomize/](../kustomize/)** which provides a cleaner
> `base/` + `overlays/{dev,prod}/` layout with explicit environment differences.
>
> This directory (`ops/deploy/k8s/`) is identical to `ops/deploy/kustomize/base/`.

Kustomize-based base for running `cmd/sso-server` in a cluster. Apply
directly for a quick stand-up:

```bash
kubectl apply -k ops/deploy/k8s/
```

The namespace `snaplink-sso` is created, a 2-replica Deployment of
`snaplink/sso-server:latest` is rolled out, and a ClusterIP Service
exposes ports `http/8080` (REST + JWKS + /health) and `grpc/8081`
(Authorizer / AuditWriter / Discovery).

## Layout

```
ops/deploy/k8s/
├── kustomization.yaml   # base entrypoint
├── namespace.yaml
├── deployment.yaml      # securityContext + probes + resource floor
├── service.yaml         # ClusterIP, http + grpc ports
├── config.yaml          # baked into sso-server-config via configMapGenerator
└── README.md            # you are here
```

## Configuring the server

Three layers, in priority order (lowest first):

1. **`config.yaml`** — the file in this directory. Kustomize wraps it
   in a hashed ConfigMap (`sso-server-config-<hash>`) and mounts it at
   `/etc/sso/config.yaml`. Editing this file changes the hash, which
   triggers a rolling restart on the next `kubectl apply -k`.

2. **Environment variables on the pod** — any `SSO_<UPPER>__<UPPER>...`
   env var overrides the matching key in the file. See
   `deployment.yaml`'s commented `env:` block. This is the 12-factor
   override path you'd use to bump the log level in staging without
   editing the ConfigMap.

3. **etcd** — if your operator workflow stores live config in etcd,
   point the sso-server at `etcd://<endpoints>/<prefix>` via the
   `config/etcd` source.

All three sources are deep-merged by `config.Loader`; the last source
wins per key.

## Quick smoke test

```bash
kubectl apply -k ops/deploy/k8s/
kubectl -n snaplink-sso rollout status deploy/sso-server --timeout=60s
kubectl -n snaplink-sso port-forward svc/sso-server 8080:8080 &
curl -s localhost:8080/health
# expect 200 + a small JSON body
```
