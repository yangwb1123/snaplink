# Kustomize — Kubernetes Deployment Manifests

Canonical Kustomize structure for deploying the snaplink/sso server on Kubernetes.

This tree deploys the pure HTTP/gRPC API backend. Hosted login, self-service,
setup, developer, and admin browser UIs are separate frontend deployments.

> **State requirement:** more than one API replica is correct only when every
> enabled stateful concern uses shared Redis/Postgres/etcd backends. The
> base/dev shape uses one memory-backed replica. The production
> overlay is a reference that still requires real external services, secrets,
> certificates, and per-feature backend review.

## Layout

```
kustomize/
├── README.md               ← you are here
├── base/                   ← shared resources (deployment, service, namespace, config)
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── deployment.yaml
│   ├── service.yaml
│   └── config.yaml
└── overlays/
    ├── dev/                ← dev overlay (minimal changes from base)
    │   └── kustomization.yaml
    └── prod/               ← production overlay (shared backends, HPA, PDB, secrets)
        ├── kustomization.yaml
        ├── config.yaml         ← replaces base config with HA backends
        ├── hpa.yaml
        ├── pdb.yaml
        └── patch-deployment.yaml
```

## Usage

```bash
# Dev: one memory-backed replica
kubectl kustomize ops/deploy/kustomize/overlays/dev/

# Production: apply only after the external services/secrets/hook review above
kubectl apply -k ops/deploy/kustomize/overlays/prod/

# Base: one memory-backed replica
kubectl kustomize ops/deploy/kustomize/base/

# Kubernetes 1.30+: enforce the same HA contract at admission and on /scale
kubectl apply -f ops/deploy/k8s-admission/topology-policy.yaml
```

## Makefile Targets

```bash
make k8s-render   # Render all overlays to flat YAML under bin/k8s-rendered/
make k8s-diff     # Diff rendered output between dev and prod overlays
```

## Environment Differences

| Aspect | Dev (`overlays/dev`) | Prod (`overlays/prod`) |
|--------|----------------------|------------------------|
| Image tag | `dev` | `prod` (pin to digest in real deploys) |
| Replicas | 1 (from base) | 3 |
| Backends | memory (not HA-safe) | Redis + Postgres + etcd for configured concerns |
| HPA | none | CPU 70%, min 3 / max 20 |
| PDB | none | minAvailable 2 |
| Secrets | none (base ConfigMap only) | `secretGenerator` placeholder |
| Zone spread | none | `topologySpreadConstraints` |
| Graceful shutdown | default | 40s terminationGracePeriod |
| Readiness probe | default (2 failures) | tolerant (4 failures) |

The native admission policy is optional on clusters older than Kubernetes
1.30. On supported clusters it rejects unsafe multi-replica Deployments and
unapproved scale updates. The process startup check remains authoritative on
every Kubernetes version.

## Migration from Legacy Paths

The legacy directories `ops/deploy/k8s/` (dev) and `ops/deploy/k8s-prod/` (prod)
are still present and functional but deployments should migrate to the
canonical `ops/deploy/kustomize/` structure.

- `ops/deploy/k8s/` → `ops/deploy/kustomize/base/`
- `ops/deploy/k8s-prod/` → `ops/deploy/kustomize/overlays/prod/`

The legacy directories are copies, not aliases; do not assume future
byte-for-byte parity.
