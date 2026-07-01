# Kustomize — Kubernetes Deployment Manifests

Canonical Kustomize structure for deploying the snaplink/sso server on Kubernetes.

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
# Dev (minimal overrides from base)
kubectl apply -k ops/deploy/kustomize/overlays/dev/

# Production (HA backends, HPA, PDB, zone spread)
kubectl apply -k ops/deploy/kustomize/overlays/prod/

# Quick dev stand-up (direct base)
kubectl apply -k ops/deploy/kustomize/base/
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
| Replicas | 2 (from base) | 3 |
| Backends | memory/sqlite (from base) | Redis + Postgres + etcd |
| HPA | none | CPU 70%, min 3 / max 20 |
| PDB | none | minAvailable 2 |
| Secrets | none (base ConfigMap only) | `secretGenerator` placeholder |
| Zone spread | none | `topologySpreadConstraints` |
| Graceful shutdown | default | preStop + 40s terminationGracePeriod |
| Readiness probe | default (2 failures) | tolerant (4 failures) |

## Migration from Legacy Paths

The legacy directories `ops/deploy/k8s/` (dev) and `ops/deploy/k8s-prod/` (prod)
are still present and functional but deployments should migrate to the
canonical `ops/deploy/kustomize/` structure.

- `ops/deploy/k8s/` → `ops/deploy/kustomize/base/` (identical content)
- `ops/deploy/k8s-prod/` → `ops/deploy/kustomize/overlays/prod/` (identical overlay)
