# sso-server Helm Chart

Deploy the [Snaplink SSO Server](https://github.com/snaplink/sso) on Kubernetes.

> **Runtime boundary:** the chart deploys the pure API backend only. Login,
> self-service, setup, developer, and admin browser UIs are separate frontend
> deployments.
>
> **State warning:** the chart defaults currently render two replicas with
> memory-backed stores. That is suitable only for manifest evaluation and
> stateless probe testing; it is not correct for OAuth flows because state
> created on one pod is unknown to another. Use one replica for local/dev, or
> configure every enabled stateful concern on shared Redis/Postgres/etcd
> backends before running more than one replica or enabling the HPA.

## Quickstart

```bash
# Add the chart repo (when published)
# helm repo add snaplink https://charts.snaplink.dev

# Safe local/dev shape: one API replica with memory stores
helm install my-sso ./ops/deploy/helm/sso-server/ \
  --set deployment.replicas=1

# Install with production overrides
helm install my-sso ./ops/deploy/helm/sso-server/ \
  --set image.tag=v1.2.3 \
  --set deployment.replicas=3 \
  -f my-prod-values.yaml
```

## Configuration

See [values.yaml](./values.yaml) for all configurable options.

### Key Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `image.repository` | `ghcr.io/snaplink/sso-server` | Container image repository |
| `image.tag` | `latest` | Image tag (pin for production) |
| `deployment.replicas` | `2` | Render default; requires shared stores for correctness |
| `config.server.issuer` | `sso-server` | SSO issuer identifier |
| `config.server.base_url` | `http://sso-server:8080` | External base URL |
| `autoscaling.enabled` | `false` | Enable HPA |
| `pdb.enabled` | `false` | Enable PodDisruptionBudget |
| `ingress.enabled` | `false` | Create Ingress resource |

### Overlays / Environments

For environment-specific configuration, create values files:

```bash
# dev-values.yaml
image:
  tag: dev
config:
  logging:
    level: debug

# prod-values.yaml
image:
  tag: v1.2.3
deployment:
  replicas: 3
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
pdb:
  enabled: true
  minAvailable: 2
```

Apply:

```bash
helm upgrade --install sso ./ops/deploy/helm/sso-server/ -f prod-values.yaml
```

The abbreviated `prod-values.yaml` above demonstrates scheduling controls
only. It is not a complete production data configuration: add the current
`redis:`, `postgres:`, per-concern `backend:`, cluster Bus, registry, and
signing-key-registry settings documented in
[`docs/config-reference.md`](../../../../docs/config-reference.md). Enabling a
new feature that defaults to memory also requires selecting its shared backend.

## Differences from Kustomize

This Helm chart mirrors the canonical `ops/deploy/kustomize/` structure but
adds value templating, version management (Chart.yaml), and parameter
documentation (values.schema.json). Choose one approach per environment:

- **Helm** — value-driven; use for templating and ecosystem tooling. This chart
  does not itself provision Redis, Postgres, etcd, TLS, or external frontends;
  manage those separately or add reviewed dependencies in your deployment
  repository.
- **Kustomize** — patch-driven; use when you prefer pure YAML without
  a separate toolchain or have existing Kustomize CI.

## Uninstall

```bash
helm uninstall my-sso
```
