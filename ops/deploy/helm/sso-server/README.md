# sso-server Helm Chart

Deploy the [Snaplink SSO Server](https://github.com/snaplink/sso) on Kubernetes.

## Quickstart

```bash
# Add the chart repo (when published)
# helm repo add snaplink https://charts.snaplink.dev

# Install with defaults (single-instance, memory stores)
helm install my-sso ./ops/deploy/helm/sso-server/

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
| `deployment.replicas` | `2` | Number of replicas |
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

## Differences from Kustomize

This Helm chart mirrors the canonical `ops/deploy/kustomize/` structure but
adds value templating, version management (Chart.yaml), and parameter
documentation (values.schema.json). Choose one approach per environment:

- **Helm** — value-driven; use when you need templating, dependency
  management (subcharts for Redis/Postgres/etcd), or ecosystem tooling.
- **Kustomize** — patch-driven; use when you prefer pure YAML without
  a separate toolchain or have existing Kustomize CI.

## Uninstall

```bash
helm uninstall my-sso
```
