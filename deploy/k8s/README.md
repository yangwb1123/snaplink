# Kubernetes manifests for snaplink/sso

Kustomize-based base for running `cmd/sso-server` in a cluster. Apply
directly for a quick stand-up:

```bash
kubectl apply -k deploy/k8s/
```

The namespace `snaplink-sso` is created, a 2-replica Deployment of
`snaplink/sso-server:latest` is rolled out, and a ClusterIP Service
exposes ports `http/8080` (REST + JWKS + /health) and `grpc/8081`
(Authorizer / AuditWriter / Discovery).

## Layout

```
deploy/k8s/
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
   `config/etcd` source. (Wiring the CLI flag for this is on the
   sso-server roadmap; today you can opt in by adding `etcd.New` to
   the loader chain in `cmd/sso-server/main.go`.)

All three sources are deep-merged by `config.Loader`; the last source
wins per key.

## Building the image

```bash
# From the repo root
docker build -t snaplink/sso-server:latest .
# Push to your registry; tag with sha or semver for production
docker tag snaplink/sso-server:latest <your-registry>/sso-server:v0.1.0
docker push <your-registry>/sso-server:v0.1.0
```

Then pin the image in an overlay:

```yaml
# deploy/k8s/overlays/prod/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../   # the base
images:
  - name: snaplink/sso-server
    newName: <your-registry>/sso-server
    newTag: v0.1.0
```

## What's intentionally NOT in the base

Each of these is one config decision that varies per environment, so
they're left to overlays rather than baked in:

| Concern         | Why deferred                                           |
|-----------------|--------------------------------------------------------|
| Ingress         | Controller choice (NGINX, Traefik, Istio, GKE-managed) |
| TLS termination | Cert source (cert-manager, BYO, gateway-level)         |
| HPA             | Metric source (CPU, custom, KEDA) — opinionated        |
| NetworkPolicy   | CNI feature support + cluster zero-trust posture       |
| ServiceMonitor  | Prometheus operator presence + label conventions       |
| PodDisruptionBudget | Cluster scheduler / drain SLO                      |
| ServiceAccount + RBAC | None needed yet — server reads no cluster API    |

Add them in `deploy/k8s/overlays/<env>/` next to whatever else that
environment patches.

## Quick smoke test

```bash
kubectl apply -k deploy/k8s/
kubectl -n snaplink-sso rollout status deploy/sso-server --timeout=60s
kubectl -n snaplink-sso port-forward svc/sso-server 8080:8080 &
curl -s localhost:8080/health
# expect 200 + a small JSON body
```
