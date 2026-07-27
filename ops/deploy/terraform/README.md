# Terraform — AWS infrastructure reference for SSO Server

Reference Terraform for the AWS substrate used by a SnapLink SSO deployment.
It provisions a VPC, EKS, RDS PostgreSQL, and an ElastiCache Redis replication
group. It does **not** deploy `sso-server`, etcd, an ingress/load balancer,
certificates, External Secrets, PgBouncer, DNS, product frontends, or the
production Kustomize overlay.

> Treat this as a starting scaffold, not a production-ready stack. Run
> `terraform validate`/`plan` against the target AWS account, review provider
> and Kubernetes versions, fix the application/backend integration described
> below, and perform a security/cost review before apply.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ VPC (10.0.0.0/16)                                           │
│                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │ Public AZ-1 │    │ Public AZ-2 │    │ Public AZ-3 │     │
│  │ 10.0.1.0/24 │    │ 10.0.2.0/24 │    │ 10.0.3.0/24 │     │
│  │  [NAT GW]   │    │  [NAT GW]   │    │  [NAT GW]   │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │Private AZ-1 │    │Private AZ-2 │    │Private AZ-3 │     │
│  │ 10.0.11.0/24│    │ 10.0.12.0/24│    │ 10.0.13.0/24│     │
│  │             │    │             │    │             │       │
│  │ ┌─────────┐ │    │ ┌─────────┐ │    │ ┌─────────┐ │     │
│  │ │  EKS    │ │    │ │  EKS    │ │    │ │  EKS    │ │     │
│  │ │  Node   │ │    │ │  Node   │ │    │ │  Node   │ │     │
│  │ └─────────┘ │    │ └─────────┘ │    │ └─────────┘ │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  RDS PostgreSQL DB instance (Multi-AZ in prod)       │  │
│  │  ┌──────────┐          ┌──────────┐                 │  │
│  │  │ Primary  │          │ Standby  │                 │  │
│  │  └──────────┘          └──────────┘                 │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  ElastiCache Redis replication group                │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐          │  │
│  │  │ Primary  │  │ Replica  │  │ Replica  │ (prod)   │  │
│  │  └──────────┘  └──────────┘  └──────────┘          │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Terraform >= 1.5.0
- AWS CLI configured with appropriate credentials
- AWS account with permissions for VPC, EKS, RDS, ElastiCache
- `kubectl` and Kustomize for the separate application deployment

## Quick Start

### Development Environment

```bash
cd ops/deploy/terraform
terraform init
terraform plan -var-file="environments/dev/terraform.tfvars"
terraform apply -var-file="environments/dev/terraform.tfvars"
```

### Production Environment

```bash
cd ops/deploy/terraform

# Set a strong Redis AUTH token (the Terraform does not generate one)
export TF_VAR_redis_auth_token="your-secure-password-here"

terraform init
terraform plan -var-file="environments/prod/terraform.tfvars"
terraform apply -var-file="environments/prod/terraform.tfvars"
```

## Post-Deployment

After Terraform completes, configure kubectl:

```bash
# Get cluster credentials
aws eks update-kubeconfig --region us-east-1 --name sso-server

# Verify connection
kubectl get nodes

# From the repository root, render/review the canonical manifests:
kubectl kustomize ops/deploy/kustomize/overlays/dev/
kubectl kustomize ops/deploy/kustomize/overlays/prod/
```

Do not apply the production overlay unchanged to this Terraform output. The
overlay assumes Redis Cluster seed endpoints, external etcd, PgBouncer, Redis
CA material, and pre-created secrets; this Terraform currently supplies a
cluster-mode-disabled Redis replication-group primary endpoint and no etcd or
PgBouncer.

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `TF_VAR_redis_auth_token` | Redis AUTH password | Yes (prod) |

### Key Variables

See `variables.tf` for all options. Key ones:

| Variable | Default | Description |
|----------|---------|-------------|
| `aws_region` | `us-east-1` | AWS region |
| `environment` | `dev` | Environment name |
| `eks_cluster_version` | `1.28` | Kubernetes version |
| `rds_instance_class` | `db.t3.medium` | RDS instance size |
| `redis_node_type` | `cache.t3.medium` | Redis node size |

## Outputs

After deployment, Terraform outputs:

- `eks_cluster_endpoint` - EKS API endpoint
- `rds_endpoint` - PostgreSQL host and port
- `redis_primary_endpoint` - Redis primary host
- `kubeconfig_instructions` - kubectl setup commands

The committed `kubeconfig_instructions` output still mentions the deprecated
`ops/deploy/k8s*` copies. Prefer the canonical Kustomize commands shown above.

Get outputs:

```bash
terraform output eks_cluster_endpoint
terraform output rds_endpoint
terraform output redis_primary_endpoint
```

## SSO Server Configuration

The stock binary directly supports Redis and Postgres, but each enabled concern
must select the intended backend. A configuration adapted to this Terraform
shape starts along these lines:

```yaml
# config.yaml fragment; inject passwords/DSN through Secret-backed SSO_* env
redis:
  mode: single
  addrs: ["<redis_primary_endpoint>:6379"]
  tls:
    enabled: true

postgres:
  dialect: postgres
  # dsn supplied as SSO_POSTGRES__DSN

oauth: { backend: redis }
ciba: { backend: redis }
identity:
  backend: postgres
  session_backend: redis
permissions: { enabled: true, backend: postgres }
tenant: { enabled: true, backend: postgres }
audit: { enabled: true, backend: postgres, hash_chain: true }

# Provision etcd separately before enabling multi-replica invalidation/registry:
cluster:
  bus:
    backend: etcd
    etcd_endpoints: ["<etcd-1>:2379", "<etcd-2>:2379", "<etcd-3>:2379"]
```

This is not exhaustive. Password reset, MFA challenges, JTI replay, rate
limits, lockout, WebAuthn ceremonies, refresh grace, and every other enabled
stateful feature also need reviewed shared backends. See
[`docs/config-reference.md`](../../../docs/config-reference.md) and
[`docs/deployment.md`](../../../docs/deployment.md).

## Cost Estimation

Committed dollar estimates become misleading as AWS pricing, regions, traffic,
storage, backups, NAT usage, and instance availability change. Generate an
account/region-specific estimate from the reviewed Terraform plan with the AWS
Pricing Calculator or your established infrastructure-cost tool. Include data
transfer, NAT processing, CloudWatch, snapshots, Secrets Manager, and the
separately provisioned etcd/ingress/frontend resources.

## Security

- RDS and ElastiCache encryption at rest enabled
- Redis in-transit encryption enabled
- EKS cluster endpoint private in the prod variable set
- The modules intend to restrict database ingress to application nodes; verify
  the rendered security-group IDs and EKS node-group wiring in the target
  account before apply
- RDS deletion protection enabled (prod)
- Automated backups with retention

## Cleanup

```bash
terraform destroy -var-file="environments/dev/terraform.tfvars"
```

**Production note:** the root configuration derives RDS deletion protection
from `environment == "prod"`; there is no `deletion_protection` root variable.
A production destroy therefore requires a reviewed Terraform change or an
explicit AWS retirement workflow, followed by a new plan. Preserve and verify
the final snapshot before removing protection.

## Troubleshooting

### EKS Authentication

```bash
# Update kubeconfig
aws eks update-kubeconfig --region us-east-1 --name sso-server

# Verify
kubectl get nodes
```

### RDS Connection

```bash
# Get password from Secrets Manager
aws secretsmanager get-secret-value \
  --secret-id $(terraform output -raw rds_master_user_secret_arn) \
  --query SecretString --output text

# Connect after supplying the retrieved password without logging it
psql "host=<rds-host> port=5432 user=sso_admin dbname=sso sslmode=verify-full"
```

## CI/CD Integration

Add to CI pipeline:

```yaml
- name: Terraform Validate
  run: |
    cd ops/deploy/terraform
    terraform init -backend=false
    terraform validate

- name: Terraform Plan
  run: |
    cd ops/deploy/terraform
    terraform plan -var-file="environments/dev/terraform.tfvars" -out=tfplan
```

## References

- [AWS EKS Best Practices](https://aws.github.io/aws-eks-best-practices/)
- [RDS PostgreSQL Best Practices](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_BestPractices.html)
- [ElastiCache Redis Best Practices](https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/best-practices.html)
- [Canonical Kustomize Deployment](../kustomize/README.md)
