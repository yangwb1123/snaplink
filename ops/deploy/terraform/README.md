# Terraform - AWS Infrastructure for SSO Server

Production-ready AWS infrastructure for deploying the SnapLink SSO server.

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
│  │  RDS PostgreSQL (Multi-AZ)                           │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐          │  │
│  │  │ Primary  │  │Standby   │  │Standby   │          │  │
│  │  └──────────┘  └──────────┘  └──────────┘          │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  ElastiCache Redis (Cluster Mode)                    │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐          │  │
│  │  │ Node 1   │  │ Node 2   │  │ Node 3   │          │  │
│  │  └──────────┘  └──────────┘  └──────────┘          │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Terraform >= 1.5.0
- AWS CLI configured with appropriate credentials
- AWS account with permissions for VPC, EKS, RDS, ElastiCache

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

# Set Redis AUTH token (required for production)
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

# Deploy SSO server using Kustomize
kubectl apply -k ../../k8s/        # Dev
kubectl apply -k ../../k8s-prod/   # Prod
```

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
- `rds_endpoint` - PostgreSQL connection string
- `redis_primary_endpoint` - Redis connection string
- `kubeconfig_instructions` - kubectl setup commands

Get outputs:

```bash
terraform output eks_cluster_endpoint
terraform output rds_endpoint
terraform output redis_primary_endpoint
```

## SSO Server Configuration

Use the Terraform outputs to configure the SSO server:

```yaml
# config.yaml (prod example)
storage:
  hot:
    backend: redis
    redis:
      address: <redis_primary_endpoint>
      password: <from TF_VAR_redis_auth_token>
      tls: true
  durable:
    backend: sqlite
    sqlite:
      dsn: <rds_endpoint>

cluster:
  bus:
    backend: etcd
    etcd:
      endpoints: ["etcd-1:2379", "etcd-2:2379", "etcd-3:2379"]
```

## Cost Estimation

### Development (dev)

- EKS: ~$73/month (2 t3.small nodes)
- RDS: ~$15/month (db.t3.micro)
- Redis: ~$15/month (cache.t3.micro)
- NAT Gateway: ~$32/month
- **Total: ~$135/month**

### Production (prod)

- EKS: ~$219/month (3 t3.medium nodes)
- RDS: ~$130/month (db.t3.medium, Multi-AZ)
- Redis: ~$100/month (3 cache.t3.medium)
- NAT Gateway: ~$96/month (3 AZs)
- **Total: ~$545/month**

## Security

- All databases encrypted at rest (AWS KMS)
- Redis in-transit encryption enabled
- EKS cluster endpoint private (prod)
- Security groups restrict access to application only
- RDS deletion protection enabled (prod)
- Automated backups with retention

## Cleanup

```bash
terraform destroy -var-file="environments/dev/terraform.tfvars"
```

**Note:** RDS has deletion protection enabled in production. Disable it first:

```bash
terraform apply -var="deletion_protection=false" -var-file="environments/prod/terraform.tfvars"
terraform destroy -var-file="environments/prod/terraform.tfvars"
```

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

# Connect
psql -h <rds_endpoint> -U sso_admin -d sso
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
- [Kustomize Deployment](../k8s/README.md)
