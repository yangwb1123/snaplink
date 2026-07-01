output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = module.vpc.private_subnet_ids
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = module.vpc.public_subnet_ids
}

output "sso_server_security_group_id" {
  description = "Security group ID for SSO server"
  value       = module.vpc.sso_server_security_group_id
}

output "eks_cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "eks_cluster_certificate_authority" {
  description = "EKS cluster certificate authority"
  value       = module.eks.cluster_certificate_authority
  sensitive   = true
}

output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint"
  value       = module.rds.endpoint
}

output "rds_db_name" {
  description = "RDS database name"
  value       = module.rds.db_name
}

output "rds_master_user_secret_arn" {
  description = "RDS master user secret ARN"
  value       = module.rds.master_user_secret_arn
  sensitive   = true
}

output "redis_primary_endpoint" {
  description = "Redis primary endpoint"
  value       = module.elasticache.primary_endpoint_address
}

output "redis_reader_endpoint" {
  description = "Redis reader endpoint"
  value       = module.elasticache.reader_endpoint_address
}

output "redis_port" {
  description = "Redis port"
  value       = module.elasticache.port
}

# Connection strings for SSO server config
output "postgres_dsn" {
  description = "PostgreSQL DSN (requires password from Secrets Manager)"
  value       = "postgres://sso_admin@${module.rds.endpoint}/sso?sslmode=verify-full"
}

output "redis_url" {
  description = "Redis URL (requires AUTH token if enabled)"
  value       = "rediss://${module.elasticache.primary_endpoint_address}:${module.elasticache.port}"
}

# Kubeconfig generation helper
output "kubeconfig_instructions" {
  description = "Instructions for configuring kubectl"
  value       = <<EOT

To configure kubectl for this cluster:

1. Install AWS CLI and configure credentials
2. Run: aws eks update-kubeconfig --region ${var.aws_region} --name ${module.eks.cluster_name}
3. Verify: kubectl get nodes

To deploy SSO server using Kustomize:
  kubectl apply -k ../../k8s/

To deploy production overlay:
  kubectl apply -k ../../k8s-prod/

EOT
}
