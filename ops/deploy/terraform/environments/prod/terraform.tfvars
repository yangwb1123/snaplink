# Production environment - HA, multi-AZ, encrypted, backed up
# Use: terraform apply -var-file="environments/prod/terraform.tfvars"

environment = "prod"

# VPC - full 3-AZ
vpc_cidr               = "10.0.0.0/16"
availability_zones     = ["us-east-1a", "us-east-1b", "us-east-1c"]
public_subnet_cidrs    = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
private_subnet_cidrs   = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
enable_nat_gateway     = true

# EKS - production sizing
eks_cluster_version      = "1.28"
eks_node_instance_types  = ["t3.medium"]
eks_node_desired_size    = 3
eks_node_min_size        = 2
eks_node_max_size        = 6

# RDS - HA
rds_instance_class      = "db.t3.medium"
rds_allocated_storage   = 50
rds_max_allocated_storage = 200
rds_engine_version      = "15.4"

# Redis - HA cluster
redis_node_type         = "cache.t3.medium"
redis_engine_version    = "7.0"

# Redis AUTH - required in production
# Provide via TF_VAR_redis_auth_token environment variable
# redis_auth_token = ""

tags = {
  CostCenter  = "production"
  Team        = "platform"
  Compliance  = "pci-dss"
}
