# Development environment - minimal resources, lower cost
# Use: terraform apply -var-file="environments/dev/terraform.tfvars"

environment = "dev"

# VPC
vpc_cidr               = "10.0.0.0/16"
availability_zones     = ["us-east-1a", "us-east-1b"]
public_subnet_cidrs    = ["10.0.1.0/24", "10.0.2.0/24"]
private_subnet_cidrs   = ["10.0.11.0/24", "10.0.12.0/24"]
enable_nat_gateway     = true

# EKS - minimal
eks_cluster_version      = "1.28"
eks_node_instance_types  = ["t3.small"]
eks_node_desired_size    = 2
eks_node_min_size        = 1
eks_node_max_size        = 3

# RDS - minimal
rds_instance_class      = "db.t3.micro"
rds_allocated_storage   = 20
rds_max_allocated_storage = 50
rds_engine_version      = "15.4"

# Redis - minimal
redis_node_type         = "cache.t3.micro"
redis_engine_version    = "7.0"

tags = {
  CostCenter  = "development"
  Team        = "platform"
}
