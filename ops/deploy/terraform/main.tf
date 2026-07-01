# SnapLink SSO Server - AWS Infrastructure
#
# Provisions production-ready infrastructure for running the SSO server:
# - VPC with public/private subnets across 3 AZs
# - EKS cluster for container orchestration
# - RDS PostgreSQL for durable storage
# - ElastiCache Redis for hot storage (OAuth codes, sessions)
#
# Usage:
#   terraform init
#   terraform plan -var-file="environments/dev/terraform.tfvars"
#   terraform apply -var-file="environments/dev/terraform.tfvars"

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state backend (recommended for production)
  # backend "s3" {
  #   bucket         = "sso-server-terraform-state"
  #   key            = "infrastructure/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "sso-server-terraform-locks"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "sso-server"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# VPC
module "vpc" {
  source = "./modules/vpc"

  name     = var.name
  vpc_cidr = var.vpc_cidr

  availability_zones   = var.availability_zones
  public_subnet_cidrs  = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs

  enable_nat_gateway = var.enable_nat_gateway
  single_nat_gateway = var.environment == "dev"

  tags = var.tags
}

# RDS PostgreSQL
module "rds" {
  source = "./modules/rds"

  name     = var.name
  vpc_id   = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnet_ids

  instance_class          = var.rds_instance_class
  allocated_storage       = var.rds_allocated_storage
  max_allocated_storage   = var.rds_max_allocated_storage
  engine_version          = var.rds_engine_version
  multi_az                = var.environment == "prod"
  deletion_protection     = var.environment == "prod"
  backup_retention_period = var.environment == "prod" ? 7 : 1

  allowed_security_group_ids = [
    module.eks.node_group_role_arn
  ]

  tags = var.tags
}

# ElastiCache Redis
module "elasticache" {
  source = "./modules/elasticache"

  name     = var.name
  vpc_id   = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnet_ids

  node_type          = var.redis_node_type
  num_cache_clusters = var.environment == "prod" ? 3 : 2
  engine_version     = var.redis_engine_version

  automatic_failover_enabled = var.environment == "prod"
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  snapshot_retention_limit = var.environment == "prod" ? 7 : 1

  allowed_security_group_ids = [
    module.eks.node_group_role_arn
  ]

  auth_token = var.redis_auth_token

  tags = var.tags
}

# EKS Cluster
module "eks" {
  source = "./modules/eks"

  name     = var.name
  vpc_id   = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnet_ids

  cluster_version = var.eks_cluster_version

  node_group_instance_types = var.eks_node_instance_types
  node_group_desired_size   = var.eks_node_desired_size
  node_group_min_size       = var.eks_node_min_size
  node_group_max_size       = var.eks_node_max_size

  cluster_endpoint_public_access  = var.environment == "dev"
  cluster_endpoint_private_access = true

  tags = var.tags
}
