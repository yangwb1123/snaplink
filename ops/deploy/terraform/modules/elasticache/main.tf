# ElastiCache Module - Redis Cluster for SSO server hot storage
# Creates a Redis replication group with encryption and snapshots

variable "name" {
  description = "Name prefix for resources"
  type        = string
  default     = "sso-server"
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for cache subnet group"
  type        = list(string)
}

variable "node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.t3.medium"
}

variable "num_cache_clusters" {
  description = "Number of cache clusters (nodes)"
  type        = number
  default     = 2
}

variable "engine_version" {
  description = "Redis engine version"
  type        = string
  default     = "7.0"
}

variable "automatic_failover_enabled" {
  description = "Enable automatic failover"
  type        = bool
  default     = true
}

variable "at_rest_encryption_enabled" {
  description = "Enable encryption at rest"
  type        = bool
  default     = true
}

variable "transit_encryption_enabled" {
  description = "Enable encryption in transit"
  type        = bool
  default     = true
}

variable "snapshot_retention_limit" {
  description = "Number of days to retain snapshots"
  type        = number
  default     = 7
}

variable "allowed_security_group_ids" {
  description = "Security groups allowed to access Redis"
  type        = list(string)
  default     = []
}

variable "auth_token" {
  description = "Redis AUTH token (password). If empty, no AUTH is enabled."
  type        = string
  default     = ""
  sensitive   = true
}

variable "tags" {
  description = "Additional tags"
  type        = map(string)
  default     = {}
}

resource "aws_security_group" "redis" {
  name_prefix = "${var.name}-redis-"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = var.allowed_security_group_ids
    description     = "Redis from SSO server"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.name}-redis-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_subnet_group" "redis" {
  name       = "${var.name}-redis-subnet-group"
  subnet_ids = var.subnet_ids

  tags = merge(var.tags, {
    Name = "${var.name}-redis-subnet-group"
  })
}

resource "aws_elasticache_replication_group" "this" {
  replication_group_id = "${var.name}-redis"
  description          = "Redis cluster for SSO server"

  engine               = "redis"
  engine_version       = var.engine_version
  node_type            = var.node_type
  num_cache_clusters   = var.num_cache_clusters
  port                 = 6379

  subnet_group_name  = aws_subnet_group.redis.name
  security_group_ids = [aws_security_group.redis.id]

  automatic_failover_enabled = var.automatic_failover_enabled
  multi_az_enabled           = var.automatic_failover_enabled

  at_rest_encryption_enabled = var.at_rest_encryption_enabled
  transit_encryption_enabled = var.transit_encryption_enabled
  auth_token                 = var.auth_token != "" ? var.auth_token : null

  snapshot_retention_limit = var.snapshot_retention_limit
  snapshot_window          = "03:00-05:00"
  maintenance_window       = "sun:05:00-sun:07:00"

  tags = merge(var.tags, {
    Name = "${var.name}-redis"
  })
}

output "primary_endpoint_address" {
  value = aws_elasticache_replication_group.this.primary_endpoint_address
}

output "reader_endpoint_address" {
  value = aws_elasticache_replication_group.this.reader_endpoint_address
}

output "security_group_id" {
  value = aws_security_group.redis.id
}

output "port" {
  value = aws_elasticache_replication_group.this.port
}
