# RDS Module - PostgreSQL for SSO server
# Creates a multi-AZ RDS cluster with encryption and backups

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
  description = "List of subnet IDs for DB subnet group"
  type        = list(string)
}

variable "instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "allocated_storage" {
  description = "Allocated storage in GB"
  type        = number
  default     = 20
}

variable "max_allocated_storage" {
  description = "Maximum storage for autoscaling"
  type        = number
  default     = 100
}

variable "engine_version" {
  description = "PostgreSQL engine version"
  type        = string
  default     = "15.4"
}

variable "multi_az" {
  description = "Enable multi-AZ deployment"
  type        = bool
  default     = true
}

variable "backup_retention_period" {
  description = "Backup retention period in days"
  type        = number
  default     = 7
}

variable "deletion_protection" {
  description = "Enable deletion protection"
  type        = bool
  default     = true
}

variable "allowed_security_group_ids" {
  description = "Security groups allowed to access RDS"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Additional tags"
  type        = map(string)
  default     = {}
}

resource "aws_db_subnet_group" "this" {
  name       = "${var.name}-db-subnet-group"
  subnet_ids = var.subnet_ids

  tags = merge(var.tags, {
    Name = "${var.name}-db-subnet-group"
  })
}

resource "aws_security_group" "rds" {
  name_prefix = "${var.name}-rds-"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = var.allowed_security_group_ids
    description     = "PostgreSQL from SSO server"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.name}-rds-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_db_instance" "this" {
  identifier = "${var.name}-postgres"

  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_encrypted     = true

  db_name  = "sso"
  username = "sso_admin"
  # Password should be managed externally (e.g., AWS Secrets Manager)
  # This is a placeholder - in production, use a managed secret
  manage_master_user_password = true

  multi_az            = var.multi_az
  db_subnet_group_name = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  backup_retention_period = var.backup_retention_period
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:00-Mon:05:00"

  deletion_protection       = var.deletion_protection
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name}-final-snapshot"

  performance_insights_enabled = true
  storage_type                 = "gp3"

  tags = merge(var.tags, {
    Name = "${var.name}-postgres"
  })
}

output "endpoint" {
  value = aws_db_instance.this.endpoint
}

output "db_name" {
  value = aws_db_instance.this.db_name
}

output "master_user_secret_arn" {
  value = aws_db_instance.this.master_user_secret_arn
}

output "security_group_id" {
  value = aws_security_group.rds.id
}
