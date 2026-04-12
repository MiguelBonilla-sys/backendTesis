# ── RDS PostgreSQL with pgvector ──────────────────────────────────────────────
# pgvector (PostgreSQL extension) replaces ChromaDB for vector similarity search.
# Enable on RDS PostgreSQL 15+ with: CREATE EXTENSION IF NOT EXISTS vector;

resource "aws_db_subnet_group" "main" {
  name        = "${var.project_name}-${var.environment}-db-subnet"
  description = "Subnet group for RDS PostgreSQL"
  subnet_ids  = aws_subnet.private[*].id

  tags = { Name = "${var.project_name}-${var.environment}-db-subnet-group" }
}

resource "aws_db_parameter_group" "postgres15" {
  name        = "${var.project_name}-${var.environment}-pg15"
  family      = "postgres15"
  description = "Parameter group for BackendTesis PostgreSQL 15"

  # Shared preload libraries required for pgvector
  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements"
  }

  tags = { Name = "${var.project_name}-postgres15-params" }
}

resource "aws_db_instance" "postgres" {
  identifier = "${var.project_name}-${var.environment}-postgres"

  # Engine
  engine               = "postgres"
  engine_version       = "15.7"
  instance_class       = var.db_instance_class  # db.t3.micro = free tier eligible
  parameter_group_name = aws_db_parameter_group.postgres15.name

  # Storage — gp3 is cheaper than gp2 for same performance
  allocated_storage     = var.db_allocated_storage_gb
  max_allocated_storage = 100   # autoscaling ceiling in GB
  storage_type          = "gp3"
  storage_encrypted     = true

  # Credentials
  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  # Network
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false

  # Availability
  multi_az               = var.db_multi_az
  availability_zone      = var.db_multi_az ? null : var.availability_zones[0]

  # Maintenance / backups
  backup_retention_period = var.environment == "production" ? 7 : 1
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"
  deletion_protection     = var.environment == "production"

  # Snapshot on destroy:
  # - Non-production: skip_final_snapshot=true, identifier omitted (null = not set).
  # - Production: skip_final_snapshot=false, identifier required by AWS.
  skip_final_snapshot = var.environment != "production"

  # final_snapshot_identifier must only be provided when skip_final_snapshot = false.
  # Setting it to null when skip_final_snapshot = true is valid Terraform (attribute omitted).
  final_snapshot_identifier = var.environment == "production" ? "${var.project_name}-${var.environment}-final-snapshot" : null

  tags = { Name = "${var.project_name}-${var.environment}-postgres" }
}

# ── Output the DATABASE_URL for the Lambda environment variable ───────────────
locals {
  database_url = "postgresql+asyncpg://${var.db_username}:${var.db_password}@${aws_db_instance.postgres.address}:5432/${var.db_name}"
}
