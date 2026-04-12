# ── Outputs ───────────────────────────────────────────────────────────────────

output "api_gateway_url" {
  description = "Base URL of the API Gateway HTTP API endpoint"
  value       = aws_apigatewayv2_stage.default.invoke_url
}

output "lambda_function_url" {
  description = "Direct Lambda Function URL (no API Gateway — zero API GW cost)"
  value       = aws_lambda_function_url.app.function_url
}

output "lambda_function_name" {
  description = "Lambda function name"
  value       = aws_lambda_function.app.function_name
}

output "ecr_repository_url" {
  description = "ECR repository URL — push container images here"
  value       = aws_ecr_repository.app.repository_url
}

output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint (host:port)"
  value       = "${aws_db_instance.postgres.address}:${aws_db_instance.postgres.port}"
  sensitive   = false
}

output "redis_endpoint" {
  description = "ElastiCache Serverless Redis endpoint"
  value       = aws_elasticache_serverless_cache.redis.endpoint[0].address
}

output "secrets_manager_arn" {
  description = "ARN of the Secrets Manager secret containing app secrets"
  value       = aws_secretsmanager_secret.app_secrets.arn
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "private_subnet_ids" {
  description = "Private subnet IDs (Lambda, RDS, ElastiCache)"
  value       = aws_subnet.private[*].id
}

output "monthly_cost_estimate" {
  description = "Rough monthly cost estimate for this environment (USD)"
  value = {
    note             = "Estimates only — see docs/AWS-DEPLOYMENT.md for full breakdown"
    lambda           = "~$0 (free tier covers thesis-scale traffic)"
    api_gateway      = "~$0 (free tier: 1M req/month for 12 months)"
    rds_postgres     = var.db_instance_class == "db.t3.micro" ? "~$0 free tier (12 months) then ~$15/month" : "~$15–60/month depending on instance class"
    elasticache      = "~$1–3/month (Serverless at low traffic)"
    nat_gateway      = "~$32/month + data transfer — largest fixed cost"
    secrets_manager  = "~$2/month (5 secrets)"
    ecr_storage      = "~$0.10/month per GB stored"
    total_estimate   = "~$35–50/month (dev); ~$50–100/month (prod with Multi-AZ)"
    free_tier_12m    = "~$5–15/month for the first 12 months (Lambda + RDS + API GW free tier)"
  }
}
