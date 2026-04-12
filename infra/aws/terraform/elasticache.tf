# ── ElastiCache Serverless (Redis-compatible) ─────────────────────────────────
# Serverless mode scales to zero-ish and is cheapest for bursty/low-traffic
# thesis workloads. Cost: $0.125/GB-stored + $0.034/ECPU.
# Estimated: ~$1–3/month at thesis scale.

resource "aws_elasticache_serverless_cache" "redis" {
  engine = "redis"
  name   = "${var.project_name}-${var.environment}-cache"

  cache_usage_limits {
    data_storage {
      maximum = 1   # GB — raise for production
      unit    = "GB"
    }
    ecpu_per_second {
      maximum = 1000  # ECPUs — raise for production
    }
  }

  subnet_ids         = aws_subnet.private[*].id
  security_group_ids = [aws_security_group.elasticache.id]

  # Snapshot — disabled for dev to allow easy teardown
  snapshot_retention_limit = var.environment == "production" ? 1 : 0

  tags = { Name = "${var.project_name}-${var.environment}-redis" }
}

locals {
  redis_url = "rediss://${aws_elasticache_serverless_cache.redis.endpoint[0].address}:6379/0"
  # Note: ElastiCache Serverless always uses TLS (rediss://)
}
