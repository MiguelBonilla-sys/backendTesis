# ── ECR Repository ────────────────────────────────────────────────────────────

resource "aws_ecr_repository" "app" {
  name                 = "${var.project_name}-${var.environment}"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
  }

  tags = { Name = "${var.project_name}-${var.environment}-ecr" }
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

# ── IAM Role for Lambda ───────────────────────────────────────────────────────

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${var.project_name}-${var.environment}-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = { Name = "${var.project_name}-${var.environment}-lambda-role" }
}

data "aws_iam_policy_document" "lambda_permissions" {
  # VPC networking (required for Lambda in VPC)
  statement {
    sid    = "VPCNetworking"
    effect = "Allow"
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DeleteNetworkInterface",
    ]
    resources = ["*"]
  }

  # CloudWatch Logs
  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"]
  }

  # Secrets Manager — read the app secrets
  statement {
    sid    = "SecretsManager"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]
    resources = [aws_secretsmanager_secret.app_secrets.arn]
  }

  # ECR — pull container image (required for container-based Lambda)
  statement {
    sid    = "ECRPull"
    effect = "Allow"
    actions = [
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:GetAuthorizationToken",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "${var.project_name}-${var.environment}-lambda-policy"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}

# ── CloudWatch Log Group ──────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.project_name}-${var.environment}"
  retention_in_days = var.environment == "production" ? 30 : 7
  tags              = { Name = "${var.project_name}-${var.environment}-logs" }
}

# ── Lambda Function (Container Image) ────────────────────────────────────────

resource "aws_lambda_function" "app" {
  function_name = "${var.project_name}-${var.environment}"
  description   = "BackendTesis FastAPI — IDN Homograph Phishing Detector"
  role          = aws_iam_role.lambda.arn
  package_type  = "Image"
  image_uri     = var.lambda_image_uri

  memory_size                    = var.lambda_memory_mb
  timeout                        = var.lambda_timeout_seconds
  reserved_concurrent_executions = var.lambda_reserved_concurrency

  # Lambda in VPC — connects to private RDS and ElastiCache
  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  # Environment variables — secrets come from Secrets Manager at cold start
  environment {
    variables = {
      APP_ENV         = var.environment
      DATABASE_URL    = local.database_url
      REDIS_URL       = local.redis_url
      LLAMASTACK_URL  = var.llamastack_url
      LLAMASTACK_MODEL = var.llamastack_model

      # Paths for bundled data files inside the container
      CONFUSABLES_PATH  = "/var/task/data/confusables.txt"
      DOMAIN_INDEX_PATH = "/var/task/data/top1m.txt"

      # Secrets Manager ARN — app reads secrets at startup
      SECRETS_MANAGER_ARN = aws_secretsmanager_secret.app_secrets.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda]

  tags = { Name = "${var.project_name}-${var.environment}-lambda" }
}

# ── Lambda Function URL (alternative to API Gateway — zero extra cost) ────────
# WARNING: authorization_type = "NONE" makes this endpoint publicly accessible.
# For production, set lambda_function_url_auth_type = "AWS_IAM" in your tfvars.

resource "aws_lambda_function_url" "app" {
  function_name      = aws_lambda_function.app.function_name
  authorization_type = var.lambda_function_url_auth_type

  cors {
    allow_credentials = true
    allow_origins     = var.cors_allow_origins
    allow_methods     = ["*"]
    allow_headers     = ["*"]
    max_age           = 86400
  }
}

# Block the plan when deploying to production with a publicly accessible Function URL.
# terraform_data + precondition is the idiomatic way to enforce cross-variable
# constraints at plan-time in Terraform (variable validation blocks cannot reference
# other variables).
resource "terraform_data" "public_access_warning" {
  # Only evaluated when the unsafe combination is detected.
  count = var.environment == "production" && var.lambda_function_url_auth_type == "NONE" ? 1 : 0

  lifecycle {
    precondition {
      condition     = false
      error_message = "SECURITY: lambda_function_url_auth_type is NONE in production. Set it to AWS_IAM or remove the Function URL and use API Gateway with an authorizer instead."
    }
  }
}
