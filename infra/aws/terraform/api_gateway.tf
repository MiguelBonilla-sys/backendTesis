# ── API Gateway HTTP API ──────────────────────────────────────────────────────
# HTTP API is ~70% cheaper than REST API and sufficient for most use cases.
# Cost: $1.00/million requests (first 300 million/month).
# Free tier: 1 million requests/month for the first 12 months.

resource "aws_apigatewayv2_api" "main" {
  name          = "${var.project_name}-${var.environment}"
  protocol_type = "HTTP"
  description   = "BackendTesis HTTP API — IDN Phishing Detector"

  cors_configuration {
    allow_credentials = true
    allow_headers     = ["*"]
    allow_methods     = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allow_origins     = var.cors_allow_origins
    max_age           = 86400
  }

  tags = { Name = "${var.project_name}-${var.environment}-apigw" }
}

# ── Lambda Integration ────────────────────────────────────────────────────────

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.app.invoke_arn
  payload_format_version = "2.0"   # required for HTTP API + Mangum
}

# ── Default route — forward all paths to Lambda ───────────────────────────────

resource "aws_apigatewayv2_route" "default" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

# ── Stage (auto-deploy) ───────────────────────────────────────────────────────

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.main.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      sourceIp       = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      protocol       = "$context.protocol"
      httpMethod     = "$context.httpMethod"
      resourcePath   = "$context.resourcePath"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      responseLength = "$context.responseLength"
      integrationLatency = "$context.integrationLatency"
    })
  }

  tags = { Name = "${var.project_name}-${var.environment}-apigw-stage" }
}

resource "aws_cloudwatch_log_group" "apigw" {
  name              = "/aws/apigateway/${var.project_name}-${var.environment}"
  retention_in_days = var.environment == "production" ? 30 : 7
  tags              = { Name = "${var.project_name}-${var.environment}-apigw-logs" }
}

# ── Lambda Permission — allow API Gateway to invoke Lambda ────────────────────

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.app.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*"
}
