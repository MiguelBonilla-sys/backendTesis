# ── Project / Environment ─────────────────────────────────────────────────────

variable "project_name" {
  description = "Project identifier used in resource names"
  type        = string
  default     = "backendtesis"
}

variable "environment" {
  description = "Deployment environment: development | staging | production"
  type        = string
  default     = "development"

  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "environment must be development, staging, or production."
  }
}

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

# ── Networking ────────────────────────────────────────────────────────────────

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones to deploy into (minimum 2 for RDS Multi-AZ)"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets (Lambda, RDS, ElastiCache)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (NAT Gateway, ALB if used)"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24"]
}

# ── RDS PostgreSQL ────────────────────────────────────────────────────────────

variable "db_instance_class" {
  description = "RDS instance class. db.t3.micro is free-tier eligible for 12 months."
  type        = string
  default     = "db.t3.micro"
}

variable "db_name" {
  description = "PostgreSQL database name"
  type        = string
  default     = "phishing_detector"
}

variable "db_username" {
  description = "PostgreSQL master username"
  type        = string
  default     = "btadmin"
}

variable "db_password" {
  description = "PostgreSQL master password (store in CI/CD secrets — never commit)"
  type        = string
  sensitive   = true
}

variable "db_allocated_storage_gb" {
  description = "Initial RDS storage in GB (gp2). Minimum 20 GB for free tier."
  type        = number
  default     = 20
}

variable "db_multi_az" {
  description = "Enable Multi-AZ RDS for high availability (increases cost ~2x)"
  type        = bool
  default     = false
}

# ── Lambda ────────────────────────────────────────────────────────────────────

variable "lambda_memory_mb" {
  description = "Lambda function memory in MB. Higher memory = more vCPU share."
  type        = number
  default     = 512
}

variable "lambda_timeout_seconds" {
  description = "Lambda function timeout in seconds (max 900)"
  type        = number
  default     = 30
}

variable "lambda_reserved_concurrency" {
  description = "Reserved concurrent executions for the Lambda (null = unreserved)"
  type        = number
  default     = null
}

variable "lambda_image_uri" {
  description = "ECR image URI for the Lambda container (e.g. 123456789.dkr.ecr.us-east-1.amazonaws.com/backendtesis:latest)"
  type        = string
}

# ── App Secrets ───────────────────────────────────────────────────────────────

variable "secret_key" {
  description = "JWT secret key for token signing — must be a strong random value in production"
  type        = string
  sensitive   = true
}

variable "virustotal_api_key" {
  description = "VirusTotal API key"
  type        = string
  sensitive   = true
  default     = ""
}

variable "urlscan_api_key" {
  description = "URLScan.io API key"
  type        = string
  sensitive   = true
  default     = ""
}

variable "google_safe_browsing_api_key" {
  description = "Google Safe Browsing API key"
  type        = string
  sensitive   = true
  default     = ""
}

variable "whoisxml_api_key" {
  description = "WhoisXML API key"
  type        = string
  sensitive   = true
  default     = ""
}

# ── LLM Backend ───────────────────────────────────────────────────────────────

variable "llamastack_url" {
  description = "URL of the LlamaStack / Bedrock-compatible inference endpoint. Leave empty to disable LLM agent."
  type        = string
  default     = ""
}

variable "llamastack_model" {
  description = "Model identifier as expected by the inference endpoint"
  type        = string
  default     = "meta.llama3-8b-instruct-v1:0"
}

variable "lambda_function_url_auth_type" {
  description = "Authorization type for Lambda Function URL. Use NONE for public access or AWS_IAM for private. Default is NONE for development convenience; set to AWS_IAM for production."
  type        = string
  default     = "NONE"

  validation {
    condition     = contains(["NONE", "AWS_IAM"], var.lambda_function_url_auth_type)
    error_message = "lambda_function_url_auth_type must be NONE or AWS_IAM."
  }
}

variable "cors_allow_origins" {
  description = "CORS allowed origins for Lambda Function URL and API Gateway. Restrict to known domains in production."
  type        = list(string)
  default     = ["*"]
}
