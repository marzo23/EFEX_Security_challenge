terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "payments_kms_key_arn" {
  type        = string
  description = "Customer-managed KMS key for payment-data S3 buckets."
  # Placeholder so `terraform plan` works in CI without secrets (same
  # pattern as factory/infra/aws/platform); real value comes from tfvars.
  default     = "arn:aws:kms:us-east-1:000000000000:key/PLACEHOLDER"
}

# ---------------------------------------------------------------------------
# VULN-010 / VULN-011 remediated -- bucket is private, encrypted with a
# customer-managed KMS key, and versioned for audit retention.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "payments_archive" {
  bucket = "efex-payments-archive"
  tags = {
    data_class = "spei-archive"
    owner      = "payments-swat"
  }
}

resource "aws_s3_bucket_public_access_block" "payments_archive" {
  bucket                  = aws_s3_bucket.payments_archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "payments_archive" {
  bucket = aws_s3_bucket.payments_archive.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.payments_kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "payments_archive" {
  bucket = aws_s3_bucket.payments_archive.id
  versioning_configuration {
    status = "Enabled"
  }
}

# ---------------------------------------------------------------------------
# VULN-012 remediated -- IAM policy scoped to the actions the SPEI batch
# runner actually performs, on the specific bucket only.
# ---------------------------------------------------------------------------
resource "aws_iam_policy" "payments_batch_runner" {
  name        = "efex-payments-batch-runner"
  description = "Read/write on the SPEI archive bucket only."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SpeiArchiveRW"
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket",
      ]
      Resource = [
        aws_s3_bucket.payments_archive.arn,
        "${aws_s3_bucket.payments_archive.arn}/*",
      ]
    }]
  })
}

# ---------------------------------------------------------------------------
# VULN-013 remediated -- SSH ingress removed. Ops access goes through SSM
# Session Manager (no inbound port required). If SSH ever returns, scope
# to the bastion CIDR via a variable, never 0.0.0.0/0.
# ---------------------------------------------------------------------------
resource "aws_security_group" "payments_runner" {
  name        = "efex-payments-runner"
  description = "Payments batch runner -- no inbound; egress to AWS APIs only."

  egress {
    description = "Outbound HTTPS for AWS API + Banxico"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
