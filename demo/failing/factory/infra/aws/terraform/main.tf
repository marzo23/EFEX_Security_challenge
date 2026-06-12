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

# ---------------------------------------------------------------------------
# VULN-010 -- S3 bucket with no server-side encryption (Checkov CKV_AWS_19 /
# custom EFEX-OPA-002: payment-data buckets MUST set
# aws_s3_bucket_server_side_encryption_configuration).
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "payments_archive" {
  bucket = "efex-payments-archive-vuln"
  tags = {
    data_class = "spei-archive"
    owner      = "payments-swat"
  }
}

# VULN-011 -- public bucket: all four public-access blocks disabled
resource "aws_s3_bucket_public_access_block" "payments_archive" {
  bucket                  = aws_s3_bucket.payments_archive.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# ---------------------------------------------------------------------------
# VULN-012 -- IAM policy with Action="*" Resource="*" on Allow.
# Caught by custom OPA policy EFEX-OPA-001 (policies/opa/iam.rego).
# ---------------------------------------------------------------------------
resource "aws_iam_policy" "wildcard_admin" {
  name        = "efex-wildcard-admin"
  description = "Pretend-temporary admin policy that becomes permanent"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AllowEverything"
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# ---------------------------------------------------------------------------
# VULN-013 -- Security Group exposing SSH to 0.0.0.0/0
# (Checkov CKV_AWS_24).
# ---------------------------------------------------------------------------
resource "aws_security_group" "open_ssh" {
  name        = "efex-open-ssh"
  description = "Open SSH for ops convenience"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
