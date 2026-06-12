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
  description = "Customer-managed KMS key used to encrypt evidence at rest."
  # Placeholder so `terraform plan` works in CI without secrets; real value
  # is wired in via the deployment pipeline's tfvars.
  default     = "arn:aws:kms:us-east-1:000000000000:key/PLACEHOLDER"
}

# ---------------------------------------------------------------------------
# Evidence bucket -- WORM storage for SARIF, SBOMs and compliance reports.
#
# Why:
#   - SOC 2 Type II practitioner consensus expects >=15 months of immutable
#     evidence (12-month observation window + buffer).
#   - CNBV CUIFPE Art. 168 requires "inalterable logs of critical operations".
#   - PCI DSS 10.3.4 requires audit logs protected from modification.
#
# Design choices:
#   - Object Lock COMPLIANCE mode (not GOVERNANCE): not even the root account
#     can shorten or override retention. GOVERNANCE would let a compromised
#     admin retro-edit evidence; that's exactly what auditors fear.
#   - 7-year retention by default; conservatively covers Mexican accounting
#     and CNBV expectations. Tunable via variable for non-prod accounts.
#   - aws:kms with a customer-managed key (referenced via variable) so EFEX
#     controls the key lifecycle independent of AWS.
#   - Bucket key enabled to cut KMS request cost on per-object encryption.
#   - Public access blocked at every layer.
# ---------------------------------------------------------------------------

variable "evidence_retention_years" {
  type        = number
  default     = 7
  description = "Object Lock retention in years (default 7; minimum 2 to stay above SOC 2)."
  validation {
    condition     = var.evidence_retention_years >= 2
    error_message = "evidence_retention_years must be >= 2 to satisfy SOC 2 Type II practitioner consensus."
  }
}

variable "evidence_writer_oidc_subjects" {
  type        = list(string)
  description = "GitHub Actions OIDC subjects allowed to write evidence (default branches only)."
  default = [
    "repo:efex/secure-factory:ref:refs/heads/main",
    "repo:efex/secure-factory:ref:refs/heads/master",
  ]
}

resource "aws_s3_bucket" "evidence" {
  bucket              = "efex-secure-factory-evidence"
  object_lock_enabled = true

  tags = {
    data_class = "spei-archive"   # so EFEX-OPA-002 enforces SSE on this bucket too
    owner      = "security-platform"
    purpose    = "compliance-evidence-worm"
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"   # required to enable Object Lock retention
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.payments_kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode  = "COMPLIANCE"
      years = var.evidence_retention_years
    }
  }
  depends_on = [aws_s3_bucket_versioning.evidence]
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    id     = "tier-old-evidence-to-glacier"
    status = "Enabled"
    filter {}
    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }
    transition {
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }
    # No expiration: Object Lock COMPLIANCE retention is the floor.
  }
}

# ---------------------------------------------------------------------------
# OIDC trust + IAM role for GitHub Actions to write (but not delete) evidence.
# Pairs with the `provenance` and `report` jobs in
# .github/workflows/secure-pipeline.yml (which assume this role via
# aws-actions/configure-aws-credentials@v4).
#
# The GitHub OIDC provider is expected to be pre-provisioned at the account
# level. We pass its ARN in as a variable so `terraform plan` works in CI
# without AWS credentials (i.e. without data-source refresh).
# ---------------------------------------------------------------------------

variable "github_oidc_provider_arn" {
  type        = string
  description = "ARN of the pre-provisioned GitHub Actions OIDC provider in this account."
  default     = "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"
}

data "aws_iam_policy_document" "evidence_writer_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.github_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    # default-branch pushes only -- PRs and feature branches don't get
    # write access to evidence.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = var.evidence_writer_oidc_subjects
    }
  }
}

resource "aws_iam_role" "evidence_writer" {
  name               = "efex-evidence-writer"
  description        = "GH Actions OIDC role: PutObject-only to the evidence bucket on main."
  assume_role_policy = data.aws_iam_policy_document.evidence_writer_trust.json
}

data "aws_iam_policy_document" "evidence_writer" {
  statement {
    sid    = "WriteEvidenceOnly"
    effect = "Allow"
    # Deliberately narrow: no DeleteObject, no PutBucketPolicy. Object Lock
    # would block deletes anyway during retention, but defense in depth.
    actions = [
      "s3:PutObject",
      "s3:PutObjectTagging",
      "s3:AbortMultipartUpload",
      "s3:ListBucketMultipartUploads",
    ]
    resources = [
      aws_s3_bucket.evidence.arn,
      "${aws_s3_bucket.evidence.arn}/*",
    ]
  }
  statement {
    sid     = "UseKmsForEvidenceEncryption"
    effect  = "Allow"
    actions = ["kms:GenerateDataKey", "kms:Encrypt", "kms:DescribeKey"]
    resources = [var.payments_kms_key_arn]
  }
}

resource "aws_iam_role_policy" "evidence_writer" {
  name   = "efex-evidence-writer"
  role   = aws_iam_role.evidence_writer.id
  policy = data.aws_iam_policy_document.evidence_writer.json
}

output "evidence_bucket" {
  value       = aws_s3_bucket.evidence.bucket
  description = "Name of the evidence bucket; set as repo variable EVIDENCE_BUCKET."
}

output "evidence_writer_role_arn" {
  value       = aws_iam_role.evidence_writer.arn
  description = "OIDC role ARN; pipeline pulls AWS_ACCOUNT_ID from this."
}
