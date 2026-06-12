# EFEX custom OPA policies -- AWS S3 / payment-data storage.
#
# Cross-cloud structure: the *intent* (encrypt payment data at rest) lives
# in factory/policies/opa/lib/. This file maps it to AWS's S3 schema.
#
# Tests: see s3_test.rego in this directory.

package main

import rego.v1

# --------------------------------------------------------------------------
# EFEX-OPA-002 -- S3 buckets holding SPEI payment data must have
# server-side encryption configured.
# --------------------------------------------------------------------------
deny contains msg if {
	bucket := input.resource_changes[_]
	bucket.type == "aws_s3_bucket"
	is_payment_data(bucket.change.after.tags)
	not has_encryption_config(bucket.address)
	msg := sprintf(
		"EFEX-OPA-002 [CRITICAL]: S3 bucket %s holds payment data (tag data_class=%s) but has no aws_s3_bucket_server_side_encryption_configuration.",
		[bucket.address, bucket.change.after.tags.data_class],
	)
}

is_payment_data(tags) if startswith(tags.data_class, "spei")

# In a real plan, `bucket = aws_s3_bucket.x.id` is unknown at plan time:
# change.after.bucket is null and change.after_unknown.bucket is true, so a
# value match alone false-positives on every correctly encrypted new bucket.
# We accept either a literal value match (existing buckets, fixtures) or a
# reference match in the plan's configuration graph (new buckets).
has_encryption_config(bucket_address) if {
	enc := input.resource_changes[_]
	enc.type == "aws_s3_bucket_server_side_encryption_configuration"
	is_string(enc.change.after.bucket)
	contains(enc.change.after.bucket, trim_aws_s3_prefix(bucket_address))
}

has_encryption_config(bucket_address) if {
	enc := input.configuration.root_module.resources[_]
	enc.type == "aws_s3_bucket_server_side_encryption_configuration"
	ref := enc.expressions.bucket.references[_]
	ref_targets_bucket(ref, bucket_address)
}

ref_targets_bucket(ref, bucket_address) if ref == bucket_address

ref_targets_bucket(ref, bucket_address) if startswith(ref, sprintf("%s.", [bucket_address]))

trim_aws_s3_prefix(s) := out if {
	prefix := "aws_s3_bucket."
	startswith(s, prefix)
	out := substring(s, count(prefix), -1)
}
