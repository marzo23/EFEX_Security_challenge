# EFEX-OPA-002 -- pass/fail test fixtures.
# Run:  conftest verify --policy factory/policies/opa/aws --policy factory/policies/opa/lib

package main

import rego.v1

_bucket(addr, tags) := {
	"address": addr,
	"type": "aws_s3_bucket",
	"change": {"after": {"tags": tags}},
}

_encryption_config(bucket_id) := {
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"change": {"after": {"bucket": bucket_id}},
}

# ---- Fail fixtures --------------------------------------------------------

test_denies_payment_bucket_without_encryption if {
	plan := {"resource_changes": [
		_bucket("aws_s3_bucket.payments", {"data_class": "spei-archive"}),
	]}
	some msg in deny with input as plan
	contains(msg, "EFEX-OPA-002")
}

# Mimics a real plan: the encryption config exists but targets a DIFFERENT
# bucket, both via value and via configuration-graph references.
test_denies_when_encryption_targets_other_bucket if {
	plan := {
		"resource_changes": [
			_bucket("aws_s3_bucket.payments", {"data_class": "spei-archive"}),
			_bucket("aws_s3_bucket.logs", {"data_class": "spei-logs"}),
			{
				"type": "aws_s3_bucket_server_side_encryption_configuration",
				"address": "aws_s3_bucket_server_side_encryption_configuration.logs",
				"change": {
					"after": {"bucket": null},
					"after_unknown": {"bucket": true},
				},
			},
		],
		"configuration": {"root_module": {"resources": [{
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"address": "aws_s3_bucket_server_side_encryption_configuration.logs",
			"expressions": {"bucket": {"references": [
				"aws_s3_bucket.logs.id",
				"aws_s3_bucket.logs",
			]}},
		}]}},
	}
	some msg in deny with input as plan
	contains(msg, "aws_s3_bucket.payments")
}

# ---- Pass fixtures --------------------------------------------------------

test_allows_payment_bucket_with_encryption if {
	plan := {"resource_changes": [
		_bucket("aws_s3_bucket.payments", {"data_class": "spei-archive"}),
		_encryption_config("payments"),
	]}
	count(deny) == 0 with input as plan
}

# Mimics a real plan for a NEW bucket: `bucket = aws_s3_bucket.payments.id`
# is unknown at plan time (after.bucket null, after_unknown.bucket true);
# the link only exists in the configuration graph.
test_allows_new_bucket_with_plan_time_unknown_encryption_ref if {
	plan := {
		"resource_changes": [
			_bucket("aws_s3_bucket.payments", {"data_class": "spei-archive"}),
			{
				"type": "aws_s3_bucket_server_side_encryption_configuration",
				"address": "aws_s3_bucket_server_side_encryption_configuration.payments",
				"change": {
					"after": {"bucket": null},
					"after_unknown": {"bucket": true},
				},
			},
		],
		"configuration": {"root_module": {"resources": [{
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"address": "aws_s3_bucket_server_side_encryption_configuration.payments",
			"expressions": {"bucket": {"references": [
				"aws_s3_bucket.payments.id",
				"aws_s3_bucket.payments",
			]}},
		}]}},
	}
	count(deny) == 0 with input as plan
}

test_ignores_non_payment_buckets if {
	# No data_class tag in scope (data_class != spei-*) -> not in scope of this policy.
	plan := {"resource_changes": [
		_bucket("aws_s3_bucket.public_assets", {"data_class": "marketing"}),
	]}
	count(deny) == 0 with input as plan
}
