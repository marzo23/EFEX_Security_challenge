# EFEX-OPA-001 -- pass/fail test fixtures.
# Run:  conftest verify --policy factory/policies/opa/aws --policy factory/policies/opa/lib

package main

import rego.v1

# ---- Helpers --------------------------------------------------------------

_policy_resource(addr, policy_doc) := {
    "address": addr,
    "type": "aws_iam_policy",
    "change": {"after": {"policy": json.marshal(policy_doc)}},
}

# ---- Fail fixtures --------------------------------------------------------

test_denies_wildcard_action_and_resource if {
    plan := {"resource_changes": [_policy_resource(
        "aws_iam_policy.wildcard_admin",
        {"Version": "2012-10-17", "Statement": [{
            "Sid": "AllowAll",
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }]},
    )]}
    some msg in deny with input as plan
    contains(msg, "EFEX-OPA-001")
}

test_denies_wildcard_in_action_list if {
    plan := {"resource_changes": [_policy_resource(
        "aws_iam_policy.list_admin",
        {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "*"],
            "Resource": ["*"],
        }]},
    )]}
    some msg in deny with input as plan
    contains(msg, "EFEX-OPA-001")
}

# ---- Pass fixtures (deny must be empty) -----------------------------------

test_allows_scoped_policy if {
    plan := {"resource_changes": [_policy_resource(
        "aws_iam_policy.scoped",
        {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": ["arn:aws:s3:::efex-payments-archive/*"],
        }]},
    )]}
    count(deny) == 0 with input as plan
}

test_ignores_wildcard_on_deny_statement if {
    # An explicit Deny on * is a guardrail, not a privilege grant.
    plan := {"resource_changes": [_policy_resource(
        "aws_iam_policy.deny_all",
        {"Version": "2012-10-17", "Statement": [{
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
        }]},
    )]}
    count(deny) == 0 with input as plan
}
