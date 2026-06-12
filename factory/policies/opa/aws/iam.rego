# EFEX custom OPA policies -- AWS IAM.
#
# Cross-cloud structure: the *intent* of each rule lives in
# factory/policies/opa/lib/. This file only encodes how that intent maps to
# AWS's Terraform resource schema. To enforce the same rule on GCP, add
# factory/policies/opa/gcp/iam.rego that imports from the same lib.
#
# Tests: see iam_test.rego in this directory. Run with:
#   conftest verify --policy factory/policies/opa/aws --policy factory/policies/opa/lib

package main

import rego.v1

import data.efex.lib.iam as iam

# --------------------------------------------------------------------------
# EFEX-OPA-001 -- IAM policies must not grant Action="*" Resource="*" Allow.
# Catalog: factory/policies/catalog.yaml
# --------------------------------------------------------------------------
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy"
    doc := json.unmarshal(resource.change.after.policy)
    stmt := doc.Statement[_]
    iam.allow_statement(stmt)
    iam.wildcard_action(stmt.Action)
    iam.wildcard_resource(stmt.Resource)
    msg := sprintf(
        "EFEX-OPA-001 [CRITICAL]: %s grants Action=* with Resource=* (Allow). Forbidden in prod.",
        [resource.address],
    )
}
