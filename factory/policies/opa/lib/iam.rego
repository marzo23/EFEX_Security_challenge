# Shared IAM predicates, cloud-agnostic.
#
# The per-cloud rule files (opa/aws/iam.rego, opa/gcp/iam.rego, ...) import
# from this package so the *intent* of a rule ("no wildcard action with
# wildcard resource") lives in one place. Per-cloud files only have to
# encode how that intent maps to their resource schema.

package efex.lib.iam

import rego.v1

# wildcard_action(action) -- true if `action` is "*" or a list containing "*"
wildcard_action(action) if action == "*"
wildcard_action(action) if "*" in action

# wildcard_resource(resource) -- same shape
wildcard_resource(resource) if resource == "*"
wildcard_resource(resource) if "*" in resource

# allow_statement(stmt) -- true if the statement has Effect=Allow
allow_statement(stmt) if stmt.Effect == "Allow"
