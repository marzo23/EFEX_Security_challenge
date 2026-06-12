#!/usr/bin/env bash
# Adapter: conftest / OPA (layer = iac custom policy).
# Adapter owns terraform plan generation so the scanner is self-contained.
# See ../README.md for the contract.
set -euo pipefail

INPUTS="${1:?json inputs required}"
OUT="${OUTPUT_DIR:?OUTPUT_DIR must be set}/${SCANNER_ID:?SCANNER_ID must be set}.sarif"

TF_DIR=$(echo "$INPUTS" | jq -r '.terraform_dir')
POLICY_DIR=$(echo "$INPUTS" | jq -r '.policy_dir')
LIB_DIRS=$(echo "$INPUTS" | jq -r '.lib_dirs[]?' || true)

# Rego helper libraries are modules, not facts -- they must load via
# --policy (conftest's --data is for JSON/YAML data files only).
LIB_ARGS=()
for lib in $LIB_DIRS; do
  LIB_ARGS+=(--policy "$lib")
done

# 1. terraform plan -> json. Tool failures here must kill the adapter
#    (they're not "no findings"; they're "we didn't even run the policies").
#
# The scan cell has no AWS credentials by design (least privilege: policy
# evaluation must never touch a live account). A *_override.tf with mock
# credentials + skip flags lets the provider configure offline; the plan is
# only ever fed to conftest, never applied.
OVERRIDE="$TF_DIR/efex_policy_scan_override.tf"
cat > "$OVERRIDE" <<'HCL'
# Written by scanners/conftest.sh for offline policy scanning. Never applied.
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "mock-policy-scan"
  secret_key                  = "mock-policy-scan"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
}
HCL
trap 'rm -f "$OVERRIDE"' EXIT

pushd "$TF_DIR" >/dev/null
terraform init -backend=false -input=false >/dev/null
terraform plan -out=plan.bin -input=false -refresh=false
terraform show -json plan.bin > plan.json
popd >/dev/null

# 2. conftest test -> JSON. Conftest exit semantics:
#    0 = no policy violations
#    1 = policy violations found (expected; we still want the SARIF)
#    2 = tool / parse error (treat as adapter failure)
RAW="$OUTPUT_DIR/${SCANNER_ID}.conftest.json"
set +e
conftest test \
  --policy "$POLICY_DIR" \
  "${LIB_ARGS[@]}" \
  --output json \
  "$TF_DIR/plan.json" > "$RAW"
CONFTEST_EXIT=$?
set -e
if [ "$CONFTEST_EXIT" -gt 1 ]; then
  echo "::error::conftest tool error (exit $CONFTEST_EXIT); aborting adapter" >&2
  exit "$CONFTEST_EXIT"
fi

# Minimal SARIF wrapper. The gate is tolerant of varied SARIF structures.
# We put the Terraform resource address (e.g. aws_iam_policy.wildcard_admin)
# in the location URI so reviewers see the specific resource, not just
# the plan filename.
python3 - "$RAW" "$OUT" <<'PY'
import json, re, sys
raw = json.loads(open(sys.argv[1]).read() or "[]")
ADDR_RE = re.compile(r"\b([a-z][a-z0-9_]+\.[A-Za-z0-9_-]+)\b")
results = []
for file_entry in raw:
    for failure in file_entry.get("failures") or []:
        msg = failure.get("msg","")
        rule = (failure.get("metadata") or {}).get("id") or msg[:64]
        m = ADDR_RE.search(msg)
        uri = m.group(1) if m else file_entry.get("filename","")
        results.append({
            "ruleId": rule,
            "level": "error",
            "message": {"text": msg},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri}
            }}],
        })
sarif = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{
        "tool": {"driver": {"name": "conftest", "informationUri": "https://www.conftest.dev/"}},
        "results": results,
        "invocations": [{"executionSuccessful": True}],
    }],
}
open(sys.argv[2], "w").write(json.dumps(sarif, indent=2))
PY
