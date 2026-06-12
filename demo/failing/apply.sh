#!/usr/bin/env bash
# Flip the factory tree BACK to the deliberately-failing seed state.
#
# Use this to undo `demo/passing/apply.sh` without needing git. This is a
# one-way `cp -r` over the files under demo/failing/factory/, restoring
# the vulnerable service/Dockerfile/Terraform that the gate is meant to
# block on. Use `git diff` or `diff -r factory demo/failing/factory`
# beforehand to preview the change set.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

cat <<'WARN'
[!]  This will overwrite files under factory/ with their *vulnerable* (failing
   seed) versions. Press Ctrl-C within 3 seconds to abort.
WARN
sleep 3

cp -Rv "$HERE/factory/" "$REPO_ROOT/factory/"
echo " Failing state applied. Re-run the pipeline to confirm:"
echo "  factory/pipeline/run-scanner.sh <scanner-id>"
echo "  python3 factory/pipeline/gate/evaluate_gate.py --evidence-dir evidence --fail-on CRITICAL,HIGH"
