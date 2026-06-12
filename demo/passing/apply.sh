#!/usr/bin/env bash
# Flip the factory tree from the failing seed to the passing (remediated)
# state. This is a one-way `cp -r` over the files under demo/passing/factory/.
# Use `git diff` or `diff -r factory demo/passing/factory` before running to
# preview the change set.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

cat <<'WARN'
[!]  This will overwrite files under factory/ with their remediated versions.
   Press Ctrl-C within 3 seconds to abort.
WARN
sleep 3

cp -Rv "$HERE/factory/" "$REPO_ROOT/factory/"
echo " Passing state applied. Re-run the pipeline to confirm:"
echo "  factory/pipeline/run-scanner.sh <scanner-id>"
echo "  python3 factory/pipeline/gate/evaluate_gate.py --evidence-dir evidence --fail-on CRITICAL,HIGH"
