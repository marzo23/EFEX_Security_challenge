#!/usr/bin/env bash
# Adapter: semgrep (layer = sast). See ../README.md for the contract.
set -euo pipefail

INPUTS="${1:?json inputs required}"
OUT="${OUTPUT_DIR:?OUTPUT_DIR must be set}/${SCANNER_ID:?SCANNER_ID must be set}.sarif"

PATHS=$(echo "$INPUTS" | jq -r '.paths[]' | tr '\n' ' ')
CONFIG_ARGS=$(echo "$INPUTS" | jq -r '.configs[] | "--config=" + .' | tr '\n' ' ')

# Semgrep exit semantics with --error:
#   0 = ran clean, no blocking findings
#   1 = findings (expected -- the gate is the blocking authority)
#   2+ = tool/config error (must propagate; "crashed" is not "no findings")
set +e
# shellcheck disable=SC2086
semgrep scan \
  $CONFIG_ARGS \
  --sarif --output "$OUT" \
  --error \
  --metrics=off \
  $PATHS
SEMGREP_EXIT=$?
set -e
if [ "$SEMGREP_EXIT" -gt 1 ]; then
  echo "::error::semgrep tool error (exit $SEMGREP_EXIT); aborting adapter" >&2
  exit "$SEMGREP_EXIT"
fi
