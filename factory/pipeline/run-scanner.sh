#!/usr/bin/env bash
# Dispatcher -- reads pipeline/config.yaml, finds the scanner by id, and
# invokes its adapter with the configured inputs.
#
# This is the only piece of glue between config and adapters. The GitHub
# Actions workflow calls it once per matrix cell; a future GitLab or
# Jenkins job would call it the same way.
#
# Usage:  run-scanner.sh <scanner-id>
#
# Env:
#   OUTPUT_DIR   (default: ./evidence)
#   COMMIT_SHA   (default: $(git rev-parse --short HEAD))

set -euo pipefail

SCANNER_ID="${1:?scanner id required}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
CONFIG="$HERE/config.yaml"

export OUTPUT_DIR="${OUTPUT_DIR:-$REPO_ROOT/evidence}"
export COMMIT_SHA="${COMMIT_SHA:-$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo local)}"
mkdir -p "$OUTPUT_DIR"

# Pull the scanner entry as JSON so adapters get a stable input format.
ENTRY=$(yq -o=json ".scanners[] | select(.id == \"$SCANNER_ID\")" "$CONFIG")
if [ -z "$ENTRY" ] || [ "$ENTRY" = "null" ]; then
  echo "::error::scanner '$SCANNER_ID' not found in $CONFIG" >&2
  exit 2
fi

ADAPTER_REL=$(echo "$ENTRY" | jq -r '.adapter')
ADAPTER="$HERE/$ADAPTER_REL"
if [ ! -x "$ADAPTER" ]; then
  echo "::error::adapter not found or not executable: $ADAPTER" >&2
  exit 2
fi

INPUTS=$(echo "$ENTRY" | jq -c '.inputs // {}' | envsubst)
export SCANNER_ID
echo " $SCANNER_ID -> $ADAPTER_REL"
echo "  inputs: $INPUTS"
exec "$ADAPTER" "$INPUTS"
