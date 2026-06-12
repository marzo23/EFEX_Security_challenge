#!/usr/bin/env bash
# Adapter: gitleaks (layer = secrets). See ../README.md for the contract.
set -euo pipefail

INPUTS="${1:?json inputs required}"
OUT="${OUTPUT_DIR:?OUTPUT_DIR must be set}/${SCANNER_ID:?SCANNER_ID must be set}.sarif"

SOURCE=$(echo "$INPUTS" | jq -r '.source // "."')

gitleaks detect \
  --source "$SOURCE" \
  --report-format sarif \
  --report-path "$OUT" \
  --exit-code 0 \
  --no-banner
