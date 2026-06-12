#!/usr/bin/env bash
# Adapter: trivy fs (layer = sca). See ../README.md for the contract.
set -euo pipefail

INPUTS="${1:?json inputs required}"
OUT="${OUTPUT_DIR:?OUTPUT_DIR must be set}/${SCANNER_ID:?SCANNER_ID must be set}.sarif"

TARGET=$(echo "$INPUTS" | jq -r '.path')

trivy fs \
  --scanners vuln,secret,misconfig \
  --severity CRITICAL,HIGH,MEDIUM \
  --format sarif \
  --output "$OUT" \
  --exit-code 0 \
  "$TARGET"
