#!/usr/bin/env bash
# Adapter: trivy image (layer = container). See ../README.md for the contract.
# Adapter owns image build so the scanner is self-contained.
set -euo pipefail

INPUTS="${1:?json inputs required}"
OUT="${OUTPUT_DIR:?OUTPUT_DIR must be set}/${SCANNER_ID:?SCANNER_ID must be set}.sarif"

CONTEXT=$(echo "$INPUTS" | jq -r '.build_context')
IMAGE=$(echo "$INPUTS" | jq -r '.image_ref')

docker build -t "$IMAGE" "$CONTEXT"

trivy image \
  --scanners vuln,secret,misconfig \
  --severity CRITICAL,HIGH,MEDIUM \
  --format sarif \
  --output "$OUT" \
  --exit-code 0 \
  "$IMAGE"
