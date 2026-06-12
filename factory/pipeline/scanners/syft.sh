#!/usr/bin/env bash
# Adapter: syft (layer = supply-chain SBOM).
# Produces a CycloneDX SBOM AND an empty SARIF so the gate sees an entry
# for this scanner. The SBOM itself is uploaded as an artifact.
set -euo pipefail

INPUTS="${1:?json inputs required}"
SARIF_OUT="${OUTPUT_DIR:?OUTPUT_DIR must be set}/${SCANNER_ID:?SCANNER_ID must be set}.sarif"
SBOM_OUT="${OUTPUT_DIR}/${SCANNER_ID}.cdx.json"

TARGET=$(echo "$INPUTS" | jq -r '.target')
FORMAT=$(echo "$INPUTS" | jq -r '.format // "cyclonedx-json"')
BUILD_CONTEXT=$(echo "$INPUTS" | jq -r '.build_context // ""')

# Matrix cells are isolated runners: an image built in the container-image
# cell does not exist here. When the target is an image, this adapter owns
# the build (same pattern as trivy-image.sh).
if [ -n "$BUILD_CONTEXT" ]; then
  docker build -t "$TARGET" "$BUILD_CONTEXT"
fi

syft "$TARGET" --output "${FORMAT}=$SBOM_OUT"

cat > "$SARIF_OUT" <<EOF
{
  "version": "2.1.0",
  "\$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [{
    "tool": {"driver": {"name": "syft", "informationUri": "https://github.com/anchore/syft"}},
    "results": [],
    "invocations": [{"executionSuccessful": true, "exitCode": 0}]
  }]
}
EOF
