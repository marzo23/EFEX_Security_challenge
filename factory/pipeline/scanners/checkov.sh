#!/usr/bin/env bash
# Adapter: checkov (layer = iac defaults + custom Python checks).
# See ../README.md for the contract.
set -euo pipefail

INPUTS="${1:?json inputs required}"
OUT="${OUTPUT_DIR:?OUTPUT_DIR must be set}/${SCANNER_ID:?SCANNER_ID must be set}.sarif"

DIR=$(echo "$INPUTS" | jq -r '.directory')
FRAMEWORKS=$(echo "$INPUTS" | jq -r '.frameworks | join(",")')
EXTERNAL=$(echo "$INPUTS" | jq -r '.external_checks_dir // ""')

EXTERNAL_ARG=()
if [ -n "$EXTERNAL" ]; then
  EXTERNAL_ARG=(--external-checks-dir "$EXTERNAL")
fi

# --soft-fail makes Checkov exit 0 on policy findings (gate is the
# authority on blocking). We rely on the SARIF file being non-empty to
# distinguish "checkov ran cleanly" from "checkov crashed and emitted
# nothing"; verified after the run below.
checkov \
  --directory "$DIR" \
  --framework "$FRAMEWORKS" \
  --output sarif \
  --output-file-path "$OUT" \
  --soft-fail \
  "${EXTERNAL_ARG[@]}"

# Checkov writes to a directory when --output-file-path is a path-without-extension;
# normalize to a single file the gate expects.
if [ -d "$OUT" ]; then
  mv "$OUT/results_sarif.sarif" "${OUT}.tmp"
  rm -rf "$OUT"
  mv "${OUT}.tmp" "$OUT"
fi

# Sanity-check: the SARIF must at least parse and contain a runs[] array.
# A silent crash that left a half-written file would otherwise be reported
# as "no findings" by the gate.
python3 - "$OUT" <<'PY'
import json, sys
try:
    doc = json.loads(open(sys.argv[1]).read())
    assert isinstance(doc.get("runs"), list), "no runs[] in SARIF"
except Exception as e:
    print(f"::error::checkov SARIF malformed: {e}", file=sys.stderr)
    sys.exit(2)
PY
