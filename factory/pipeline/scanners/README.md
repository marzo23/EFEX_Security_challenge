# Scanner adapters

Each file in this directory wraps a single tool so the rest of the system
never has to know which tool is running. This is the swap point.

## Contract

Every adapter MUST:

1. Accept a single positional argument: a JSON blob (the `inputs:` block
   from `pipeline/config.yaml`, with `${VARS}` expanded).
2. Read `SCANNER_ID` and `OUTPUT_DIR` from the environment.
3. Produce exactly one SARIF file at `${OUTPUT_DIR}/${SCANNER_ID}.sarif`.
4. Exit 0 on success **even when findings exist**. Severity gating belongs
   to `pipeline/gate/evaluate_gate.py`, not the adapter -- this keeps the
   pipeline's "what blocks" decision in one place.
5. Be idempotent and side-effect-free outside `OUTPUT_DIR` (except for
   tool caches, which CI handles).

## Skeleton

```bash
#!/usr/bin/env bash
set -euo pipefail
INPUTS="${1:?json inputs required}"
OUT="${OUTPUT_DIR:?OUTPUT_DIR must be set}/${SCANNER_ID:?SCANNER_ID must be set}.sarif"

# parse inputs with jq, run the tool, write SARIF to $OUT
```

## Why this shape

- **CI-agnostic.** Adapters are plain shell. GitHub Actions, GitLab CI,
  Jenkins, or a local dev run can all call them with no changes.
- **Tool-agnostic upstream.** The gate doesn't know which tool produced a
  finding -- it only reads SARIF. Trivy -> Grype, Semgrep -> CodeQL: same
  downstream.
- **Single error mode.** Adapter problems (network, missing binary, bad
  inputs) exit non-zero and kill the job loudly. Findings never do -- the
  gate is the only authority on "this build blocks."
