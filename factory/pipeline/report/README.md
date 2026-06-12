# Compliance report generator

Turns scanner SARIF + the policy/control catalog into an auditor-facing
report on **which controls each build proved**.

## Inputs

| Source | Role |
|---|---|
| `evidence/*.sarif` (from the scan jobs) | What the build found. |
| `factory/policies/catalog.yaml` | Map: each policy/scanner -> control IDs it satisfies, per framework. |
| `factory/controls/*.yaml` | Per-framework control inventory + acknowledged gaps. |

## Outputs

- `report.md` -- human-readable, one summary table + one table per
  framework. Suitable to attach to an audit PBC ("Provided by Client")
  request.
- `report.json` (optional, with `--json`) -- machine-readable, same shape;
  feeds a SIEM/dashboard later.

## Status semantics (per control)

| Status | When |
|---|---|
| `PASSING` | every policy/scanner claiming this control passed |
| `FAILING` | at least one policy/scanner claiming this control failed |
| `PARTIAL` | mixed pass/fail across covering items, or some did not run |
| `UNCOVERED` | no policy/scanner in the catalog claims this control |

## Relationship to the gate

The gate (`pipeline/gate/evaluate_gate.py`) decides whether a build *blocks*.
This report decides what the build *proved*. They run independently; a
build can block while the report still ships, and vice versa, by design --
audit evidence should be produced even on failed builds so reviewers can
see the failure mode.

## Local run

```bash
python3 factory/pipeline/report/compliance_report.py \
  --evidence-dir evidence \
  --catalog factory/policies/catalog.yaml \
  --controls-dir factory/controls \
  --output report.md \
  --json report.json
```

## Extending

- Add a framework: drop a new `controls/<framework>.yaml`, add an entry to
  `FRAMEWORK_FILE_TO_KEY` in `compliance_report.py`, reuse the same
  `controls.<framework_key>` schema in `policies/catalog.yaml`.
- Add a policy or scanner: register it in `catalog.yaml` under `policies:`
  or `scanners:` with `controls:` listing the IDs it satisfies. No code
  changes needed.
