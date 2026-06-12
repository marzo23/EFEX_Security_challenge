# Failing / Passing Demo

The factory ships with a deliberately broken `factory/service/` and
`factory/infra/aws/terraform/` so the pipeline's blocking behaviour is
demonstrable on first run.

| State | Canonical location | Snapshot | Flip script |
|---|---|---|---|
| [X] **Failing** | `factory/` on `main` (today) | `demo/failing/factory/` | `demo/failing/apply.sh` |
| [OK] **Passing** | -- (apply to overwrite) | `demo/passing/factory/` | `demo/passing/apply.sh` |

Both directions are idempotent `cp -Rv` operations over the seed files
(`service/` + `infra/aws/terraform/`); the always-good platform infra
(`infra/aws/platform/`, the evidence bucket) is left alone in either
direction.

## How to switch -- round trip

```bash
# preview what would change
diff -r factory demo/passing/factory

# flip to passing
demo/passing/apply.sh

# re-run the pipeline locally; gate should pass
factory/pipeline/run-scanner.sh secrets         # ...or any other scanner id
python3 factory/pipeline/gate/evaluate_gate.py \
  --evidence-dir evidence \
  --fail-on CRITICAL,HIGH

# flip back to failing (restores the vulnerable seed)
demo/failing/apply.sh
```

## What's in `demo/passing/`

| File | VULNs it fixes |
|---|---|
| `factory/service/app/main.py` | VULN-001 (hardcoded secrets), VULN-002 (SQLi), VULN-003 (cmd injection) |
| `factory/service/requirements.txt` | VULN-004 (pyyaml CVE), VULN-005 (requests CVE) |
| `factory/service/Dockerfile` | VULN-006 (floating tag), VULN-007 (root user), VULN-008 (no healthcheck) |
| `factory/infra/aws/terraform/main.tf` | VULN-010 (no SSE), VULN-011 (public bucket), VULN-012 (wildcard IAM), VULN-013 (open SSH) |

See [`passing/README.md`](./passing/README.md) for line-by-line remediation
notes per VULN, and [`passing/sample-compliance-report.md`](./passing/sample-compliance-report.md)
for what the auditor sees after the flip.
