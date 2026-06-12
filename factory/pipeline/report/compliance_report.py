"""Compliance report generator for the EFEX Secure Software Factory.

Walks every ``*.sarif`` under ``--evidence-dir``, computes pass/fail per
registered policy and scanner (from ``policies/catalog.yaml``), and emits a
per-framework coverage report for every controls file under
``--controls-dir``.

Status semantics per control:
  - PASSING    : every policy/scanner claiming this control passed
  - FAILING    : at least one policy/scanner claiming this control failed
  - PARTIAL    : mixed pass/fail across covering items (or some did not run)
  - UNCOVERED  : no policy/scanner in the catalog claims this control

This is the auditor-facing artifact. The pipeline gate (`evaluate_gate.py`)
decides if the build blocks; this report decides what the build *proved*.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable

SEVERITY_RANK = {
    "NOTE": 0, "LOW": 1, "MEDIUM": 2, "MODERATE": 2,
    "HIGH": 3, "ERROR": 4, "CRITICAL": 4,
}

# Different control YAML files use domain-specific top-level keys.
CONTROL_LIST_KEYS = ("controls", "requirements", "criteria", "articles")


@dataclasses.dataclass
class PolicyStatus:
    id: str
    kind: str          # "policy" | "scanner"
    status: str        # PASSING | FAILING | UNRUN
    failing_findings: int = 0


def load_yaml(path: Path) -> dict:
    import yaml
    return yaml.safe_load(path.read_text()) or {}


def iter_sarif_findings(path: Path) -> Iterable[dict]:
    try:
        doc = json.loads(path.read_text() or "{}")
    except json.JSONDecodeError:
        return
    for run in doc.get("runs", []):
        tool = (run.get("tool") or {}).get("driver", {}).get("name", path.stem)
        for result in run.get("results", []):
            level = (result.get("level") or "warning").upper()
            properties = result.get("properties") or {}
            severity = (
                properties.get("severity")
                or properties.get("security-severity")
                or {"ERROR": "CRITICAL", "WARNING": "HIGH",
                    "NOTE": "LOW", "NONE": "LOW"}.get(level, level)
            )
            if isinstance(severity, (int, float)):
                severity = "HIGH" if severity >= 7 else "MEDIUM"
            yield {
                "tool": tool,
                "rule": result.get("ruleId") or "UNKNOWN",
                "severity": (severity or "MEDIUM").upper(),
                "file": str(path),
            }


def compute_policy_statuses(
    catalog: dict, evidence_dir: Path, severity_floor: str
) -> dict[str, PolicyStatus]:
    floor = SEVERITY_RANK[severity_floor]
    statuses: dict[str, PolicyStatus] = {}

    # 1. Custom policies: ruleId equals policy id (per our catalog convention).
    rule_failure_count: dict[str, int] = defaultdict(int)
    for sarif in evidence_dir.rglob("*.sarif"):
        for finding in iter_sarif_findings(sarif):
            if SEVERITY_RANK.get(finding["severity"], 0) >= floor:
                rule_failure_count[finding["rule"]] += 1

    for policy in catalog.get("policies", []) or []:
        pid = policy["id"]
        n = rule_failure_count.get(pid, 0)
        statuses[pid] = PolicyStatus(
            id=pid, kind="policy",
            status="FAILING" if n else "PASSING",
            failing_findings=n,
        )

    # 2. Scanner-level: SCANNER:<scanner-id> maps to evidence/<scanner-id>.sarif.
    for scanner in catalog.get("scanners", []) or []:
        sid = scanner["id"]
        short = sid.removeprefix("SCANNER:")
        candidates = list(evidence_dir.rglob(f"{short}.sarif"))
        if not candidates:
            statuses[sid] = PolicyStatus(id=sid, kind="scanner", status="UNRUN")
            continue
        n = sum(
            1 for c in candidates for f in iter_sarif_findings(c)
            if SEVERITY_RANK.get(f["severity"], 0) >= floor
        )
        statuses[sid] = PolicyStatus(
            id=sid, kind="scanner",
            status="FAILING" if n else "PASSING",
            failing_findings=n,
        )

    return statuses


def build_control_index(catalog: dict) -> dict[str, dict[str, list[str]]]:
    """{framework_name -> {control_id -> [policy_ids that cover it]}}"""
    index: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for source in ("policies", "scanners"):
        for entry in catalog.get(source, []) or []:
            for framework, ids in (entry.get("controls") or {}).items():
                for cid in ids or []:
                    index[framework][str(cid)].append(entry["id"])
    return index


def framework_results(
    framework_key: str,
    controls_doc: dict,
    index: dict[str, dict[str, list[str]]],
    statuses: dict[str, PolicyStatus],
) -> list[dict]:
    items: list[dict] = []
    list_key = next((k for k in CONTROL_LIST_KEYS if k in controls_doc), None)
    if not list_key:
        return items
    by_control = index.get(framework_key, {})
    for control in controls_doc[list_key]:
        cid = str(control["id"])
        covering = by_control.get(cid, [])
        if not covering:
            status = "UNCOVERED"
        else:
            policy_statuses = [statuses.get(pid).status if statuses.get(pid)
                               else "UNRUN" for pid in covering]
            if any(s == "FAILING" for s in policy_statuses):
                status = "FAILING"
            elif all(s == "PASSING" for s in policy_statuses):
                status = "PASSING"
            else:
                status = "PARTIAL"
        items.append({
            "id": cid,
            "title": control.get("title", ""),
            "status": status,
            "covered_by": covering,
            "gaps": control.get("gaps") or [],
        })
    return items


FRAMEWORK_FILE_TO_KEY = {
    "iso27001.yaml": "iso27001",
    "pci-dss.yaml": "pci_dss",
    "soc2.yaml": "soc2",
    "cnbv-cub.yaml": "cnbv_cub",
}


def to_markdown(report: dict) -> str:
    lines: list[str] = []
    lines.append("# Compliance Report")
    lines.append("")
    lines.append(f"- Build SHA: `{report['build']['sha']}`")
    lines.append(f"- Generated: {report['build']['generated_at']}")
    lines.append(f"- Severity floor: {report['build']['severity_floor']}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Framework | Total | [OK] Passing | [X] Failing | [!] Partial |  Uncovered |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for fw in report["frameworks"]:
        c = fw["counts"]
        lines.append(f"| {fw['title']} | {c['total']} | {c['PASSING']} | "
                     f"{c['FAILING']} | {c['PARTIAL']} | {c['UNCOVERED']} |")
    lines.append("")

    for fw in report["frameworks"]:
        lines.append(f"## {fw['title']}")
        lines.append("")
        lines.append("| Control | Title | Status | Covered by |")
        lines.append("|---|---|---|---|")
        for item in fw["controls"]:
            badge = {"PASSING": "[OK]", "FAILING": "[X]",
                     "PARTIAL": "[!]", "UNCOVERED": ""}[item["status"]]
            covering = ", ".join(f"`{p}`" for p in item["covered_by"]) or "--"
            lines.append(f"| `{item['id']}` | {item['title']} | "
                         f"{badge} {item['status']} | {covering} |")
        lines.append("")

    lines.append("## Policy / Scanner statuses")
    lines.append("")
    lines.append("| ID | Kind | Status | Failing findings |")
    lines.append("|---|---|---|---:|")
    for s in report["statuses"]:
        lines.append(f"| `{s['id']}` | {s['kind']} | {s['status']} | "
                     f"{s.get('failing_findings', 0)} |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--evidence-dir", required=True, type=Path)
    p.add_argument("--catalog", required=True, type=Path,
                   help="factory/policies/catalog.yaml")
    p.add_argument("--controls-dir", required=True, type=Path,
                   help="factory/controls/")
    p.add_argument("--severity-floor", default="HIGH",
                   choices=list(SEVERITY_RANK))
    p.add_argument("--output", required=True, type=Path,
                   help="markdown output path")
    p.add_argument("--json", dest="json_out", type=Path,
                   help="JSON output path (optional)")
    p.add_argument("--build-sha", default=os.environ.get("COMMIT_SHA", "local"))
    args = p.parse_args()

    catalog = load_yaml(args.catalog)
    statuses = compute_policy_statuses(catalog, args.evidence_dir,
                                       args.severity_floor)
    index = build_control_index(catalog)

    frameworks_out = []
    for filename, framework_key in FRAMEWORK_FILE_TO_KEY.items():
        path = args.controls_dir / filename
        if not path.exists():
            continue
        doc = load_yaml(path)
        items = framework_results(framework_key, doc, index, statuses)
        counts = {"PASSING": 0, "FAILING": 0, "PARTIAL": 0, "UNCOVERED": 0}
        for it in items:
            counts[it["status"]] += 1
        counts["total"] = len(items)
        frameworks_out.append({
            "key": framework_key,
            "title": doc.get("framework", framework_key),
            "controls": items,
            "counts": counts,
        })

    report = {
        "build": {
            "sha": args.build_sha,
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(
                timespec="seconds"),
            "severity_floor": args.severity_floor,
        },
        "frameworks": frameworks_out,
        "statuses": [dataclasses.asdict(s) for s in statuses.values()],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(to_markdown(report))
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2))

    # Print a one-line summary so it lands in CI logs.
    totals = {"PASSING": 0, "FAILING": 0, "PARTIAL": 0, "UNCOVERED": 0}
    for fw in frameworks_out:
        for k in totals:
            totals[k] += fw["counts"][k]
    print(f"Compliance: {totals['PASSING']} passing * "
          f"{totals['FAILING']} failing * {totals['PARTIAL']} partial * "
          f"{totals['UNCOVERED']} uncovered across {len(frameworks_out)} frameworks.")
    print(f"Report written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
