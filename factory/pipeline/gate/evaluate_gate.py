"""Quality-gate evaluator for the EFEX Secure Software Factory.

Walks every ``*.sarif`` under ``--evidence-dir`` and exits non-zero if
any finding at or above ``--fail-on`` severity is present.

Dependency-free except for PyYAML (so we stay auditable in one screen).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

SEVERITY_ORDER = ["NOTE", "LOW", "MEDIUM", "MODERATE", "HIGH", "CRITICAL", "ERROR"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

SARIF_LEVEL_TO_SEVERITY = {
    "ERROR": "CRITICAL",
    "WARNING": "HIGH",
    "NOTE": "LOW",
    "NONE": "LOW",
}


def normalize_severity(properties: dict, level: str) -> str:
    """Resolve a finding's severity label.

    Precedence: an explicit severity *label* in properties, then GitHub's
    ``security-severity`` convention (a CVSS score string like "9.8" that
    must be bucketed numerically), then the SARIF level.
    """
    label = properties.get("severity")
    if isinstance(label, str) and label.upper() in SEVERITY_RANK:
        return label.upper()
    score = properties.get("security-severity")
    try:
        score = float(score)
    except (TypeError, ValueError):
        score = None
    if score is not None:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
    return SARIF_LEVEL_TO_SEVERITY.get(level, level)


def expected_scanner_ids(config_path: Path) -> list[str]:
    """Scanner ids from pipeline config -- the gate's coverage contract."""
    if not config_path.exists():
        print(f"::error::pipeline config not found: {config_path}")
        raise SystemExit(2)
    import yaml

    config = yaml.safe_load(config_path.read_text()) or {}
    return [s["id"] for s in config.get("scanners") or [] if s.get("id")]


def sarif_findings(path: Path):
    try:
        doc = json.loads(path.read_text() or "{}")
    except json.JSONDecodeError as exc:
        print(f"::warning::could not parse {path}: {exc}")
        return
    for run in doc.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", path.stem)
        for result in run.get("results", []):
            rule_id = result.get("ruleId") or "UNKNOWN"
            level = (result.get("level") or "warning").upper()
            # SARIF-rich tools (Checkov, Semgrep) may put severity in properties.
            properties = result.get("properties") or {}
            severity = normalize_severity(properties, level)
            locs = result.get("locations") or [{}]
            uri = (
                locs[0]
                .get("physicalLocation", {})
                .get("artifactLocation", {})
                .get("uri", "")
            )
            yield {
                "tool": tool,
                "rule": rule_id,
                "severity": severity,
                "where": uri,
            }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--evidence-dir", required=True, type=Path)
    p.add_argument("--fail-on", default="CRITICAL,HIGH")
    p.add_argument(
        "--config",
        type=Path,
        help="pipeline config.yaml; when given, a missing <scanner>.sarif "
        "fails the gate (a crashed scanner must never be a silent pass)",
    )
    args = p.parse_args()

    threshold = min(
        SEVERITY_RANK[s] for s in args.fail_on.split(",") if s in SEVERITY_RANK
    )

    blocking: list[dict] = []
    total = 0

    sarifs = sorted(args.evidence_dir.rglob("*.sarif"))
    if not sarifs:
        print(f"::error::no SARIF files under {args.evidence_dir}")
        return 2

    if args.config:
        present = {s.stem for s in sarifs}
        missing = [i for i in expected_scanner_ids(args.config) if i not in present]
        if missing:
            for scanner_id in missing:
                print(f"::error::scanner '{scanner_id}' produced no SARIF -- "
                      "its layer ran with zero coverage")
            return 2

    for sarif in sarifs:
        for finding in sarif_findings(sarif):
            total += 1
            rank = SEVERITY_RANK.get(finding["severity"], 0)
            if rank < threshold:
                continue
            blocking.append(finding)

    print(f"Evidence: {total} findings scanned across {len(sarifs)} SARIF files; "
          f"{len(blocking)} blocking.")
    for f in blocking:
        print(f"  BLOCK  {f['severity']:>8}  {f['tool']:<15} {f['rule']}  {f['where']}")

    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
