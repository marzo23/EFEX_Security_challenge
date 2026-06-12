"""Forward the per-build compliance report to the SIEM webhook.

Minimal, dependency-free sink (stdlib only): POSTs ``report.json`` plus
build metadata to ``$SIEM_WEBHOOK_URL``. Failure to deliver is a real
error (exit 1) -- evidence sinks must not fail silently -- but the workflow
step only runs when the webhook secret is configured.

Usage:
    SIEM_WEBHOOK_URL=https://siem.example/ingest \\
    python3 siem_forward.py --report compliance/report.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--report", required=True, help="path to report.json")
    p.add_argument("--timeout", type=int, default=15)
    args = p.parse_args()

    url = os.environ.get("SIEM_WEBHOOK_URL")
    if not url:
        print("::error::SIEM_WEBHOOK_URL is not set", file=sys.stderr)
        return 1
    if not url.startswith("https://"):
        print("::error::SIEM webhook must be https", file=sys.stderr)
        return 1

    with open(args.report) as fh:
        report = json.load(fh)

    event = {
        "source": "efex-secure-software-factory",
        "event_type": "compliance_report",
        "commit_sha": os.environ.get("COMMIT_SHA", "unknown"),
        "workflow_run": os.environ.get("GITHUB_RUN_ID", "local"),
        "repository": os.environ.get("GITHUB_REPOSITORY", "local"),
        "report": report,
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(event).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            print(f"SIEM webhook accepted the report (HTTP {resp.status})")
    except urllib.error.URLError as exc:
        print(f"::error::SIEM forwarding failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
