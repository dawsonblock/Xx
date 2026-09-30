from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .jev import JevAdvisor


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="aide-rsi-jev", description="AIDE-DREAM-RSI JEV integration tools"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_doctor = sub.add_parser("doctor", help="verify typed SystemOne connectivity")
    p_doctor.add_argument("--endpoint", default="http://127.0.0.1:8090/v1/systemone")
    p_doctor.add_argument("--model", default="local-jev-fabric")
    p_doctor.add_argument("--api-key-env", default="FABRIC_API_KEY")
    p_doctor.add_argument("--timeout", type=float, default=1.5)

    sub.add_parser("vendor-path", help="print the bundled LocalJevFabric source path")

    p_report = sub.add_parser("report", help="summarize JEV advisory JSONL evidence")
    p_report.add_argument(
        "path", type=Path, help="a jev_advisory.jsonl file or a log directory"
    )

    args = parser.parse_args()
    if args.cmd == "vendor-path":
        root = Path(__file__).resolve().parents[2]
        path = root / "vendor" / "LocalJevFabric-v1.5.0"
        print(path)
        return

    if args.cmd == "report":
        files = (
            [args.path]
            if args.path.is_file()
            else sorted(args.path.rglob("jev_advisory.jsonl"))
        )
        rows = []
        for file in files:
            for line in file.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(row, dict):
                    rows.append(row)
        by_event = {}
        confidences = []
        errors = 0
        action_agree = []
        for row in rows:
            event = str(row.get("event", "unknown"))
            by_event[event] = by_event.get(event, 0) + 1
            advice = row.get("advice") or {}
            if isinstance(advice, dict):
                if advice.get("error"):
                    errors += 1
                try:
                    confidences.append(float(advice.get("confidence", 0.0)))
                except (TypeError, ValueError):
                    pass
            if event == "action_ranking_shadow":
                meta = row.get("metadata") or {}
                if isinstance(meta, dict) and "agreement" in meta:
                    action_agree.append(bool(meta["agreement"]))
        report = {
            "files": len(files),
            "rows": len(rows),
            "events": by_event,
            "errors": errors,
            "mean_confidence": (
                (sum(confidences) / len(confidences)) if confidences else None
            ),
            "action_top1_agreement": (
                (sum(action_agree) / len(action_agree)) if action_agree else None
            ),
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return

    advisor = JevAdvisor(
        enabled=True,
        endpoint=args.endpoint,
        model=args.model,
        api_key=os.environ.get(args.api_key_env) if args.api_key_env else None,
        timeout_s=args.timeout,
        fail_open=True,
        failure_classification=False,
        shadow_action_ranking=False,
        shadow_model_routing=False,
        shadow_verification_depth=False,
    )
    report = advisor.doctor()
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["ok"] else 2)


if __name__ == "__main__":
    main()
