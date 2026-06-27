#!/usr/bin/env python3
"""Headless CLI — same engine as the web dashboard."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from core.parsers import parse_file
from detection.rules import run_rules
from detection.anomaly import score_events
from core.exporter import export_csv, export_pdf


def main():
    parser = argparse.ArgumentParser(
        description="SecLog Analyzer — MITRE ATT&CK-mapped log detection engine"
    )
    parser.add_argument("files", nargs="+", help="Log files to analyze (.evtx, .log, .csv, .json)")
    parser.add_argument("--output", "-o", default="terminal",
                        choices=["terminal", "json", "csv", "pdf"],
                        help="Output format (default: terminal)")
    parser.add_argument("--out-file", "-f", help="Output file path (for csv/pdf modes)")
    parser.add_argument("--min-severity", "-s", default="low",
                        choices=["low", "medium", "high", "critical"],
                        help="Minimum severity to report")
    parser.add_argument("--no-anomaly", action="store_true",
                        help="Skip anomaly scoring")
    args = parser.parse_args()

    SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_rank = SEV_RANK[args.min_severity]

    all_events = []
    for path in args.files:
        print(f"[*] Parsing {path} ...", file=sys.stderr)
        events = parse_file(path)
        print(f"    → {len(events)} events", file=sys.stderr)
        all_events.extend(events)

    print(f"[*] Running {len(all_events)} events through detection rules...", file=sys.stderr)
    alerts = run_rules(all_events)
    alerts = [a for a in alerts if SEV_RANK.get(a.severity, 0) >= min_rank]

    anomalies = []
    if not args.no_anomaly:
        print("[*] Running anomaly scorer...", file=sys.stderr)
        anomalies = score_events(all_events)

    print(f"[*] {len(alerts)} alerts | {len(anomalies)} anomalies\n", file=sys.stderr)

    if args.output == "terminal":
        _print_terminal(alerts, anomalies)

    elif args.output == "json":
        data = {
            "alerts": [a.to_dict() for a in alerts],
            "anomalies": [a.to_dict() for a in anomalies],
        }
        out = json.dumps(data, indent=2, default=str)
        if args.out_file:
            Path(args.out_file).write_text(out)
            print(f"[+] JSON written to {args.out_file}", file=sys.stderr)
        else:
            print(out)

    elif args.output == "csv":
        data = export_csv(alerts, anomalies)
        out_path = args.out_file or "alerts.csv"
        Path(out_path).write_bytes(data)
        print(f"[+] CSV written to {out_path}")

    elif args.output == "pdf":
        data = export_pdf(alerts, anomalies, args.files)
        out_path = args.out_file or "report.pdf"
        Path(out_path).write_bytes(data)
        print(f"[+] PDF written to {out_path}")


SEVERITY_COLOR = {
    "critical": "\033[91m",
    "high": "\033[93m",
    "medium": "\033[94m",
    "low": "\033[92m",
}
RESET = "\033[0m"


def _print_terminal(alerts, anomalies):
    print("=" * 72)
    print("  SECLOG ANALYZER — DETECTION RESULTS")
    print("=" * 72)

    if not alerts:
        print("  No alerts triggered.")
    else:
        for a in alerts:
            col = SEVERITY_COLOR.get(a.severity, "")
            ts = a.event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if a.event.timestamp else "?"
            print(f"\n{col}[{a.severity.upper():8s}]{RESET} {a.name}")
            print(f"  Rule:     {a.rule_id}")
            print(f"  MITRE:    {a.mitre_tactic} | {a.mitre_technique}")
            print(f"  Time:     {ts}")
            print(f"  User:     {a.event.username or 'N/A'}  |  IP: {a.event.source_ip or 'N/A'}")
            print(f"  Host:     {a.event.hostname or 'N/A'}  |  Event: {a.event.event_id or 'N/A'}")
            print(f"  Message:  {a.event.message[:100]}")

    if anomalies:
        print("\n" + "=" * 72)
        print("  ANOMALY SCORES (Top 10)")
        print("=" * 72)
        for a in anomalies[:10]:
            print(f"  {a.score:.2f}  {a.event.username or 'N/A':15s}  {a.event.action:20s}  {a.reason[:50]}")

    print("\n" + "=" * 72)


if __name__ == "__main__":
    main()
