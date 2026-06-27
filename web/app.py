"""Flask web dashboard for SecLog Analyzer."""
import io
import json
import os
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

from flask import (Flask, jsonify, redirect, render_template, request,
                   send_file, url_for)

sys.path.insert(0, str(Path(__file__).parent.parent))

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core.parsers import parse_file
from detection.rules import run_rules
from detection.anomaly import score_events
from core.exporter import export_csv, export_pdf

app = Flask(__name__)
app.secret_key = os.urandom(24)

UPLOAD_FOLDER = tempfile.mkdtemp(prefix="seclog_")
ALLOWED_EXT = {".evtx", ".log", ".syslog", ".txt", ".csv", ".json", ".cef", ".access"}
MAX_UPLOAD_MB = 50

# In-memory analysis state (single-session demo)
_state: dict = {}


def allowed(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXT


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    files = request.files.getlist("logfiles")
    if not files or all(f.filename == "" for f in files):
        return jsonify({"error": "No files uploaded"}), 400

    saved_paths = []
    names = []
    for f in files:
        if f and allowed(f.filename):
            dest = os.path.join(UPLOAD_FOLDER, f.filename)
            f.save(dest)
            saved_paths.append(dest)
            names.append(f.filename)

    if not saved_paths:
        return jsonify({"error": "No valid log files (accepted: evtx, log, csv, json, cef)"}), 400

    all_events, parse_summary = _ingest_paths(saved_paths)
    _state["files"] = names
    return jsonify(_run_and_build(all_events, parse_summary))


@app.route("/demo", methods=["POST"])
def demo():
    """Load the built-in synthetic sample data."""
    sample_dir = Path(__file__).parent.parent / "sample_data"
    samples = [
        str(sample_dir / "sample_auth.log"),
        str(sample_dir / "sample_windows.csv"),
        str(sample_dir / "sample_webapp.json"),
        str(sample_dir / "sample_access.log"),
        str(sample_dir / "sample_firewall.cef"),
    ]
    paths = [p for p in samples if Path(p).exists()]
    all_events, parse_summary = _ingest_paths(paths)
    _state["files"] = [Path(p).name for p in paths]
    return jsonify(_run_and_build(all_events, parse_summary))


def _ingest_paths(paths: list[str]):
    all_events = []
    summary = []
    for path in paths:
        events = parse_file(path)
        summary.append({"file": Path(path).name, "events": len(events),
                        "format": Path(path).suffix.lstrip(".") or "auto"})
        all_events.extend(events)
    return all_events, summary


def _run_and_build(all_events, parse_summary) -> dict:
    alerts = run_rules(all_events)
    anomalies = score_events(all_events)

    _state["alerts"] = alerts
    _state["anomalies"] = anomalies
    _state["events"] = all_events

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    tactic_counts: dict[str, int] = {}
    for a in alerts:
        sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1
        tactic_counts[a.mitre_tactic] = tactic_counts.get(a.mitre_tactic, 0) + 1

    # Timeline: alert counts bucketed by hour
    hour_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for a in alerts:
        if a.event.timestamp:
            bucket = a.event.timestamp.strftime("%H:00")
            hour_counts[bucket][a.severity] += 1
    timeline = [{"hour": h, **counts} for h, counts in sorted(hour_counts.items())]

    # Top attacker IPs
    ip_counts: dict[str, int] = defaultdict(int)
    for a in alerts:
        if a.event.source_ip:
            ip_counts[a.event.source_ip] += 1
    top_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:10]

    return {
        "total_events": len(all_events),
        "total_alerts": len(alerts),
        "total_anomalies": len(anomalies),
        "parse_summary": parse_summary,
        "severity_counts": sev_counts,
        "tactic_counts": tactic_counts,
        "timeline": timeline,
        "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
        "alerts": [_alert_row(a) for a in alerts],
        "anomalies": [_anom_row(a) for a in anomalies[:50]],
    }


def _alert_row(a) -> dict:
    return {
        "rule_id": a.rule_id,
        "name": a.name,
        "severity": a.severity,
        "mitre_tactic": a.mitre_tactic,
        "mitre_technique": a.mitre_technique,
        "timestamp": a.event.timestamp.isoformat() if a.event.timestamp else "",
        "username": a.event.username or "",
        "source_ip": a.event.source_ip or "",
        "hostname": a.event.hostname or "",
        "event_id": a.event.event_id or "",
        "log_source": a.event.log_source,
        "message": a.event.message[:150],
        "description": a.description,
        "dest_ip": a.event.dest_ip or "",
    }


def _anom_row(a) -> dict:
    return {
        "score": a.score,
        "username": a.event.username or "",
        "action": a.event.action,
        "source_ip": a.event.source_ip or "",
        "timestamp": a.event.timestamp.isoformat() if a.event.timestamp else "",
        "reason": a.reason,
    }


@app.route("/export/csv")
def export_csv_route():
    if not _state.get("alerts"):
        return "No analysis results. Run analysis first.", 400
    data = export_csv(_state["alerts"], _state.get("anomalies", []))
    return send_file(
        io.BytesIO(data),
        mimetype="text/csv",
        as_attachment=True,
        download_name="seclog_alerts.csv",
    )


@app.route("/export/pdf")
def export_pdf_route():
    if not _state.get("alerts"):
        return "No analysis results. Run analysis first.", 400
    data = export_pdf(
        _state["alerts"],
        _state.get("anomalies", []),
        _state.get("files", []),
    )
    return send_file(
        io.BytesIO(data),
        mimetype="application/pdf",
        as_attachment=True,
        download_name="seclog_report.pdf",
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print(f"[*] SecLog Analyzer running at http://localhost:{port}")
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(debug=debug, host="0.0.0.0", port=port)
