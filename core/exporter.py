"""Export alerts to PDF or CSV."""
import csv
import io
from datetime import datetime


def export_csv(alerts: list, anomalies: list) -> bytes:
    buf = io.StringIO()
    fieldnames = [
        "timestamp", "severity", "rule_name", "mitre_tactic", "mitre_technique",
        "username", "source_ip", "hostname", "event_id", "alert_description",
        "anomaly_score", "anomaly_reason",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()

    anomaly_map = {id(a.event): a for a in anomalies}

    for alert in alerts:
        row = alert.to_dict()
        anom = anomaly_map.get(id(alert.event))
        row["anomaly_score"] = anom.score if anom else ""
        row["anomaly_reason"] = anom.reason if anom else ""
        writer.writerow(row)

    return buf.getvalue().encode()


def export_pdf(alerts: list, anomalies: list, log_files: list[str]) -> bytes:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle, HRFlowable)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                            leftMargin=0.75*inch, rightMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title_style = ParagraphStyle("title", parent=styles["Title"],
                                  fontSize=20, textColor=colors.HexColor("#1a237e"),
                                  spaceAfter=6)
    story.append(Paragraph("Security Log Analysis Report", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | "
        f"Files: {', '.join(log_files) if log_files else 'N/A'}",
        styles["Normal"]))
    story.append(Spacer(1, 0.15*inch))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#3949ab")))
    story.append(Spacer(1, 0.1*inch))

    # Summary stats
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in alerts:
        sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1

    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    summary_data = [
        ["Metric", "Value"],
        ["Total Alerts", str(len(alerts))],
        ["Critical", str(sev_counts["critical"])],
        ["High", str(sev_counts["high"])],
        ["Medium", str(sev_counts["medium"])],
        ["Anomalies Detected", str(len(anomalies))],
    ]
    t = Table(summary_data, colWidths=[3*inch, 2*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3949ab")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f5f5f5"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.2*inch))

    # Alert table
    story.append(Paragraph("Detected Alerts", styles["Heading2"]))
    SEV_COLORS = {
        "critical": colors.HexColor("#b71c1c"),
        "high": colors.HexColor("#e65100"),
        "medium": colors.HexColor("#f57f17"),
        "low": colors.HexColor("#1b5e20"),
    }

    headers = ["Time", "Sev", "Rule", "Tactic", "User", "Source IP"]
    table_data = [headers]
    row_colors = []
    for i, a in enumerate(alerts[:100]):
        ts = a.event.timestamp.strftime("%m/%d %H:%M") if a.event.timestamp else ""
        table_data.append([
            ts,
            a.severity.upper(),
            a.name[:30],
            a.mitre_tactic[:20],
            (a.event.username or "")[:15],
            (a.event.source_ip or "")[:16],
        ])
        row_colors.append(SEV_COLORS.get(a.severity, colors.grey))

    col_widths = [0.85*inch, 0.6*inch, 2.1*inch, 1.4*inch, 1.0*inch, 1.0*inch]
    at = Table(table_data, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3949ab")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#fff8e1"), colors.white]),
    ]
    for i, col in enumerate(row_colors, start=1):
        style_cmds.append(("TEXTCOLOR", (1, i), (1, i), col))
        style_cmds.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
    at.setStyle(TableStyle(style_cmds))
    story.append(at)

    if len(alerts) > 100:
        story.append(Paragraph(f"... and {len(alerts)-100} more alerts. See CSV export for full list.",
                                styles["Italic"]))

    # Anomalies
    if anomalies:
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph("Anomaly Scores (Top 10)", styles["Heading2"]))
        anom_data = [["Score", "User", "Action", "Reason"]]
        for a in anomalies[:10]:
            anom_data.append([
                f"{a.score:.2f}",
                (a.event.username or "")[:15],
                (a.event.action or "")[:20],
                a.reason[:55],
            ])
        ant = Table(anom_data, colWidths=[0.6*inch, 1.1*inch, 1.3*inch, 3.95*inch])
        ant.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#eceff1"), colors.white]),
        ]))
        story.append(ant)

    doc.build(story)
    return buf.getvalue()
