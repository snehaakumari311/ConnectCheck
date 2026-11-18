
"""PDF report generation for ConnectCheck."""

from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


def _safe(value):
    """Convert values into safely escaped printable text."""
    if value is None:
        return "Not available"

    if isinstance(value, (dict, list, tuple)):
        value = str(value)

    return escape(str(value))


def _section(title, styles):
    return Paragraph(escape(title), styles["Section"])


def _bullet(text, styles):
    return Paragraph(
        "&#8226; " + _safe(text),
        styles["BodySmall"],
    )


def _key_value_table(rows):
    table = Table(
        rows,
        colWidths=[48 * mm, 112 * mm],
        repeatRows=1,
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b2a55")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#edf1f7")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#ccd3df")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    return table


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)

    canvas.drawString(
        20 * mm,
        12 * mm,
        "ConnectCheck | Network Diagnostics",
    )

    canvas.drawRightString(
        A4[0] - 20 * mm,
        12 * mm,
        f"Page {doc.page}",
    )

    canvas.restoreState()


def _extract_pcap_items(pcap_result):
    """Extract packet findings and recommendations from PCAP analysis."""
    findings = []
    recommendations = []

    if not isinstance(pcap_result, dict):
        return findings, recommendations

    for item in pcap_result.get("findings", []):
        if isinstance(item, dict):
            observation = item.get("observation") or item.get("message")

            if observation:
                findings.append(observation)

            recommendation = item.get("recommendation")

            if recommendation:
                recommendations.append(recommendation)

        elif item:
            findings.append(str(item))

    # Remove duplicate recommendations while preserving their order.
    recommendations = list(dict.fromkeys(recommendations))

    return findings, recommendations


def generate_pdf_report(diagnostic_result, pcap_result=None):
    """
    Generate a PDF report in memory.

    diagnostic_result:
        {
            "domain": "...",
            "checks": [...],
            "diagnosis": {...}
        }

    pcap_result:
        Optional result returned by analyze_pcap().
    """
    if not isinstance(diagnostic_result, dict):
        raise ValueError("Diagnostic result must be a dictionary.")

    if pcap_result is not None and not isinstance(pcap_result, dict):
        raise ValueError("PCAP result must be a dictionary.")

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=22 * mm,
        title="ConnectCheck Troubleshooting Report",
        author="ConnectCheck",
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontSize=20,
        leading=25,
        textColor=colors.HexColor("#1b2a55"),
        alignment=TA_CENTER,
        spaceAfter=5 * mm,
    ))

    styles.add(ParagraphStyle(
        name="Section",
        parent=styles["Heading2"],
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1b2a55"),
        spaceBefore=5 * mm,
        spaceAfter=3 * mm,
    ))

    styles.add(ParagraphStyle(
        name="BodySmall",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        spaceAfter=3,
    ))

    story = []

    # --------------------------------------------------
    # 1. REPORT HEADING AND METADATA
    # --------------------------------------------------

    story.append(Paragraph("ConnectCheck", styles["ReportTitle"]))

    story.append(Paragraph(
        "Network Troubleshooting Report",
        styles["Heading2"],
    ))

    story.append(Spacer(1, 3 * mm))

    generated_at = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    metadata = [
        ["Report Detail", "Value"],
        ["Domain / Capture", _safe(diagnostic_result.get("domain"))],
        ["Generated At", generated_at],
    ]

    story.append(_key_value_table(metadata))

    # --------------------------------------------------
    # 2. NETWORK DIAGNOSTIC RESULTS
    # --------------------------------------------------

    story.append(_section("1. Network Diagnostic Results", styles))

    checks = diagnostic_result.get("checks", [])

    if checks:
        rows = [["Check", "Result", "Message"]]

        for check in checks:
            if not isinstance(check, dict):
                continue

            rows.append([
                _safe(check.get("check", "Unknown")),
                "Success" if check.get("success") else "Failed",
                Paragraph(
                    _safe(check.get("message")),
                    styles["BodySmall"],
                ),
            ])

        if len(rows) > 1:
            table = Table(
                rows,
                colWidths=[38 * mm, 25 * mm, 97 * mm],
                repeatRows=1,
            )

            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b2a55")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))

            story.append(table)
        else:
            story.append(Paragraph(
                "No individual diagnostic checks were provided.",
                styles["BodyText"],
            ))
    else:
        story.append(Paragraph(
            "No individual diagnostic checks were provided.",
            styles["BodyText"],
        ))

    # --------------------------------------------------
    # 3. DIAGNOSIS AND PROBABLE ROOT CAUSE
    # --------------------------------------------------

    diagnosis = diagnostic_result.get("diagnosis", {})

    if not isinstance(diagnosis, dict):
        diagnosis = {}

    pcap_findings, pcap_recommendations = _extract_pcap_items(
        pcap_result
    )

    # Use PCAP findings when the ordinary diagnosis has none.
    findings = diagnosis.get("findings") or pcap_findings
    recommendations = (
        diagnosis.get("recommendations") or pcap_recommendations
    )

    story.append(_section(
        "2. Diagnosis and Probable Root Cause",
        styles,
    ))

    diagnosis_rows = [
        ["Field", "Result"],
        ["Status", _safe(diagnosis.get(
            "status",
            "Informational" if pcap_result else None,
        ))],
        ["Category", _safe(diagnosis.get(
            "category",
            "Packet Capture" if pcap_result else None,
        ))],
        ["Probable Cause", _safe(diagnosis.get(
            "probable_cause",
            "Review the packet analysis findings." if pcap_result else None,
        ))],
        ["Summary", _safe(diagnosis.get(
            "summary",
            "This report contains packet capture analysis results."
            if pcap_result else None,
        ))],
    ]

    story.append(_key_value_table(diagnosis_rows))

    # Findings
    story.append(_section("Findings", styles))

    if findings:
        for item in findings:
            story.append(_bullet(item, styles))
    else:
        story.append(Paragraph(
            "No findings were reported.",
            styles["BodySmall"],
        ))

    # Recommendations
    story.append(_section("Recommended Actions", styles))

    if recommendations:
        for item in recommendations:
            story.append(_bullet(item, styles))
    else:
        story.append(Paragraph(
            "No specific recommendations were reported.",
            styles["BodySmall"],
        ))

    # --------------------------------------------------
    # 4. OPTIONAL PACKET CAPTURE ANALYSIS
    # --------------------------------------------------

    if pcap_result is not None:
        story.append(_section(
            "3. Packet Capture Analysis",
            styles,
        ))

        summary = pcap_result.get("summary", {})

        if not isinstance(summary, dict):
            summary = {}

        pcap_rows = [["Metric", "Value"]]

        for key in (
            "filename",
            "total_packets",
            "total_bytes",
            "unique_source_ips",
            "unique_destination_ips",
            "duration_seconds",
        ):
            if key in summary:
                pcap_rows.append([
                    _safe(key.replace("_", " ").title()),
                    _safe(summary[key]),
                ])

        if len(pcap_rows) == 1:
            pcap_rows.append([
                "Status",
                "No summary details available",
            ])

        story.append(_key_value_table(pcap_rows))

        # Detailed packet findings
        detailed_findings = pcap_result.get("findings", [])

        if detailed_findings:
            story.append(_section(
                "Detailed Packet Findings",
                styles,
            ))

            for finding in detailed_findings:
                if isinstance(finding, dict):
                    observation = finding.get(
                        "observation",
                        finding.get("message", "Finding detected"),
                    )

                    story.append(Paragraph(
                        "<b>Observation:</b> " + _safe(observation),
                        styles["BodySmall"],
                    ))

                    for label, key in (
                        ("Evidence", "evidence"),
                        ("Possible explanation", "possible_explanation"),
                        ("Recommendation", "recommendation"),
                    ):
                        value = finding.get(key)

                        if value:
                            story.append(Paragraph(
                                "<b>" + label + ":</b> " + _safe(value),
                                styles["BodySmall"],
                            ))

                    story.append(Spacer(1, 2 * mm))

                else:
                    story.append(_bullet(finding, styles))

    # --------------------------------------------------
    # 5. BUILD AND RETURN PDF
    # --------------------------------------------------

    doc.build(
        story,
        onFirstPage=_footer,
        onLaterPages=_footer,
    )

    buffer.seek(0)
    return buffer
