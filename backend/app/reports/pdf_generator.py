"""
PDF Report Generator using ReportLab.
Generates professional investigation reports.
"""
import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT


def generate_pdf_report(case, result, analyst_name=None, analyst_notes=None) -> bytes:
    """Generate a PDF investigation report."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=20*mm, bottomMargin=20*mm,
                            leftMargin=20*mm, rightMargin=20*mm)

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='ReportTitle', fontSize=20, spaceAfter=12,
                               textColor=colors.HexColor("#1a1a2e"), alignment=TA_CENTER, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='SectionTitle', fontSize=14, spaceAfter=8, spaceBefore=16,
                               textColor=colors.HexColor("#0f3460"), fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='SubSection', fontSize=11, spaceAfter=6, spaceBefore=8,
                               textColor=colors.HexColor("#16213e"), fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='BodyText2', fontSize=9, spaceAfter=4, leading=13))

    elements = []

    # Title
    elements.append(Paragraph("EMAIL ANALYSIS REPORT", styles['ReportTitle']))
    elements.append(Paragraph("Security Operations Center — Investigation Report", styles['Normal']))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0f3460")))
    elements.append(Spacer(1, 12))

    # Case metadata
    severity_colors = {"critical": "#e74c3c", "high": "#e67e22", "medium": "#f39c12", "low": "#3498db", "safe": "#2ecc71"}
    verdict_color = severity_colors.get(case.severity, "#95a5a6")

    meta_data = [
        ["Case Number", case.case_number],
        ["Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Analyst", analyst_name or case.assigned_analyst or "N/A"],
        ["Verdict", (case.verdict or "N/A").upper()],
        ["Severity", (case.severity or "N/A").upper()],
        ["Risk Score", f"{case.risk_score}/100" if case.risk_score is not None else "N/A"],
    ]
    meta_table = Table(meta_data, colWidths=[120, 350])
    meta_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 12))

    # Email Summary
    elements.append(Paragraph("Email Summary", styles['SectionTitle']))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#bdc3c7")))
    email_data = [
        ["Subject", case.email_subject or "N/A"],
        ["Sender", case.email_sender or "N/A"],
        ["Recipient", case.email_recipient or "N/A"],
        ["Message-ID", case.email_message_id or "N/A"],
    ]
    email_table = Table(email_data, colWidths=[100, 370])
    email_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(email_table)

    # Header Analysis
    header_data = result.header_analysis or {}
    findings = header_data.get("findings", [])
    if findings:
        elements.append(Paragraph("Header Analysis", styles['SectionTitle']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#bdc3c7")))
        header_table_data = [["Severity", "Finding", "Description"]]
        for f in findings:
            header_table_data.append([
                f.get("severity", "").upper(),
                f.get("title", ""),
                f.get("description", "")[:120],
            ])
        ht = Table(header_table_data, colWidths=[60, 120, 290])
        ht.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f3460")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(ht)

    # Phishing Indicators
    phishing_data = result.phishing_analysis or {}
    indicators = phishing_data.get("indicators", [])
    if indicators:
        elements.append(Paragraph("Phishing Indicators", styles['SectionTitle']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#bdc3c7")))
        p_table_data = [["Category", "Indicator", "Confidence"]]
        for ind in indicators:
            conf = ind.get("confidence", 0)
            p_table_data.append([
                ind.get("category", ""),
                ind.get("indicator", ""),
                f"{conf:.0%}",
            ])
        pt = Table(p_table_data, colWidths=[100, 280, 80])
        pt.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e74c3c")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(pt)

    # IOC Summary
    ioc_data = result.ioc_summary or {}
    total_iocs = ioc_data.get("total_count", 0)
    if total_iocs > 0:
        elements.append(Paragraph(f"Indicators of Compromise ({total_iocs} total)", styles['SectionTitle']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#bdc3c7")))
        ioc_table_data = [["Type", "Value"]]
        for category in ["ips", "domains", "urls", "hashes", "emails"]:
            for ioc in ioc_data.get(category, [])[:15]:
                ioc_table_data.append([ioc.get("ioc_type", ""), ioc.get("defanged", ioc.get("value", ""))[:80]])
        if len(ioc_table_data) > 1:
            it = Table(ioc_table_data, colWidths=[80, 390])
            it.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTNAME', (1, 1), (1, -1), 'Courier'),
            ]))
            elements.append(it)

    # MITRE ATT&CK
    mitre_data = result.mitre_mapping or []
    if mitre_data:
        elements.append(Paragraph("MITRE ATT&CK Mapping", styles['SectionTitle']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#bdc3c7")))
        mitre_table_data = [["Technique", "Tactic", "Confidence"]]
        for m in mitre_data:
            mitre_table_data.append([
                f"{m.get('technique_id', '')} — {m.get('technique_name', '')}",
                m.get("tactic", ""),
                f"{m.get('confidence', 0):.0%}",
            ])
        mt = Table(mitre_table_data, colWidths=[250, 130, 80])
        mt.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#8e44ad")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(mt)

    # Recommended Actions
    actions = result.recommended_actions or []
    if actions:
        elements.append(Paragraph("Recommended Actions", styles['SectionTitle']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#bdc3c7")))
        for i, action in enumerate(actions, 1):
            elements.append(Paragraph(f"{i}. {action}", styles['BodyText2']))

    # Analyst Notes
    notes = analyst_notes or case.analyst_notes
    if notes:
        elements.append(Paragraph("Analyst Notes", styles['SectionTitle']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#bdc3c7")))
        elements.append(Paragraph(notes, styles['BodyText2']))

    # Footer
    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f3460")))
    elements.append(Paragraph("Generated by Email Analysis Tool v1.0 — Confidential", styles['Normal']))

    doc.build(elements)
    return buffer.getvalue()
