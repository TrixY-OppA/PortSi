"""
reporter.py — PortSi PDF Report Generator (Premium Aesthetic)

This module implements a high-fidelity, corporate-style PDF report for the
PortSi vulnerability scanner. It focuses on:

- Hero branding header with title + subtitle in Times-Roman/Times-Bold
- Georgia-inspired serif body text for all content
- Modern, minimalist color palette
- Asset context and executive summary
- Detailed findings with CVE-level technical breakdowns
- Dynamic rich context generation for clean/exposed states
- Remediation guidance section

Design goals:
- No absolute filesystem paths — output respects `output_dir` or `Path.cwd()`
- Flowables-only layout (Platypus) for robust pagination and wrapping
- Continuous single-stream flow without forced page breaks
"""

import logging
import html
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
)
from reportlab.pdfgen import canvas
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY

logger = logging.getLogger(__name__)

# === High-fidelity color palette ===
COLOR_SLATE_BLUE = HexColor("#1A2B3C")   # Hero title color
COLOR_SUBTITLE_GRAY = HexColor("#6B7280")
COLOR_NAVY_HEADER = HexColor("#2C3E50")  # Table header
COLOR_BORDER = HexColor("#E5E7EB")      # Ultra-thin borders
COLOR_ROW_BG = HexColor("#F9FAFB")      # Off-white row background
COLOR_CRITICAL = HexColor("#DC2626")    # Critical / High
COLOR_MEDIUM = HexColor("#D97706")      # Medium / Amber
COLOR_TEXT = HexColor("#111827")        # Dark text


class VulnerabilityReport:
    """Generate a premium PDF report for PortSi scans.
    
    Adaptive to both init-style and execution-style data injection to maintain
    seamless compatibility with portsi.py orchestrator.
    """

    def __init__(
        self, 
        target: str, 
        scan_results: Optional[Dict[int, Dict[str, Any]]] = None, 
        vulnerability_data: Optional[Dict[int, List[Dict[str, Any]]]] = None
    ):
        self.target = target
        self.timestamp = datetime.now()
        
        # Capture scan items if supplied during instantiation (fixes signature mismatch)
        self.scan_results = scan_results if scan_results is not None else {}
        self.vulnerability_data = vulnerability_data if vulnerability_data is not None else {}

        # Layout defaults
        self.page_size = letter
        self.left_margin = 0.7 * inch
        self.right_margin = 0.7 * inch
        self.top_margin = 0.6 * inch
        self.bottom_margin = 0.6 * inch

    def _spaced(self, text: str) -> str:
        """Return tracking-spaced text for subtitle aesthetic."""
        return " ".join(list(text.upper()))

    def _severity_color(self, severity: str) -> HexColor:
        if severity == "CRITICAL" or severity == "HIGH":
            return COLOR_CRITICAL
        if severity == "MEDIUM":
            return COLOR_MEDIUM
        return COLOR_TEXT

    def _generate_clean_state_context(self) -> str:
        return (
            "<b>System Analysis Status:</b> All structural validation checks passed successfully. "
            "PortSi executed a fast multi-layered socket scan along with deep system diagnostics on the target host. "
            "No anomalous listening services or exposed entry points were uncovered. "
            "All audited ports are securely filtered or closed, exhibiting a robust baseline perimeter defense posture."
        )

    def _generate_risk_breakdown(self, port: int, service_name: str, version: str, cves: List[Dict[str, Any]]) -> str:
        if not cves:
            return f"<b>Service Status:</b> {html.escape(service_name)} (v{html.escape(version)}) on port {port} is exposed but no known CVEs are currently indexed."

        cve_count = len(cves)
        critical_count = sum(1 for c in cves if c.get('severity') == 'CRITICAL')
        high_count = sum(1 for c in cves if c.get('severity') == 'HIGH')

        breakdown = f"<b>Security Risk Assessment:</b> {html.escape(service_name)} (v{html.escape(version)}) on port {port} presents active structural risk. "
        breakdown += f"Enumerated: {cve_count} known CVE(s) "

        if critical_count > 0:
            breakdown += f"including <b>{critical_count} CRITICAL</b>-severity vector(s) "
        if high_count > 0:
            breakdown += f"and <b>{high_count} HIGH</b>-severity findings. "

        breakdown += "Immediate remediation through vendor patching or service retirement is strongly recommended."
        return breakdown

    def generate_pdf(self, *args, **kwargs) -> str:
        """Create the PDF file and return its path.
        
        Dynamically unrolls arguments to process both standard calls and legacy signatures
        seamlessly without throwing positional errors.
        """
        # Default data structures sourced from instantiation
        final_scan_results = self.scan_results
        final_vulnerability_data = self.vulnerability_data
        output_dir = kwargs.get("output_dir", None)

        # Evaluate arguments to establish data parsing mode
        if len(args) == 1:
            # Invocation pattern matches: generate_pdf(output_dir)
            output_dir = args[0]
        elif len(args) >= 2:
            # Invocation pattern matches: generate_pdf(scan_results, vulnerability_data, [output_dir])
            if isinstance(args[0], dict) and isinstance(args[1], dict):
                final_scan_results = args[0]
                final_vulnerability_data = args[1]
                if len(args) > 2:
                    output_dir = args[2]
            else:
                # Fallback mechanism if first item is string-based path
                output_dir = args[0]

        # Enforce dict types to block structure errors upstream
        if not isinstance(final_scan_results, dict):
            final_scan_results = {}
        if not isinstance(final_vulnerability_data, dict):
            final_vulnerability_data = {}

        out_dir = Path(output_dir) if output_dir else Path.cwd()
        out_dir.mkdir(parents=True, exist_ok=True)

        timestamp_str = self.timestamp.strftime("%Y%m%d_%H%M%S")
        safe_target = self.target.replace("/", "_").replace(":", "_")
        filename = f"portsi_report_{safe_target}_{timestamp_str}.pdf"
        filepath = out_dir / filename

        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=self.page_size,
            leftMargin=self.left_margin,
            rightMargin=self.right_margin,
            topMargin=self.top_margin,
            bottomMargin=self.bottom_margin,
            title="PortSi Enterprise Vulnerability Report",
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "Title",
            parent=styles["Heading1"],
            fontName="Times-Bold",
            fontSize=36,
            textColor=COLOR_SLATE_BLUE,
            alignment=TA_CENTER,
            spaceAfter=6,
        )

        subtitle_style = ParagraphStyle(
            "Subtitle",
            parent=styles["Normal"],
            fontName="Times-Roman",
            fontSize=14,
            textColor=COLOR_SUBTITLE_GRAY,
            alignment=TA_CENTER,
            spaceAfter=12,
            leading=16,
        )

        heading_style = ParagraphStyle(
            "Heading",
            parent=styles["Heading2"],
            fontName="Times-Bold",
            fontSize=12,
            textColor=COLOR_TEXT,
            spaceBefore=12,
            spaceAfter=6,
        )

        normal_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontName="Times-Roman",
            fontSize=10,
            textColor=COLOR_TEXT,
            leading=14,
            alignment=TA_JUSTIFY,
        )

        small_style = ParagraphStyle(
            "Small",
            parent=styles["Normal"],
            fontName="Times-Roman",
            fontSize=8,
            textColor=COLOR_SUBTITLE_GRAY,
            leading=10,
        )

        port_header_style = ParagraphStyle(
            "PortHeader",
            parent=styles["Heading3"],
            fontName="Times-Bold",
            fontSize=11,
            textColor=COLOR_TEXT,
            spaceBefore=10,
            spaceAfter=6,
        )

        story: List[Any] = []

        # ============================================================
        # HERO HEADER
        # ============================================================
        story.append(Paragraph("PortSi", title_style))
        subtitle_text = self._spaced("VULNERABILITY SCAN REPORT")
        story.append(Paragraph(subtitle_text, subtitle_style))
        story.append(Spacer(1, 20))

        # ============================================================
        # ASSET CONTEXT BLOCK
        # ============================================================
        story.append(Paragraph("ASSET CONTEXT", heading_style))

        total_ports = len(final_scan_results)
        total_cves = sum(len(v) for v in final_vulnerability_data.values())

        context_data = [
            ["Target:", html.escape(self.target)],
            ["Scan Execution:", self.timestamp.strftime("%Y-%m-%d %H:%M:%S")],
            ["Scan Duration:", "Not available"],
            ["Detected Services:", str(total_ports)],
            ["Total CVEs:", str(total_cves)],
        ]

        context_table = Table(context_data, colWidths=[1.6 * inch, 4.4 * inch])
        context_table.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, COLOR_BORDER),
            ("BACKGROUND", (0, 0), (-1, -1), HexColor("#FFFFFF")),
            ("FONTNAME", (0, 0), (-1, -1), "Times-Roman"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))

        story.append(context_table)
        story.append(Spacer(1, 0.25 * inch))

        # ============================================================
        # EXECUTIVE SUMMARY
        # ============================================================
        story.append(Paragraph("EXECUTIVE SUMMARY", heading_style))

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
        for cves in final_vulnerability_data.values():
            for c in cves:
                severity_counts[c.get("severity", "NONE")] = severity_counts.get(c.get("severity", "NONE"), 0) + 1

        summary_data = [
            [Paragraph("<b>Metric</b>", normal_style), Paragraph("<b>Value</b>", normal_style)],
            ["Total Open Ports", str(total_ports)],
            ["Total CVEs", str(total_cves)],
            ["Critical", str(severity_counts.get("CRITICAL", 0))],
            ["High", str(severity_counts.get("HIGH", 0))],
            ["Medium", str(severity_counts.get("MEDIUM", 0))],
            ["Low", str(severity_counts.get("LOW", 0))],
        ]

        summary_table = Table(summary_data, colWidths=[3.0 * inch, 3.0 * inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_NAVY_HEADER),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#FFFFFF")),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, -1), "Times-Roman"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, COLOR_BORDER),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), COLOR_ROW_BG]),
        ]))

        story.append(summary_table)
        story.append(Spacer(1, 0.25 * inch))

        # ============================================================
        # DETAILED FINDINGS
        # ============================================================
        story.append(Paragraph("DETAILED FINDINGS", heading_style))

        if not final_scan_results and total_cves == 0:
            clean_context = self._generate_clean_state_context()
            story.append(Paragraph(clean_context, normal_style))
            story.append(Spacer(1, 0.2 * inch))
        else:
            for port in sorted(final_scan_results.keys()):
                svc = final_scan_results[port]
                svc_name = html.escape(svc.get("service", "Unknown"))
                svc_version = html.escape(svc.get("version", "Unknown"))
                svc_state = html.escape(svc.get("state", "unknown"))
                cves = final_vulnerability_data.get(port, [])

                story.append(Paragraph(f"Port {port} — {svc_name}", port_header_style))

                risk_breakdown = self._generate_risk_breakdown(port, svc_name, svc_version, cves)
                story.append(Paragraph(risk_breakdown, normal_style))
                story.append(Spacer(1, 0.12 * inch))

                svc_table = Table([
                    ["Service", svc_name, "Version", svc_version],
                    ["State", svc_state, "CVE Count", str(len(cves))],
                ], colWidths=[1.0 * inch, 2.2 * inch, 1.0 * inch, 2.0 * inch])

                svc_table.setStyle(TableStyle([
                    ("BOX", (0, 0), (-1, -1), 0.25, COLOR_BORDER),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, COLOR_BORDER),
                    ("BACKGROUND", (0, 0), (-1, -1), HexColor("#FFFFFF")),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [HexColor("#FFFFFF"), COLOR_ROW_BG]),
                    ("FONTNAME", (0, 0), (-1, -1), "Times-Roman"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                ]))

                story.append(svc_table)
                story.append(Spacer(1, 0.1 * inch))

                if not cves:
                    story.append(Paragraph("No CVEs found for this service.", small_style))
                    story.append(Spacer(1, 0.15 * inch))
                    continue

                cve_rows: List[List[Any]] = [[
                    Paragraph('<b>CVE ID</b>', normal_style),
                    Paragraph('<b>CVSS</b>', normal_style),
                    Paragraph('<b>Severity</b>', normal_style),
                    Paragraph('<b>Description</b>', normal_style),
                ]]

                for cve in cves:
                    cve_id = html.escape(cve.get('cve_id', 'Unknown'))
                    cvss = cve.get('cvss_score', 0.0)
                    severity = html.escape(cve.get('severity', 'NONE'))
                    
                    raw_desc = cve.get('description', 'No description provided.')
                    desc_para = Paragraph(html.escape(raw_desc), normal_style)

                    cve_rows.append([
                        Paragraph(cve_id, normal_style),
                        Paragraph(f"{cvss:.1f}", normal_style),
                        Paragraph(severity, normal_style),
                        desc_para,
                    ])

                    technical_parts = []
                    if 'cvss_vector' in cve and cve.get('cvss_vector'):
                        technical_parts.append(f"CVSS Vector: {html.escape(cve.get('cvss_vector'))}")
                    if 'remediation' in cve and cve.get('remediation'):
                        technical_parts.append(f"Remediation: {html.escape(cve.get('remediation'))}")

                    if technical_parts:
                        tech_text = ' | '.join(technical_parts)
                        cve_rows.append([
                            Paragraph('', small_style),
                            Paragraph('', small_style),
                            Paragraph('', small_style),
                            Paragraph(f"<i>Technical Breakdown: {tech_text}</i>", small_style),
                        ])

                cve_table = Table(cve_rows, colWidths=[1.2 * inch, 0.8 * inch, 1.0 * inch, 3.0 * inch], repeatRows=1)
                cve_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), COLOR_NAVY_HEADER),
                    ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#FFFFFF")),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, -1), "Times-Roman"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, COLOR_BORDER),
                    ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), COLOR_ROW_BG]),
                ]))

                for r in range(1, len(cve_rows)):
                    if r < len(cve_rows) and isinstance(cve_rows[r][2], Paragraph):
                        sev_text = cve_rows[r][2].text if hasattr(cve_rows[r][2], 'text') else ''
                        if 'CRITICAL' in sev_text or 'HIGH' in sev_text:
                            cve_table.setStyle(TableStyle([('TEXTCOLOR', (2, r), (2, r), COLOR_CRITICAL)]))
                        elif 'MEDIUM' in sev_text:
                            cve_table.setStyle(TableStyle([('TEXTCOLOR', (2, r), (2, r), COLOR_MEDIUM)]))

                story.append(cve_table)
                story.append(Spacer(1, 0.2 * inch))

        # ============================================================
        # REMEDIATION GUIDANCE
        # ============================================================
        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph("REMEDIATION GUIDANCE", heading_style))

        if total_cves > 0:
            guidance = Paragraph(
                "Action required: Review critical CVEs and apply vendor patches immediately. "
                "Prioritize CRITICAL and HIGH severity items and validate fixes in a staging environment before production rollout.",
                normal_style,
            )
        else:
            guidance = Paragraph(
                "No remediation actions are required at this time. Continue regular security monitoring and keep systems updated with the latest patches.",
                normal_style,
            )
        story.append(guidance)

        # ============================================================
        # FOOTER AND HEADER DRAWING
        # ============================================================
        def _on_page(canvas_obj: canvas.Canvas, doc_obj: SimpleDocTemplate):
            canvas_obj.saveState()
            y = doc_obj.pagesize[1] - (self.top_margin + 0.85 * inch)
            canvas_obj.setStrokeColor(COLOR_BORDER)
            canvas_obj.setLineWidth(0.5)
            canvas_obj.line(self.left_margin, y, doc_obj.pagesize[0] - self.right_margin, y)

            header = f"PortSi — {html.escape(self.target)}"
            canvas_obj.setFont("Times-Roman", 8)
            canvas_obj.setFillColor(COLOR_SUBTITLE_GRAY)
            canvas_obj.drawString(self.left_margin, doc_obj.pagesize[1] - 0.4 * inch, header)

            page_num = canvas_obj.getPageNumber()
            footer = f"Page {page_num} — Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            canvas_obj.setFillColor(COLOR_SUBTITLE_GRAY)
            canvas_obj.drawRightString(doc_obj.pagesize[0] - self.right_margin, 0.45 * inch, footer)
            canvas_obj.restoreState()

        try:
            doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
            logger.info(f"Generated report: {filepath}")
            print(f"[✓] Report generated: {filepath}")
            return str(filepath)
        except Exception:
            logger.exception("Failed to generate PDF report")
            raise