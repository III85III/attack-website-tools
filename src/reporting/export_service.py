"""Export one assessment and its engine runs without mixing targets."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from src.core.database import DatabaseManager
from src.core.evidence import distinct_findings
from src.reporting.docx_report import HTMLExporter, JSONExporter, MarkdownExporter, ReportGenerator


def export_assessment(
    db: DatabaseManager,
    scan_id: str,
    report_format: str,
    output_dir: Optional[Path] = None,
    target_name: str = "",
    title: str = "Security Assessment Report",
) -> Path:
    scan = db.get_scan(scan_id)
    if scan is None:
        raise ValueError("The selected assessment no longer exists.")
    if scan.status in {"RUNNING", "QUEUED"}:
        raise ValueError("Wait for the assessment to finish before exporting its report.")
    fmt = report_format.lower().strip()
    if fmt not in {"docx", "json", "markdown", "md", "html"}:
        raise ValueError("Choose Word (docx), HTML, Markdown, or JSON report format.")
    # UI tables may cap rows for responsiveness. Reports must contain every
    # finding from this assessment, including its optional engine runs.
    findings = distinct_findings(db.list_findings(scan_id=scan.id, limit=None))
    scan.findings_count = len(findings)
    tools = db.list_tool_health()
    if fmt == "docx":
        return ReportGenerator(output_dir).generate_docx(scan, findings, tools, target_name, title)
    if fmt in {"markdown", "md"}:
        return MarkdownExporter(output_dir).export_markdown(scan, findings, tools, target_name, title)
    if fmt == "html":
        return HTMLExporter(output_dir).export_html(scan, findings, tools, target_name, title)
    return JSONExporter(output_dir).export_json(scan, findings, tools)
