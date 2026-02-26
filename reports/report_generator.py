from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from PyQt6.QtCore import QSizeF, QMarginsF
from PyQt6.QtGui import QGuiApplication, QPageLayout, QPageSize, QTextDocument, QPdfWriter

from core.case_manager import CaseData


class ReportGenerator:
    @staticmethod
    def _safe(value: object) -> str:
        return html.escape(str(value), quote=True).replace("\n", "<br>")

    @staticmethod
    def _case_summary(case_data: CaseData) -> dict:
        return {
            "case_number": case_data.case_number,
            "investigator": case_data.investigator,
            "evidence_id": case_data.evidence_id,
            "notes": case_data.notes,
            "memory_image": {
                "path": case_data.memory_image.path,
                "size": case_data.memory_image.size,
                "sha256": case_data.memory_image.sha256,
                "verified": case_data.memory_image.verified,
            },
            "custody_log": case_data.custody_log,
            "executions": [
                {
                    "plugin": e.plugin,
                    "version": e.version,
                    "timestamp": e.timestamp,
                    "parameters": e.parameters,
                }
                for e in case_data.executions
            ],
            "findings": [
                {
                    "title": f.title,
                    "details": f.details,
                    "tags": f.tags,
                    "bookmarked": f.bookmarked,
                    "created_at": f.created_at,
                }
                for f in case_data.findings
            ],
        }

    @staticmethod
    def export_json(case_data: CaseData, target_path: str) -> None:
        Path(target_path).write_text(
            json.dumps(ReportGenerator._case_summary(case_data), indent=2), encoding="utf-8"
        )

    @staticmethod
    def export_csv(case_data: CaseData, target_path: str) -> None:
        with Path(target_path).open("w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["Case Number", case_data.case_number])
            writer.writerow(["Investigator", case_data.investigator])
            writer.writerow(["Evidence ID", case_data.evidence_id])
            writer.writerow(["Memory Image", case_data.memory_image.path])
            writer.writerow(["SHA256", case_data.memory_image.sha256])
            writer.writerow([])
            writer.writerow(["Executions"])
            writer.writerow(["Timestamp", "Plugin", "Version", "Parameters"])
            for rec in case_data.executions:
                writer.writerow([rec.timestamp, rec.plugin, rec.version, json.dumps(rec.parameters)])
            writer.writerow([])
            writer.writerow(["Findings"])
            writer.writerow(["Created", "Title", "Details", "Tags", "Bookmarked"])
            for finding in case_data.findings:
                writer.writerow(
                    [
                        finding.created_at,
                        finding.title,
                        finding.details,
                        ";".join(finding.tags),
                        str(finding.bookmarked),
                    ]
                )

    @staticmethod
    def _html(case_data: CaseData) -> str:
        exec_rows = "".join(
            "<tr>"
            f"<td>{ReportGenerator._safe(e.timestamp)}</td>"
            f"<td>{ReportGenerator._safe(e.plugin)}</td>"
            f"<td>{ReportGenerator._safe(e.version)}</td>"
            f"<td>{ReportGenerator._safe(e.parameters)}</td>"
            "</tr>"
            for e in case_data.executions
        ) or "<tr><td colspan='4'>No plugin executions recorded.</td></tr>"

        execution_details = []
        for idx, execution in enumerate(case_data.executions, start=1):
            if execution.parsed_header and execution.parsed_rows:
                header_html = "".join(
                    f"<th>{ReportGenerator._safe(col)}</th>" for col in execution.parsed_header
                )
                rows_html = "".join(
                    "<tr>"
                    + "".join(f"<td>{ReportGenerator._safe(cell)}</td>" for cell in row)
                    + "</tr>"
                    for row in execution.parsed_rows
                )
                details_html = (
                    f"<table><tr>{header_html}</tr>{rows_html}</table>"
                )
            else:
                details_html = (
                    "<p><i>No structured rows parsed for this execution.</i></p>"
                )
            execution_details.append(
                f"<h3>{idx}. {ReportGenerator._safe(execution.plugin)} "
                f"({ReportGenerator._safe(execution.timestamp)})</h3>{details_html}"
            )
        execution_details_html = "".join(execution_details) or "<p>No execution details available.</p>"

        finding_rows = "".join(
            "<tr>"
            f"<td>{ReportGenerator._safe(f.created_at)}</td>"
            f"<td>{ReportGenerator._safe(f.title)}</td>"
            f"<td>{ReportGenerator._safe(f.details)}</td>"
            f"<td>{ReportGenerator._safe(', '.join(f.tags))}</td>"
            f"<td>{ReportGenerator._safe(f.bookmarked)}</td>"
            "</tr>"
            for f in case_data.findings
        ) or "<tr><td colspan='5'>No findings recorded. Use Bookmark Selected Row to include artifacts here.</td></tr>"

        custody_items = "".join(
            f"<li>{ReportGenerator._safe(item)}</li>" for item in case_data.custody_log
        ) or "<li>No chain of custody events recorded.</li>"

        return f"""
<html>
<head>
<style>
body {{ font-family: Segoe UI, sans-serif; color: #111; }}
h1, h2 {{ color: #1f2937; }}
table {{ border-collapse: collapse; width: 100%; margin: 8px 0 16px 0; }}
th, td {{ border: 1px solid #d1d5db; padding: 6px; text-align: left; font-size: 12px; }}
th {{ background: #f3f4f6; }}
</style>
</head>
<body>
<h1>MemoraX Forensic Report</h1>
<h2>Case Information</h2>
<p><b>Case Number:</b> {ReportGenerator._safe(case_data.case_number)}<br>
<b>Investigator:</b> {ReportGenerator._safe(case_data.investigator)}<br>
<b>Evidence ID:</b> {ReportGenerator._safe(case_data.evidence_id)}<br>
<b>Notes:</b> {ReportGenerator._safe(case_data.notes)}</p>
<h2>Memory Image</h2>
<p><b>Path:</b> {ReportGenerator._safe(case_data.memory_image.path)}<br>
<b>Size:</b> {ReportGenerator._safe(case_data.memory_image.size)} bytes<br>
<b>SHA256:</b> {ReportGenerator._safe(case_data.memory_image.sha256)}<br>
<b>Verified:</b> {ReportGenerator._safe(case_data.memory_image.verified)}</p>
<h2>Chain of Custody</h2>
<ul>{custody_items}</ul>
<h2>Plugin Executions</h2>
<table><tr><th>Timestamp</th><th>Plugin</th><th>Version</th><th>Parameters</th></tr>{exec_rows}</table>
<h2>Execution Results</h2>
{execution_details_html}
<h2>Findings</h2>
<table><tr><th>Created</th><th>Title</th><th>Details</th><th>Tags</th><th>Bookmarked</th></tr>{finding_rows}</table>
</body></html>
"""

    @staticmethod
    def export_html(case_data: CaseData, target_path: str) -> None:
        Path(target_path).write_text(ReportGenerator._html(case_data), encoding="utf-8")

    @staticmethod
    def export_pdf(case_data: CaseData, target_path: str) -> None:
        app = QGuiApplication.instance()
        owned_app = None
        if app is None:
            owned_app = QGuiApplication([])

        writer = QPdfWriter(target_path)
        writer.setPageLayout(
            QPageLayout(
                QPageSize(QPageSize.PageSizeId.A4),
                QPageLayout.Orientation.Portrait,
                QMarginsF(24, 24, 24, 24),
            )
        )
        writer.setResolution(96)

        doc = QTextDocument()
        doc.setHtml(ReportGenerator._html(case_data))
        doc.setPageSize(QSizeF(writer.width(), writer.height()))
        doc.print(writer)

        if owned_app is not None:
            owned_app.quit()
