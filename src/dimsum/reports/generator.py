"""Report generation for scan findings.

Supports multiple output formats:
- JSON: Complete structured data
- CSV: Tabular findings export
- SARIF: Static Analysis Results Interchange Format (for CI/CD)
- HTML: Rendered report (can be converted to PDF with WeasyPrint)
"""

from __future__ import annotations

import csv
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def generate_json_report(scan_data: dict, findings: list[dict]) -> str:
    """Generate a JSON report."""
    report = {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "dimsum",
            "version": "0.1.0",
            "format": "json",
        },
        "scan": scan_data,
        "summary": _build_summary(findings),
        "findings": findings,
    }
    return json.dumps(report, indent=2, default=str)


def generate_csv_report(findings: list[dict]) -> str:
    """Generate a CSV report of findings."""
    output = io.StringIO()
    fieldnames = [
        "title", "severity", "confidence", "url", "method",
        "parameter", "plugin_id", "cwe_id", "cvss_score",
        "description", "remediation", "evidence",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        writer.writerow(f)
    return output.getvalue()


def generate_sarif_report(scan_data: dict, findings: list[dict]) -> str:
    """Generate a SARIF 2.1.0 report for CI/CD integration.

    SARIF (Static Analysis Results Interchange Format) is used by
    GitHub Advanced Security, Azure DevOps, and other tools.
    """
    rules: dict[str, dict] = {}
    results = []

    for f in findings:
        plugin_id = f.get("plugin_id", "unknown")
        if plugin_id not in rules:
            rules[plugin_id] = {
                "id": plugin_id,
                "name": plugin_id.replace("_", " ").title(),
                "shortDescription": {"text": f.get("title", plugin_id)},
                "fullDescription": {"text": f.get("description", "")},
                "helpUri": f"https://owasp.org/Top10/",
                "properties": {},
            }
            if f.get("cwe_id"):
                rules[plugin_id]["properties"]["tags"] = [f"CWE-{f['cwe_id']}"]

        severity_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }

        result = {
            "ruleId": plugin_id,
            "level": severity_map.get(f.get("severity", "info"), "note"),
            "message": {"text": f.get("description", f.get("title", ""))},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.get("url", ""),
                        },
                    },
                }
            ],
            "properties": {
                "severity": f.get("severity", "info"),
                "confidence": f.get("confidence", "tentative"),
            },
        }

        if f.get("source_file"):
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = f["source_file"]
            if f.get("source_line"):
                result["locations"][0]["physicalLocation"]["region"] = {
                    "startLine": f["source_line"]
                }

        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dimsum",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/devsecmatt/dimsum",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": scan_data.get("started_at", ""),
                        "endTimeUtc": scan_data.get("completed_at", ""),
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif, indent=2, default=str)


def generate_html_report(scan_data: dict, findings: list[dict]) -> str:
    """Generate an HTML report suitable for browser viewing or PDF conversion."""
    summary = _build_summary(findings)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    severity_colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#2563eb",
        "info": "#6b7280",
    }

    # Build findings HTML
    findings_html = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info")
        color = severity_colors.get(sev, "#6b7280")
        findings_html += f"""
        <div class="finding" style="border-left: 4px solid {color}; margin: 16px 0; padding: 12px 16px; background: #fafafa;">
            <h3 style="margin:0 0 8px 0;">
                <span style="display:inline-block; background:{color}; color:white; padding:2px 8px; border-radius:3px; font-size:12px; text-transform:uppercase; margin-right:8px;">{sev}</span>
                {_escape_html(f.get('title', 'Finding'))}
            </h3>
            <p><strong>URL:</strong> {_escape_html(f.get('url', 'N/A'))}</p>
            <p><strong>Plugin:</strong> {_escape_html(f.get('plugin_id', 'N/A'))} | <strong>CWE:</strong> {f.get('cwe_id', 'N/A')} | <strong>Confidence:</strong> {f.get('confidence', 'N/A')}</p>
            <p>{_escape_html(f.get('description', ''))}</p>
            {"<p><strong>Parameter:</strong> " + _escape_html(f.get('parameter', '')) + "</p>" if f.get('parameter') else ""}
            {"<p><strong>Evidence:</strong><br><code style='background:#f0f0f0;padding:4px 8px;display:block;white-space:pre-wrap;'>" + _escape_html(f.get('evidence', ''))[:500] + "</code></p>" if f.get('evidence') else ""}
            {"<p><strong>Remediation:</strong> " + _escape_html(f.get('remediation', '')) + "</p>" if f.get('remediation') else ""}
        </div>
"""

    # Severity chart data
    severity_rows = ""
    for sev in ("critical", "high", "medium", "low", "info"):
        count = summary["severity_counts"].get(sev, 0)
        if count > 0:
            color = severity_colors.get(sev, "#6b7280")
            bar_width = min(count * 30, 300)
            severity_rows += f"""
            <tr>
                <td style="text-transform:capitalize; padding:4px 12px;">{sev}</td>
                <td style="padding:4px 12px;">
                    <div style="background:{color}; height:20px; width:{bar_width}px; border-radius:3px; display:inline-block;"></div>
                    <strong>{count}</strong>
                </td>
            </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dimsum Scan Report — {_escape_html(scan_data.get('project_name', 'Scan'))}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 24px; color: #1a1a1a; }}
        h1 {{ border-bottom: 2px solid #1a1a1a; padding-bottom: 8px; }}
        table {{ border-collapse: collapse; }}
        .summary-box {{ display: flex; gap: 16px; margin: 16px 0; flex-wrap: wrap; }}
        .stat-card {{ background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 16px; min-width: 120px; text-align: center; }}
        .stat-card .number {{ font-size: 28px; font-weight: bold; }}
        .stat-card .label {{ font-size: 12px; text-transform: uppercase; color: #666; }}
        @media print {{ body {{ font-size: 11px; }} .finding {{ page-break-inside: avoid; }} }}
    </style>
</head>
<body>
    <h1>🥟 Dimsum Scan Report</h1>
    <p><strong>Generated:</strong> {generated_at}</p>
    <p><strong>Scan ID:</strong> {scan_data.get('scan_id', 'N/A')}</p>
    <p><strong>Status:</strong> {scan_data.get('status', 'N/A')} | <strong>Duration:</strong> {scan_data.get('duration_seconds', 'N/A')}s</p>

    <h2>Executive Summary</h2>
    <div class="summary-box">
        <div class="stat-card"><div class="number">{summary['total']}</div><div class="label">Total Findings</div></div>
        <div class="stat-card"><div class="number" style="color:#dc2626">{summary['severity_counts'].get('critical', 0)}</div><div class="label">Critical</div></div>
        <div class="stat-card"><div class="number" style="color:#ea580c">{summary['severity_counts'].get('high', 0)}</div><div class="label">High</div></div>
        <div class="stat-card"><div class="number" style="color:#d97706">{summary['severity_counts'].get('medium', 0)}</div><div class="label">Medium</div></div>
        <div class="stat-card"><div class="number" style="color:#2563eb">{summary['severity_counts'].get('low', 0)}</div><div class="label">Low</div></div>
        <div class="stat-card"><div class="number" style="color:#6b7280">{summary['severity_counts'].get('info', 0)}</div><div class="label">Info</div></div>
    </div>

    <h2>Severity Distribution</h2>
    <table>{severity_rows}</table>

    <h2>Findings ({summary['total']})</h2>
    {findings_html if findings_html else "<p>No findings.</p>"}

    <hr>
    <p style="font-size:11px; color:#888;">Generated by dimsum v0.1.0</p>
</body>
</html>"""

    return html


def _build_summary(findings: list[dict]) -> dict:
    severity_counts: dict[str, int] = {}
    plugin_counts: dict[str, int] = {}
    unique_urls: set[str] = set()

    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        pid = f.get("plugin_id", "unknown")
        plugin_counts[pid] = plugin_counts.get(pid, 0) + 1
        if f.get("url"):
            unique_urls.add(f["url"])

    return {
        "total": len(findings),
        "severity_counts": severity_counts,
        "plugin_counts": plugin_counts,
        "unique_urls": len(unique_urls),
    }


def _escape_html(text: str) -> str:
    """Basic HTML escaping."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
