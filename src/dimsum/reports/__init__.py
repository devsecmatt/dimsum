"""Report generation for dimsum DAST scanner."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dimsum.models.finding import Finding
    from dimsum.models.scan import Scan


def _serialize_finding(f: Finding) -> dict:
    return {
        "title": f.title,
        "severity": f.severity,
        "confidence": f.confidence,
        "url": f.url,
        "method": f.method,
        "parameter": f.parameter,
        "cwe_id": f.cwe_id,
        "cvss_score": f.cvss_score,
        "plugin_id": f.plugin_id,
        "description": f.description,
        "payload": f.payload,
        "evidence": f.evidence,
        "remediation": f.remediation,
        "is_false_positive": f.is_false_positive,
        "request_dump": f.request_dump,
        "response_dump": f.response_dump,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


def generate_json_report(scan: Scan, findings: list[Finding]) -> str:
    """Generate a JSON report from scan and findings data."""
    report = {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool": "dimsum",
            "version": "0.1.0",
        },
        "scan": {
            "id": str(scan.id),
            "project_id": str(scan.project_id),
            "scan_type": scan.scan_type,
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration_seconds": scan.duration_seconds,
            "total_requests": scan.total_requests,
            "summary_stats": scan.summary_stats,
        },
        "findings": [_serialize_finding(f) for f in findings],
        "summary": {
            "total_findings": len(findings),
            "severity_counts": _count_severities(findings),
        },
    }
    return json.dumps(report, indent=2, default=str)


def generate_csv_report(scan: Scan, findings: list[Finding]) -> str:
    """Generate a CSV report from findings data."""
    output = io.StringIO()
    writer = csv.writer(output)

    columns = [
        "title", "severity", "confidence", "url", "method", "parameter",
        "cwe_id", "cvss_score", "plugin_id", "description", "payload",
        "evidence", "remediation", "is_false_positive", "created_at",
    ]
    writer.writerow(columns)

    for f in findings:
        writer.writerow([
            f.title, f.severity, f.confidence, f.url, f.method, f.parameter,
            f.cwe_id, f.cvss_score, f.plugin_id, f.description, f.payload,
            f.evidence, f.remediation, f.is_false_positive,
            f.created_at.isoformat() if f.created_at else "",
        ])

    return output.getvalue()


def _count_severities(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
