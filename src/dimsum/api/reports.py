from __future__ import annotations

import uuid

from flask import Blueprint, Response, jsonify, request
from flask_login import login_required

from dimsum.extensions import db
from dimsum.models.finding import Finding
from dimsum.models.scan import Scan
from dimsum.reports.generator import (
    generate_csv_report,
    generate_html_report,
    generate_json_report,
    generate_sarif_report,
)

reports_bp = Blueprint("api_reports", __name__)

_VALID_FORMATS = ("json", "csv", "sarif", "html")


@reports_bp.route("/generate", methods=["POST"])
@login_required
def generate_report():
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan_id")
    report_format = data.get("format", "json")

    if not scan_id:
        return jsonify({"error": "scan_id is required"}), 400
    if report_format not in _VALID_FORMATS:
        return jsonify({"error": f"Invalid format. Choose: {', '.join(_VALID_FORMATS)}"}), 400

    try:
        sid = uuid.UUID(scan_id)
    except ValueError:
        return jsonify({"error": "Invalid scan_id"}), 400

    scan = db.session.get(Scan, sid)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    findings_orm = db.session.execute(
        db.select(Finding).filter_by(scan_id=scan.id).order_by(
            db.case(
                (Finding.severity == "critical", 0),
                (Finding.severity == "high", 1),
                (Finding.severity == "medium", 2),
                (Finding.severity == "low", 3),
                (Finding.severity == "info", 4),
                else_=5,
            )
        )
    ).scalars().all()

    findings = [_serialize_finding(f) for f in findings_orm]
    scan_data = _serialize_scan(scan)
    short_id = scan_id[:8]

    if report_format == "json":
        content = generate_json_report(scan_data, findings)
        return Response(content, mimetype="application/json", headers={
            "Content-Disposition": f"attachment; filename=dimsum-report-{short_id}.json"
        })
    elif report_format == "csv":
        content = generate_csv_report(findings)
        return Response(content, mimetype="text/csv", headers={
            "Content-Disposition": f"attachment; filename=dimsum-report-{short_id}.csv"
        })
    elif report_format == "sarif":
        content = generate_sarif_report(scan_data, findings)
        return Response(content, mimetype="application/json", headers={
            "Content-Disposition": f"attachment; filename=dimsum-report-{short_id}.sarif.json"
        })
    elif report_format == "html":
        content = generate_html_report(scan_data, findings)
        return Response(content, mimetype="text/html", headers={
            "Content-Disposition": f"attachment; filename=dimsum-report-{short_id}.html"
        })


@reports_bp.route("/preview/<scan_id>", methods=["GET"])
@login_required
def preview_report(scan_id):
    """Preview the HTML report inline (no download header)."""
    try:
        sid = uuid.UUID(scan_id)
    except ValueError:
        return jsonify({"error": "Invalid scan_id"}), 400

    scan = db.session.get(Scan, sid)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    findings_orm = db.session.execute(
        db.select(Finding).filter_by(scan_id=scan.id)
    ).scalars().all()

    findings = [_serialize_finding(f) for f in findings_orm]
    scan_data = _serialize_scan(scan)
    content = generate_html_report(scan_data, findings)
    return Response(content, mimetype="text/html")


@reports_bp.route("/summary/<scan_id>", methods=["GET"])
@login_required
def report_summary(scan_id):
    """Quick summary without full report generation."""
    try:
        sid = uuid.UUID(scan_id)
    except ValueError:
        return jsonify({"error": "Invalid scan_id"}), 400

    scan = db.session.get(Scan, sid)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    findings_orm = db.session.execute(
        db.select(Finding).filter_by(scan_id=scan.id)
    ).scalars().all()

    severity_counts: dict[str, int] = {}
    plugin_counts: dict[str, int] = {}

    for f in findings_orm:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        plugin_counts[f.plugin_id] = plugin_counts.get(f.plugin_id, 0) + 1

    return jsonify({
        "scan_id": str(scan.id),
        "status": scan.status,
        "total_findings": len(findings_orm),
        "severity_counts": severity_counts,
        "plugin_counts": plugin_counts,
        "available_formats": list(_VALID_FORMATS),
    })


def _serialize_finding(f: Finding) -> dict:
    return {
        "id": str(f.id),
        "plugin_id": f.plugin_id,
        "title": f.title,
        "description": f.description,
        "severity": f.severity,
        "confidence": f.confidence,
        "url": f.url,
        "method": f.method,
        "parameter": f.parameter,
        "payload": f.payload,
        "evidence": f.evidence,
        "cwe_id": f.cwe_id,
        "cvss_score": f.cvss_score,
        "remediation": f.remediation,
        "is_false_positive": f.is_false_positive,
        "source_file": f.source_file,
        "source_line": f.source_line,
    }


def _serialize_scan(scan: Scan) -> dict:
    return {
        "scan_id": str(scan.id),
        "project_id": str(scan.project_id),
        "status": scan.status,
        "scan_type": scan.scan_type,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "duration_seconds": scan.duration_seconds,
        "total_requests": scan.total_requests,
        "summary_stats": scan.summary_stats,
    }
