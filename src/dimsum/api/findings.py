from __future__ import annotations

import uuid

from flask import Blueprint, jsonify, request
from flask_login import login_required
from marshmallow import ValidationError

from dimsum.api.schemas import FindingUpdateSchema
from dimsum.extensions import db
from dimsum.models.finding import Finding
from dimsum.utils.pagination import get_pagination_params

findings_bp = Blueprint("api_findings", __name__)

_update_schema = FindingUpdateSchema()


@findings_bp.route("/", methods=["GET"])
@login_required
def list_findings():
    query = db.select(Finding)

    scan_id = request.args.get("scan_id")
    if scan_id:
        query = query.filter_by(scan_id=uuid.UUID(scan_id))

    severity = request.args.get("severity")
    if severity:
        query = query.filter_by(severity=severity)

    plugin_id = request.args.get("plugin_id")
    if plugin_id:
        query = query.filter_by(plugin_id=plugin_id)

    false_positive = request.args.get("false_positive")
    if false_positive is not None:
        query = query.filter_by(is_false_positive=false_positive.lower() == "true")

    query = query.order_by(Finding.created_at.desc())

    page, per_page, offset = get_pagination_params()

    findings = db.session.execute(query.offset(offset).limit(per_page)).scalars().all()
    return jsonify([_serialize_finding(f) for f in findings])


@findings_bp.route("/<finding_id>", methods=["GET"])
@login_required
def get_finding(finding_id):
    finding = _get_finding(finding_id)
    if finding is None:
        return jsonify({"error": "Finding not found"}), 404
    return jsonify(_serialize_finding(finding, full=True))


@findings_bp.route("/<finding_id>", methods=["PATCH"])
@login_required
def update_finding(finding_id):
    finding = _get_finding(finding_id)
    if finding is None:
        return jsonify({"error": "Finding not found"}), 404

    data = request.get_json(silent=True) or {}
    try:
        validated = _update_schema.load(data)
    except ValidationError as err:
        return jsonify({"error": "Validation failed", "details": err.messages}), 400

    if "is_false_positive" in validated:
        finding.is_false_positive = validated["is_false_positive"]
    if "notes" in validated:
        finding.notes = validated["notes"]
    db.session.commit()
    return jsonify(_serialize_finding(finding))


def _get_finding(finding_id: str) -> Finding | None:
    try:
        fid = uuid.UUID(finding_id)
    except ValueError:
        return None
    return db.session.get(Finding, fid)


def _serialize_finding(f: Finding, full: bool = False) -> dict:
    data = {
        "id": str(f.id),
        "scan_id": str(f.scan_id),
        "plugin_id": f.plugin_id,
        "title": f.title,
        "severity": f.severity,
        "confidence": f.confidence,
        "url": f.url,
        "method": f.method,
        "parameter": f.parameter,
        "cwe_id": f.cwe_id,
        "cvss_score": f.cvss_score,
        "is_false_positive": f.is_false_positive,
        "created_at": f.created_at.isoformat(),
    }
    if full:
        data.update({
            "description": f.description,
            "payload": f.payload,
            "evidence": f.evidence,
            "request_dump": f.request_dump,
            "response_dump": f.response_dump,
            "remediation": f.remediation,
            "notes": f.notes,
            "source_file": f.source_file,
            "source_line": f.source_line,
        })
    return data
