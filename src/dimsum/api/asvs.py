from __future__ import annotations

import uuid

from flask import Blueprint, jsonify, request
from flask_login import login_required

from dimsum.asvs.compliance import analyze_compliance
from dimsum.extensions import db
from dimsum.models.asvs_check import ASVSCheck
from dimsum.models.finding import Finding
from dimsum.models.scan import Scan

asvs_bp = Blueprint("api_asvs", __name__)


@asvs_bp.route("/checks", methods=["GET"])
@login_required
def list_asvs_checks():
    query = db.select(ASVSCheck)

    chapter = request.args.get("chapter", type=int)
    if chapter:
        query = query.filter_by(chapter=chapter)

    level = request.args.get("level", type=int)
    if level:
        query = query.filter(ASVSCheck.level <= level)

    automatable = request.args.get("automatable")
    if automatable is not None:
        query = query.filter_by(can_be_automated=automatable.lower() == "true")

    checks = db.session.execute(query.order_by(ASVSCheck.asvs_id)).scalars().all()
    return jsonify([_serialize_check(c) for c in checks])


@asvs_bp.route("/checks/<asvs_id>", methods=["GET"])
@login_required
def get_asvs_check(asvs_id):
    check = db.session.execute(
        db.select(ASVSCheck).filter_by(asvs_id=asvs_id)
    ).scalar_one_or_none()
    if check is None:
        return jsonify({"error": "ASVS check not found"}), 404
    result = _serialize_check(check)
    result["plugin_ids"] = check.plugin_ids
    return jsonify(result)


@asvs_bp.route("/compliance/<scan_id>", methods=["GET"])
@login_required
def get_compliance_report(scan_id):
    """Generate an ASVS compliance report for a completed scan."""
    try:
        sid = uuid.UUID(scan_id)
    except ValueError:
        return jsonify({"error": "Invalid scan_id"}), 400

    scan = db.session.get(Scan, sid)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    asvs_level = request.args.get("level", 1, type=int)
    if asvs_level not in (1, 2, 3):
        return jsonify({"error": "ASVS level must be 1, 2, or 3"}), 400

    checks_orm = db.session.execute(
        db.select(ASVSCheck).order_by(ASVSCheck.asvs_id)
    ).scalars().all()
    checks = [
        {
            "asvs_id": c.asvs_id, "chapter": c.chapter, "section": c.section,
            "requirement": c.requirement, "level": c.level, "cwe_id": c.cwe_id,
            "can_be_automated": c.can_be_automated, "plugin_ids": c.plugin_ids or [],
        }
        for c in checks_orm
    ]

    findings_orm = db.session.execute(
        db.select(Finding).filter_by(scan_id=scan.id)
    ).scalars().all()
    findings = [
        {"plugin_id": f.plugin_id, "severity": f.severity, "cwe_id": f.cwe_id, "title": f.title, "url": f.url}
        for f in findings_orm
    ]

    report = analyze_compliance(checks, findings, asvs_level=asvs_level)

    return jsonify({"scan_id": str(scan.id), "scan_status": scan.status, **report.to_dict()})


@asvs_bp.route("/gaps/<scan_id>", methods=["GET"])
@login_required
def get_compliance_gaps(scan_id):
    """Get only the failed and not-tested ASVS checks for gap analysis."""
    try:
        sid = uuid.UUID(scan_id)
    except ValueError:
        return jsonify({"error": "Invalid scan_id"}), 400

    scan = db.session.get(Scan, sid)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    asvs_level = request.args.get("level", 1, type=int)

    checks_orm = db.session.execute(
        db.select(ASVSCheck).order_by(ASVSCheck.asvs_id)
    ).scalars().all()
    checks = [
        {
            "asvs_id": c.asvs_id, "chapter": c.chapter, "section": c.section,
            "requirement": c.requirement, "level": c.level, "cwe_id": c.cwe_id,
            "can_be_automated": c.can_be_automated, "plugin_ids": c.plugin_ids or [],
        }
        for c in checks_orm
    ]

    findings_orm = db.session.execute(
        db.select(Finding).filter_by(scan_id=scan.id)
    ).scalars().all()
    findings = [
        {"plugin_id": f.plugin_id, "severity": f.severity, "cwe_id": f.cwe_id, "title": f.title, "url": f.url}
        for f in findings_orm
    ]

    report = analyze_compliance(checks, findings, asvs_level=asvs_level)
    gaps = [c.to_dict() for c in report.checks if c.status in ("fail", "not_tested")]

    return jsonify({
        "scan_id": str(scan.id),
        "asvs_level": asvs_level,
        "total_gaps": len(gaps),
        "failed": sum(1 for g in gaps if g["status"] == "fail"),
        "not_tested": sum(1 for g in gaps if g["status"] == "not_tested"),
        "gaps": gaps,
    })


@asvs_bp.route("/seed", methods=["POST"])
@login_required
def seed_checks():
    """Seed or update the ASVS checks database."""
    from dimsum.asvs.seeder import seed_asvs_checks
    count = seed_asvs_checks()
    return jsonify({"message": f"Seeded {count} new ASVS checks"})


def _serialize_check(c: ASVSCheck) -> dict:
    return {
        "id": str(c.id),
        "asvs_id": c.asvs_id,
        "chapter": c.chapter,
        "section": c.section,
        "requirement": c.requirement,
        "level": c.level,
        "cwe_id": c.cwe_id,
        "can_be_automated": c.can_be_automated,
    }
