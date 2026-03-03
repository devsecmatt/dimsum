from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import login_required

from dimsum.extensions import db
from dimsum.models.asvs_check import ASVSCheck

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

    checks = db.session.execute(query.order_by(ASVSCheck.asvs_id)).scalars().all()
    return jsonify([
        {
            "id": str(c.id),
            "asvs_id": c.asvs_id,
            "chapter": c.chapter,
            "section": c.section,
            "requirement": c.requirement,
            "level": c.level,
            "cwe_id": c.cwe_id,
            "can_be_automated": c.can_be_automated,
        }
        for c in checks
    ])


@asvs_bp.route("/checks/<asvs_id>", methods=["GET"])
@login_required
def get_asvs_check(asvs_id):
    check = db.session.execute(
        db.select(ASVSCheck).filter_by(asvs_id=asvs_id)
    ).scalar_one_or_none()
    if check is None:
        return jsonify({"error": "ASVS check not found"}), 404
    return jsonify({
        "id": str(check.id),
        "asvs_id": check.asvs_id,
        "chapter": check.chapter,
        "section": check.section,
        "requirement": check.requirement,
        "level": check.level,
        "cwe_id": check.cwe_id,
        "can_be_automated": check.can_be_automated,
        "plugin_ids": check.plugin_ids,
    })
