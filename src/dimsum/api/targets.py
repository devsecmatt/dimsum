from __future__ import annotations

import json
import uuid

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from dimsum.extensions import db
from dimsum.models.project import Project
from dimsum.models.target import Target

targets_bp = Blueprint("api_targets", __name__)


@targets_bp.route("/<project_id>/targets", methods=["GET"])
@login_required
def list_targets(project_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    targets = db.session.execute(
        db.select(Target).filter_by(project_id=project.id, is_active=True).order_by(Target.created_at.desc())
    ).scalars().all()
    return jsonify([_serialize_target(t) for t in targets])


@targets_bp.route("/<project_id>/targets", methods=["POST"])
@login_required
def create_target(project_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    data = request.get_json(silent=True) or {}
    target_type = data.get("target_type", "").strip()
    value = data.get("value", "").strip()

    if target_type not in ("url", "url_list", "domain", "ip", "api_spec"):
        return jsonify({"error": "Invalid target_type"}), 400
    if not value:
        return jsonify({"error": "Target value is required"}), 400

    target = Target(
        project_id=project.id,
        target_type=target_type,
        value=value,
        api_spec_format=data.get("api_spec_format"),
        api_spec_content=data.get("api_spec_content"),
    )
    db.session.add(target)
    db.session.commit()
    return jsonify(_serialize_target(target)), 201


@targets_bp.route("/<project_id>/targets/import-spec", methods=["POST"])
@login_required
def import_api_spec(project_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    data = request.get_json(silent=True) or {}
    base_url = data.get("base_url", "").strip()
    spec_format = data.get("format", "openapi_3")
    spec_content = data.get("spec")

    if not base_url or not spec_content:
        return jsonify({"error": "base_url and spec are required"}), 400

    if isinstance(spec_content, str):
        try:
            spec_content = json.loads(spec_content)
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON in spec"}), 400

    target = Target(
        project_id=project.id,
        target_type="api_spec",
        value=base_url,
        api_spec_format=spec_format,
        api_spec_content=spec_content,
    )
    db.session.add(target)
    db.session.commit()
    return jsonify(_serialize_target(target)), 201


@targets_bp.route("/<project_id>/targets/import-urls", methods=["POST"])
@login_required
def import_url_list(project_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    data = request.get_json(silent=True) or {}
    urls = data.get("urls", [])
    if not urls:
        return jsonify({"error": "urls list is required"}), 400

    created = []
    for url in urls:
        url = url.strip()
        if url:
            target = Target(project_id=project.id, target_type="url", value=url)
            db.session.add(target)
            created.append(target)
    db.session.commit()
    return jsonify({"created": len(created)}), 201


@targets_bp.route("/<project_id>/targets/<target_id>", methods=["GET"])
@login_required
def get_target(project_id, target_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    target = _get_target(project.id, target_id)
    if target is None:
        return jsonify({"error": "Target not found"}), 404
    return jsonify(_serialize_target(target))


@targets_bp.route("/<project_id>/targets/<target_id>", methods=["DELETE"])
@login_required
def delete_target(project_id, target_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    target = _get_target(project.id, target_id)
    if target is None:
        return jsonify({"error": "Target not found"}), 404

    target.is_active = False
    db.session.commit()
    return jsonify({"message": "Target deleted"})


def _get_user_project(project_id: str) -> Project | None:
    try:
        pid = uuid.UUID(project_id)
    except ValueError:
        return None
    return db.session.execute(
        db.select(Project).filter_by(id=pid, owner_id=current_user.id)
    ).scalar_one_or_none()


def _get_target(project_id: uuid.UUID, target_id: str) -> Target | None:
    try:
        tid = uuid.UUID(target_id)
    except ValueError:
        return None
    return db.session.execute(
        db.select(Target).filter_by(id=tid, project_id=project_id)
    ).scalar_one_or_none()


def _serialize_target(t: Target) -> dict:
    return {
        "id": str(t.id),
        "target_type": t.target_type,
        "value": t.value,
        "api_spec_format": t.api_spec_format,
        "is_active": t.is_active,
        "created_at": t.created_at.isoformat(),
    }
