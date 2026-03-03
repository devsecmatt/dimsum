from __future__ import annotations

import json
import uuid

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required
from marshmallow import ValidationError

from dimsum.api.schemas import APISpecImportSchema, TargetCreateSchema, URLListImportSchema
from dimsum.extensions import db
from dimsum.models.project import Project
from dimsum.models.target import Target
from dimsum.utils.validators import validate_api_spec, validate_target

targets_bp = Blueprint("api_targets", __name__)

_create_schema = TargetCreateSchema()
_spec_schema = APISpecImportSchema()
_url_list_schema = URLListImportSchema()


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
    try:
        validated = _create_schema.load(data)
    except ValidationError as err:
        return jsonify({"error": "Validation failed", "details": err.messages}), 400

    is_valid, normalized, error_msg = validate_target(validated["target_type"], validated["value"])
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    target = Target(
        project_id=project.id,
        target_type=validated["target_type"],
        value=normalized,
        api_spec_format=validated.get("api_spec_format"),
        api_spec_content=validated.get("api_spec_content"),
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
    try:
        validated = _spec_schema.load(data)
    except ValidationError as err:
        return jsonify({"error": "Validation failed", "details": err.messages}), 400

    spec_content = validated["spec"]
    if isinstance(spec_content, str):
        try:
            spec_content = json.loads(spec_content)
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON in spec"}), 400

    spec_valid, spec_error = validate_api_spec(spec_content, validated["format"])
    if not spec_valid:
        return jsonify({"error": spec_error}), 400

    is_valid, normalized_url, url_error = validate_target("api_spec", validated["base_url"])
    if not is_valid:
        return jsonify({"error": url_error}), 400

    target = Target(
        project_id=project.id,
        target_type="api_spec",
        value=normalized_url,
        api_spec_format=validated["format"],
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
    try:
        validated = _url_list_schema.load(data)
    except ValidationError as err:
        return jsonify({"error": "Validation failed", "details": err.messages}), 400

    created = []
    errors = []
    for url in validated["urls"]:
        is_valid, normalized, error_msg = validate_target("url", url)
        if is_valid:
            target = Target(project_id=project.id, target_type="url", value=normalized)
            db.session.add(target)
            created.append(target)
        else:
            errors.append(error_msg)

    db.session.commit()
    result = {"created": len(created)}
    if errors:
        result["errors"] = errors
    return jsonify(result), 201


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
