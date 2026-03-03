from __future__ import annotations

import uuid

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required
from marshmallow import ValidationError

from dimsum.api.schemas import ScanConfigCreateSchema, ScanConfigUpdateSchema
from dimsum.extensions import db
from dimsum.models.project import Project
from dimsum.models.scan_config import ScanConfiguration

scan_configs_bp = Blueprint("api_scan_configs", __name__)

_create_schema = ScanConfigCreateSchema()
_update_schema = ScanConfigUpdateSchema()


@scan_configs_bp.route("/<project_id>/configs", methods=["GET"])
@login_required
def list_configs(project_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    configs = db.session.execute(
        db.select(ScanConfiguration)
        .filter_by(project_id=project.id)
        .order_by(ScanConfiguration.updated_at.desc())
    ).scalars().all()
    return jsonify([_serialize_config(c) for c in configs])


@scan_configs_bp.route("/<project_id>/configs", methods=["POST"])
@login_required
def create_config(project_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    data = request.get_json(silent=True) or {}
    try:
        validated = _create_schema.load(data)
    except ValidationError as err:
        return jsonify({"error": "Validation failed", "details": err.messages}), 400

    config = ScanConfiguration(project_id=project.id, **validated)
    db.session.add(config)
    db.session.commit()
    return jsonify(_serialize_config(config)), 201


@scan_configs_bp.route("/<project_id>/configs/<config_id>", methods=["GET"])
@login_required
def get_config(project_id, config_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    config = _get_config(project.id, config_id)
    if config is None:
        return jsonify({"error": "Configuration not found"}), 404
    return jsonify(_serialize_config(config))


@scan_configs_bp.route("/<project_id>/configs/<config_id>", methods=["PUT"])
@login_required
def update_config(project_id, config_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    config = _get_config(project.id, config_id)
    if config is None:
        return jsonify({"error": "Configuration not found"}), 404

    data = request.get_json(silent=True) or {}
    try:
        validated = _update_schema.load(data)
    except ValidationError as err:
        return jsonify({"error": "Validation failed", "details": err.messages}), 400

    for key, value in validated.items():
        setattr(config, key, value)
    db.session.commit()
    return jsonify(_serialize_config(config))


@scan_configs_bp.route("/<project_id>/configs/<config_id>", methods=["DELETE"])
@login_required
def delete_config(project_id, config_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    config = _get_config(project.id, config_id)
    if config is None:
        return jsonify({"error": "Configuration not found"}), 404

    db.session.delete(config)
    db.session.commit()
    return jsonify({"message": "Configuration deleted"})


def _get_user_project(project_id: str) -> Project | None:
    try:
        pid = uuid.UUID(project_id)
    except ValueError:
        return None
    return db.session.execute(
        db.select(Project).filter_by(id=pid, owner_id=current_user.id)
    ).scalar_one_or_none()


def _get_config(project_id: uuid.UUID, config_id: str) -> ScanConfiguration | None:
    try:
        cid = uuid.UUID(config_id)
    except ValueError:
        return None
    return db.session.execute(
        db.select(ScanConfiguration).filter_by(id=cid, project_id=project_id)
    ).scalar_one_or_none()


def _serialize_config(c: ScanConfiguration) -> dict:
    return {
        "id": str(c.id),
        "name": c.name,
        "enabled_plugins": c.enabled_plugins,
        "max_concurrency": c.max_concurrency,
        "request_delay_ms": c.request_delay_ms,
        "timeout_seconds": c.timeout_seconds,
        "max_depth": c.max_depth,
        "custom_headers": c.custom_headers,
        "auth_config": c.auth_config,
        "wordlist_ids": c.wordlist_ids,
        "enable_enumeration": c.enable_enumeration,
        "enable_source_analysis": c.enable_source_analysis,
        "asvs_level": c.asvs_level,
        "created_at": c.created_at.isoformat(),
        "updated_at": c.updated_at.isoformat(),
    }
