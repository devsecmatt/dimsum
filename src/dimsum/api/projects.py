from __future__ import annotations

import uuid

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required
from marshmallow import ValidationError

from dimsum.api.schemas import ProjectCreateSchema, ProjectUpdateSchema
from dimsum.extensions import db
from dimsum.models.project import Project

projects_bp = Blueprint("api_projects", __name__)

_create_schema = ProjectCreateSchema()
_update_schema = ProjectUpdateSchema()


@projects_bp.route("/", methods=["GET"])
@login_required
def list_projects():
    projects = db.session.execute(
        db.select(Project).filter_by(owner_id=current_user.id).order_by(Project.updated_at.desc())
    ).scalars().all()
    return jsonify([
        {
            "id": str(p.id),
            "name": p.name,
            "description": p.description,
            "created_at": p.created_at.isoformat(),
            "updated_at": p.updated_at.isoformat(),
        }
        for p in projects
    ])


@projects_bp.route("/", methods=["POST"])
@login_required
def create_project():
    data = request.get_json(silent=True) or {}
    try:
        validated = _create_schema.load(data)
    except ValidationError as err:
        return jsonify({"error": "Validation failed", "details": err.messages}), 400

    project = Project(
        name=validated["name"],
        description=validated.get("description"),
        owner_id=current_user.id,
    )
    db.session.add(project)
    db.session.commit()
    return jsonify({"id": str(project.id), "name": project.name}), 201


@projects_bp.route("/<project_id>", methods=["GET"])
@login_required
def get_project(project_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404
    return jsonify({
        "id": str(project.id),
        "name": project.name,
        "description": project.description,
        "created_at": project.created_at.isoformat(),
        "updated_at": project.updated_at.isoformat(),
        "target_count": len(project.targets),
        "scan_count": len(project.scans),
    })


@projects_bp.route("/<project_id>", methods=["PUT"])
@login_required
def update_project(project_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    data = request.get_json(silent=True) or {}
    try:
        validated = _update_schema.load(data)
    except ValidationError as err:
        return jsonify({"error": "Validation failed", "details": err.messages}), 400

    if "name" in validated:
        project.name = validated["name"]
    if "description" in validated:
        project.description = validated["description"]
    db.session.commit()
    return jsonify({"id": str(project.id), "name": project.name})


@projects_bp.route("/<project_id>", methods=["DELETE"])
@login_required
def delete_project(project_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    db.session.delete(project)
    db.session.commit()
    return jsonify({"message": "Project deleted"})


@projects_bp.route("/<project_id>/stats", methods=["GET"])
@login_required
def get_project_stats(project_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    from dimsum.models.finding import Finding
    from dimsum.models.scan import Scan

    scan_count = db.session.execute(
        db.select(db.func.count(Scan.id)).filter_by(project_id=project.id)
    ).scalar()

    finding_counts = {}
    for severity in ("critical", "high", "medium", "low", "info"):
        count = db.session.execute(
            db.select(db.func.count(Finding.id))
            .join(Scan)
            .filter(Scan.project_id == project.id, Finding.severity == severity)
        ).scalar()
        finding_counts[severity] = count

    return jsonify({
        "project_id": str(project.id),
        "scan_count": scan_count,
        "finding_counts": finding_counts,
        "total_findings": sum(finding_counts.values()),
    })


def _get_user_project(project_id: str) -> Project | None:
    try:
        pid = uuid.UUID(project_id)
    except ValueError:
        return None
    return db.session.execute(
        db.select(Project).filter_by(id=pid, owner_id=current_user.id)
    ).scalar_one_or_none()
