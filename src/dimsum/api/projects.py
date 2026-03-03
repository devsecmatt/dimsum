from __future__ import annotations

import uuid

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from dimsum.extensions import db
from dimsum.models.project import Project

projects_bp = Blueprint("api_projects", __name__)


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
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "Project name is required"}), 400

    project = Project(name=name, description=data.get("description"), owner_id=current_user.id)
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
    if "name" in data:
        project.name = data["name"].strip()
    if "description" in data:
        project.description = data["description"]
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


def _get_user_project(project_id: str) -> Project | None:
    try:
        pid = uuid.UUID(project_id)
    except ValueError:
        return None
    return db.session.execute(
        db.select(Project).filter_by(id=pid, owner_id=current_user.id)
    ).scalar_one_or_none()
