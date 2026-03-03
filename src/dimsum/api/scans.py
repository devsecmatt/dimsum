from __future__ import annotations

import uuid

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from dimsum.extensions import db
from dimsum.models.project import Project
from dimsum.models.scan import Scan

scans_bp = Blueprint("api_scans", __name__)


@scans_bp.route("/<project_id>/scans", methods=["GET"])
@login_required
def list_scans(project_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    scans = db.session.execute(
        db.select(Scan).filter_by(project_id=project.id).order_by(Scan.created_at.desc())
    ).scalars().all()
    return jsonify([_serialize_scan(s) for s in scans])


@scans_bp.route("/<project_id>/scans", methods=["POST"])
@login_required
def create_scan(project_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    data = request.get_json(silent=True) or {}
    scan = Scan(
        project_id=project.id,
        scan_type=data.get("scan_type", "full"),
        target_ids=data.get("target_ids", []),
        config_id=data.get("config_id"),
    )
    db.session.add(scan)
    db.session.commit()

    # Dispatch Celery task
    try:
        from dimsum.tasks.scan_tasks import run_scan
        task = run_scan.delay(str(scan.id))
        scan.celery_task_id = task.id
        db.session.commit()
    except Exception:
        # Celery may not be available in dev; scan stays as 'pending'
        pass

    return jsonify(_serialize_scan(scan)), 201


@scans_bp.route("/<project_id>/scans/<scan_id>", methods=["GET"])
@login_required
def get_scan(project_id, scan_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    scan = _get_scan(project.id, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(_serialize_scan(scan))


@scans_bp.route("/<project_id>/scans/<scan_id>/progress", methods=["GET"])
@login_required
def get_scan_progress(project_id, scan_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    scan = _get_scan(project.id, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    return jsonify({
        "status": scan.status,
        "progress_percent": scan.progress_percent,
        "progress_message": scan.progress_message,
        "summary_stats": scan.summary_stats,
    })


@scans_bp.route("/<project_id>/scans/<scan_id>/cancel", methods=["POST"])
@login_required
def cancel_scan(project_id, scan_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    scan = _get_scan(project.id, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    if scan.status not in ("pending", "running"):
        return jsonify({"error": "Scan cannot be cancelled"}), 400

    if scan.celery_task_id:
        from dimsum.celery_app import celery
        celery.control.revoke(scan.celery_task_id, terminate=True)

    scan.status = "cancelled"
    db.session.commit()
    return jsonify({"message": "Scan cancelled"})


def _get_user_project(project_id: str) -> Project | None:
    try:
        pid = uuid.UUID(project_id)
    except ValueError:
        return None
    return db.session.execute(
        db.select(Project).filter_by(id=pid, owner_id=current_user.id)
    ).scalar_one_or_none()


def _get_scan(project_id: uuid.UUID, scan_id: str) -> Scan | None:
    try:
        sid = uuid.UUID(scan_id)
    except ValueError:
        return None
    return db.session.execute(
        db.select(Scan).filter_by(id=sid, project_id=project_id)
    ).scalar_one_or_none()


def _serialize_scan(s: Scan) -> dict:
    return {
        "id": str(s.id),
        "status": s.status,
        "scan_type": s.scan_type,
        "target_ids": s.target_ids,
        "progress_percent": s.progress_percent,
        "progress_message": s.progress_message,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        "duration_seconds": s.duration_seconds,
        "total_requests": s.total_requests,
        "error_message": s.error_message,
        "summary_stats": s.summary_stats,
        "created_at": s.created_at.isoformat(),
    }
