from __future__ import annotations

import hashlib
import os
import uuid

from flask import Blueprint, current_app, jsonify, request
from flask_login import login_required
from werkzeug.utils import secure_filename

from dimsum.extensions import db
from dimsum.models.project import Project
from dimsum.models.source_upload import SourceUpload
from dimsum.source_analysis.analyzer import analyze_source, detect_language

source_analysis_bp = Blueprint("api_source_analysis", __name__)

_ALLOWED_EXTENSIONS = {".js", ".jsx", ".mjs", ".ts", ".tsx", ".py"}


@source_analysis_bp.route("/<project_id>/source/upload", methods=["POST"])
@login_required
def upload_source(project_id):
    project = db.session.get(Project, uuid.UUID(project_id))
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in _ALLOWED_EXTENSIONS:
        return jsonify({"error": f"Unsupported file type. Allowed: {', '.join(sorted(_ALLOWED_EXTENSIONS))}"}), 400

    language = detect_language(file.filename)
    if not language:
        return jsonify({"error": "Could not detect language"}), 400

    content = file.read()
    file_hash = hashlib.sha256(content).hexdigest()

    # Check for duplicate
    existing = db.session.execute(
        db.select(SourceUpload).filter_by(project_id=project.id, file_hash=file_hash)
    ).scalar_one_or_none()
    if existing:
        return jsonify({"error": "This file has already been uploaded", "id": str(existing.id)}), 409

    # Save file
    upload_dir = os.path.join(current_app.config.get("UPLOAD_FOLDER", "/app/uploads"), "source", str(project.id))
    os.makedirs(upload_dir, exist_ok=True)
    safe_name = secure_filename(f"{uuid.uuid4().hex}_{file.filename}")
    file_path = os.path.join(upload_dir, safe_name)
    with open(file_path, "wb") as f:
        f.write(content)

    upload = SourceUpload(
        project_id=project.id,
        filename=file.filename,
        language=language,
        file_path=file_path,
        file_hash=file_hash,
        analysis_status="pending",
    )
    db.session.add(upload)
    db.session.commit()

    return jsonify(_serialize_upload(upload)), 201


@source_analysis_bp.route("/<project_id>/source/files", methods=["GET"])
@login_required
def list_source_files(project_id):
    project = db.session.get(Project, uuid.UUID(project_id))
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    uploads = db.session.execute(
        db.select(SourceUpload)
        .filter_by(project_id=project.id)
        .order_by(SourceUpload.created_at.desc())
    ).scalars().all()

    return jsonify([_serialize_upload(u) for u in uploads])


@source_analysis_bp.route("/<project_id>/source/analyze", methods=["POST"])
@login_required
def trigger_analysis(project_id):
    project = db.session.get(Project, uuid.UUID(project_id))
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    data = request.get_json(silent=True) or {}
    file_ids = data.get("file_ids")

    if file_ids:
        uploads = db.session.execute(
            db.select(SourceUpload).filter(
                SourceUpload.project_id == project.id,
                SourceUpload.id.in_([uuid.UUID(fid) for fid in file_ids]),
            )
        ).scalars().all()
    else:
        uploads = db.session.execute(
            db.select(SourceUpload).filter_by(project_id=project.id)
        ).scalars().all()

    if not uploads:
        return jsonify({"error": "No source files to analyze"}), 400

    results = []
    for upload in uploads:
        upload.analysis_status = "running"
        db.session.commit()

        try:
            with open(upload.file_path, "r", errors="replace") as f:
                content = f.read()

            analysis = analyze_source(content, upload.filename, upload.language)

            upload.extracted_routes = [
                {"path": r.path, "method": r.method, "line": r.line, "framework": r.framework}
                for r in analysis.routes
            ]
            upload.extracted_params = [
                {"name": p.name, "source": p.source, "line": p.line}
                for p in analysis.parameters
            ]
            upload.analysis_status = "completed"

            results.append(analysis.to_dict())

        except Exception as exc:
            upload.analysis_status = "failed"
            results.append({"file_path": upload.filename, "error": str(exc)[:500]})

        db.session.commit()

    return jsonify({
        "analyzed": len(results),
        "results": results,
    })


@source_analysis_bp.route("/<project_id>/source/results", methods=["GET"])
@login_required
def get_analysis_results(project_id):
    project = db.session.get(Project, uuid.UUID(project_id))
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    uploads = db.session.execute(
        db.select(SourceUpload).filter_by(project_id=project.id, analysis_status="completed")
    ).scalars().all()

    all_routes = []
    all_params = []
    all_risk_indicators = []

    for upload in uploads:
        for route in (upload.extracted_routes or []):
            route["file"] = upload.filename
            all_routes.append(route)

        for param in (upload.extracted_params or []):
            param["file"] = upload.filename
            all_params.append(param)

    # Re-run risk analysis for results endpoint
    for upload in uploads:
        try:
            with open(upload.file_path, "r", errors="replace") as f:
                content = f.read()
            analysis = analyze_source(content, upload.filename, upload.language)
            for ri in analysis.risk_indicators:
                all_risk_indicators.append({
                    "pattern_name": ri.pattern_name,
                    "description": ri.description,
                    "severity": ri.severity,
                    "file": ri.file,
                    "line": ri.line,
                    "code_snippet": ri.code_snippet,
                    "cwe_id": ri.cwe_id,
                })
        except Exception:
            pass

    return jsonify({
        "routes": all_routes,
        "parameters": all_params,
        "risk_indicators": all_risk_indicators,
    })


@source_analysis_bp.route("/<project_id>/source/<upload_id>", methods=["DELETE"])
@login_required
def delete_source_file(project_id, upload_id):
    upload = db.session.get(SourceUpload, uuid.UUID(upload_id))
    if upload is None or str(upload.project_id) != project_id:
        return jsonify({"error": "Source file not found"}), 404

    if os.path.exists(upload.file_path):
        os.remove(upload.file_path)

    db.session.delete(upload)
    db.session.commit()
    return jsonify({"message": "Source file deleted"})


def _serialize_upload(u: SourceUpload) -> dict:
    return {
        "id": str(u.id),
        "filename": u.filename,
        "language": u.language,
        "file_hash": u.file_hash,
        "analysis_status": u.analysis_status,
        "routes_count": len(u.extracted_routes) if u.extracted_routes else 0,
        "params_count": len(u.extracted_params) if u.extracted_params else 0,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }
