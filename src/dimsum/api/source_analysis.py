from __future__ import annotations

import hashlib
import os
import re
import uuid

from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from dimsum.extensions import db
from dimsum.models.project import Project
from dimsum.models.source_upload import SourceUpload
from dimsum.source_analysis.analyzer import analyze_source, detect_language

source_analysis_bp = Blueprint("api_source_analysis", __name__)

_ALLOWED_EXTENSIONS = {".js", ".jsx", ".mjs", ".ts", ".tsx", ".py"}

_GITHUB_URL_PATTERN = re.compile(
    r'^https?://github\.com/[\w.\-]+/[\w.\-]+(?:\.git)?$'
)


def _get_user_project(project_id: str) -> Project | None:
    try:
        pid = uuid.UUID(project_id)
    except ValueError:
        return None
    return db.session.execute(
        db.select(Project).filter_by(id=pid, owner_id=current_user.id)
    ).scalar_one_or_none()


@source_analysis_bp.route("/<project_id>/source/upload", methods=["POST"])
@login_required
def upload_source(project_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    data = request.get_json(silent=True)

    # If JSON body with repo_url, handle as GitHub repo clone
    if data and data.get("repo_url"):
        return _handle_repo_clone(project, data)

    # Otherwise handle as file upload
    return _handle_file_upload(project)


def _handle_repo_clone(project, data):
    repo_url = data.get("repo_url", "").strip()
    branch = data.get("branch", "main").strip()

    if not repo_url:
        return jsonify({"error": "repo_url is required"}), 400

    if not _GITHUB_URL_PATTERN.match(repo_url):
        return jsonify({"error": "Invalid GitHub URL. Expected: https://github.com/owner/repo"}), 400

    from dimsum.source_analysis import analyze_repo, cleanup_repo, clone_repo

    try:
        repo_path = clone_repo(repo_url, branch)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 400

    try:
        results = analyze_repo(repo_path)
    finally:
        cleanup_repo(repo_path)

    # Delete previous uploads for this project+repo to avoid duplicates
    db.session.execute(
        db.delete(SourceUpload).where(
            SourceUpload.project_id == project.id,
            SourceUpload.repo_url == repo_url,
        )
    )

    for file_info in results["files"]:
        su = SourceUpload(
            project_id=project.id,
            filename=file_info["filepath"],
            language=file_info["language"],
            file_path=file_info["filepath"],
            file_hash=file_info["hash"],
            repo_url=repo_url,
            analysis_status="completed",
            extracted_params=file_info["parameters"],
            extracted_routes=file_info["routes"],
            risk_indicators=file_info["risk_indicators"],
        )
        db.session.add(su)

    db.session.commit()

    return jsonify({
        "message": f"Analyzed {results['files_analyzed']} files",
        "files_analyzed": results["files_analyzed"],
        "routes_found": len(results["routes"]),
        "parameters_found": len(results["parameters"]),
        "risk_indicators_found": len(results["risk_indicators"]),
        "routes": results["routes"],
        "parameters": results["parameters"],
        "risk_indicators": results["risk_indicators"],
    }), 201


def _handle_file_upload(project):
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
    project = _get_user_project(project_id)
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
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    data = request.get_json(silent=True) or {}
    file_ids = data.get("file_ids")

    # Re-analyze GitHub repos
    repo_urls = db.session.execute(
        db.select(SourceUpload.repo_url)
        .filter(SourceUpload.project_id == project.id, SourceUpload.repo_url.isnot(None))
        .distinct()
    ).scalars().all()

    total_repo_files = 0
    if repo_urls:
        from dimsum.source_analysis import analyze_repo, cleanup_repo, clone_repo

        for repo_url in repo_urls:
            try:
                repo_path = clone_repo(repo_url)
            except RuntimeError:
                continue

            try:
                results = analyze_repo(repo_path)
            finally:
                cleanup_repo(repo_path)

            db.session.execute(
                db.delete(SourceUpload).where(
                    SourceUpload.project_id == project.id,
                    SourceUpload.repo_url == repo_url,
                )
            )

            for file_info in results["files"]:
                su = SourceUpload(
                    project_id=project.id,
                    filename=file_info["filepath"],
                    language=file_info["language"],
                    file_path=file_info["filepath"],
                    file_hash=file_info["hash"],
                    repo_url=repo_url,
                    analysis_status="completed",
                    extracted_params=file_info["parameters"],
                    extracted_routes=file_info["routes"],
                    risk_indicators=file_info["risk_indicators"],
                )
                db.session.add(su)

            total_repo_files += results["files_analyzed"]

        db.session.commit()

    # Re-analyze uploaded files
    if file_ids:
        uploads = db.session.execute(
            db.select(SourceUpload).filter(
                SourceUpload.project_id == project.id,
                SourceUpload.id.in_([uuid.UUID(fid) for fid in file_ids]),
                SourceUpload.repo_url.is_(None),
            )
        ).scalars().all()
    else:
        uploads = db.session.execute(
            db.select(SourceUpload).filter(
                SourceUpload.project_id == project.id,
                SourceUpload.repo_url.is_(None),
            )
        ).scalars().all()

    if not uploads and not repo_urls:
        return jsonify({"error": "No source files to analyze"}), 400

    results_list = []
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
            upload.risk_indicators = [
                {"pattern_name": ri.pattern_name, "description": ri.description,
                 "severity": ri.severity, "file": ri.file, "line": ri.line,
                 "code_snippet": ri.code_snippet, "cwe_id": ri.cwe_id}
                for ri in analysis.risk_indicators
            ]
            upload.analysis_status = "completed"

            results_list.append(analysis.to_dict())

        except Exception as exc:
            upload.analysis_status = "failed"
            results_list.append({"file_path": upload.filename, "error": str(exc)[:500]})

        db.session.commit()

    return jsonify({
        "analyzed": len(results_list) + total_repo_files,
        "results": results_list,
    })


@source_analysis_bp.route("/<project_id>/source/results", methods=["GET"])
@login_required
def get_analysis_results(project_id):
    project = _get_user_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    uploads = db.session.execute(
        db.select(SourceUpload).filter_by(project_id=project.id, analysis_status="completed")
    ).scalars().all()

    all_routes = []
    all_params = []
    all_risk_indicators = []
    seen_params: set[str] = set()

    for upload in uploads:
        for route in (upload.extracted_routes or []):
            if "file" not in route:
                route["file"] = upload.filename
            all_routes.append(route)

        for param in (upload.extracted_params or []):
            key = f"{param.get('name', '')}:{param.get('source', '')}"
            if key not in seen_params:
                seen_params.add(key)
                if "file" not in param:
                    param["file"] = upload.filename
                all_params.append(param)

        for ri in (upload.risk_indicators or []):
            all_risk_indicators.append(ri)

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

    if upload.file_path and os.path.exists(upload.file_path):
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
        "repo_url": u.repo_url,
        "analysis_status": u.analysis_status,
        "routes_count": len(u.extracted_routes) if u.extracted_routes else 0,
        "params_count": len(u.extracted_params) if u.extracted_params else 0,
        "risks_count": len(u.risk_indicators) if u.risk_indicators else 0,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }
