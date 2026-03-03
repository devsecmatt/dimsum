from __future__ import annotations

from flask import Blueprint, jsonify
from flask_login import login_required

source_analysis_bp = Blueprint("api_source_analysis", __name__)


@source_analysis_bp.route("/<project_id>/source/upload", methods=["POST"])
@login_required
def upload_source(project_id):
    # Stub — will be implemented in Phase 7
    return jsonify({"error": "Not implemented"}), 501


@source_analysis_bp.route("/<project_id>/source/files", methods=["GET"])
@login_required
def list_source_files(project_id):
    return jsonify([])


@source_analysis_bp.route("/<project_id>/source/analyze", methods=["POST"])
@login_required
def trigger_analysis(project_id):
    return jsonify({"error": "Not implemented"}), 501


@source_analysis_bp.route("/<project_id>/source/results", methods=["GET"])
@login_required
def get_analysis_results(project_id):
    return jsonify({"routes": [], "parameters": [], "risk_indicators": []})
