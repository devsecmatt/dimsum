from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import login_required

reports_bp = Blueprint("api_reports", __name__)


@reports_bp.route("/generate", methods=["POST"])
@login_required
def generate_report():
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan_id")
    report_format = data.get("format", "json")

    if not scan_id:
        return jsonify({"error": "scan_id is required"}), 400
    if report_format not in ("json", "pdf", "csv", "sarif"):
        return jsonify({"error": "Invalid format. Choose: json, pdf, csv, sarif"}), 400

    # Will be implemented in Phase 8
    return jsonify({"message": "Report generation queued", "format": report_format}), 202


@reports_bp.route("/<report_id>/status", methods=["GET"])
@login_required
def get_report_status(report_id):
    return jsonify({"status": "pending"}), 200


@reports_bp.route("/<report_id>/download", methods=["GET"])
@login_required
def download_report(report_id):
    return jsonify({"error": "Not implemented"}), 501
