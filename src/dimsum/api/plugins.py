"""API endpoint to list available scan plugins."""

from __future__ import annotations

from flask import Blueprint, jsonify
from flask_login import login_required

from dimsum.scanner.registry import PluginRegistry

plugins_bp = Blueprint("api_plugins", __name__)


@plugins_bp.route("/", methods=["GET"])
@login_required
def list_plugins():
    """Return metadata for all registered scan plugins."""
    PluginRegistry.discover_plugins()
    return jsonify(PluginRegistry.list_info())
