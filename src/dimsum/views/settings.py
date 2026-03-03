from __future__ import annotations

from flask import Blueprint, render_template
from flask_login import login_required

views_settings_bp = Blueprint("views_settings", __name__, url_prefix="/settings")


@views_settings_bp.route("/")
@login_required
def index():
    return render_template("settings/index.html")
