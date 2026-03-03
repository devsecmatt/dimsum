from __future__ import annotations

from flask import Blueprint, render_template
from flask_login import login_required

views_reports_bp = Blueprint("views_reports", __name__, url_prefix="/reports")


@views_reports_bp.route("/")
@login_required
def generate():
    return render_template("reports/generate.html")
