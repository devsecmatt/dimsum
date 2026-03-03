from __future__ import annotations

from flask import Blueprint, render_template
from flask_login import login_required

views_scans_bp = Blueprint("views_scans", __name__, url_prefix="/scans")


@views_scans_bp.route("/")
@login_required
def list_scans():
    return render_template("scans/list.html")


@views_scans_bp.route("/<scan_id>")
@login_required
def detail(scan_id):
    return render_template("scans/detail.html", scan_id=scan_id)
