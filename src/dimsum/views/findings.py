from __future__ import annotations

from flask import Blueprint, render_template
from flask_login import login_required

views_findings_bp = Blueprint("views_findings", __name__, url_prefix="/findings")


@views_findings_bp.route("/")
@login_required
def list_findings():
    return render_template("findings/list.html")


@views_findings_bp.route("/<finding_id>")
@login_required
def detail(finding_id):
    return render_template("findings/detail.html", finding_id=finding_id)
