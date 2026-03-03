from __future__ import annotations

import uuid

from flask import Blueprint, render_template, abort
from flask_login import current_user, login_required

from dimsum.extensions import db
from dimsum.models.scan import Scan

views_scans_bp = Blueprint("views_scans", __name__, url_prefix="/scans")


@views_scans_bp.route("/")
@login_required
def list_scans():
    return render_template("scans/list.html")


@views_scans_bp.route("/<scan_id>")
@login_required
def detail(scan_id):
    try:
        sid = uuid.UUID(scan_id)
    except ValueError:
        abort(404)

    scan = db.session.get(Scan, sid)
    if scan is None:
        abort(404)

    # Verify the user owns this scan's project
    if scan.project.owner_id != current_user.id:
        abort(404)

    return render_template(
        "scans/detail.html",
        scan_id=scan_id,
        project_id=str(scan.project_id),
    )
