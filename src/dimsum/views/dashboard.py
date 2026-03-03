from __future__ import annotations

from flask import Blueprint, render_template
from flask_login import current_user, login_required

from dimsum.extensions import db
from dimsum.models.project import Project
from dimsum.models.scan import Scan

dashboard_bp = Blueprint("views_dashboard", __name__)


@dashboard_bp.route("/")
@login_required
def index():
    projects = db.session.execute(
        db.select(Project).filter_by(owner_id=current_user.id).order_by(Project.updated_at.desc()).limit(10)
    ).scalars().all()

    recent_scans = db.session.execute(
        db.select(Scan)
        .join(Project)
        .filter(Project.owner_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(10)
    ).scalars().all()

    return render_template(
        "dashboard/index.html",
        projects=projects,
        recent_scans=recent_scans,
    )
