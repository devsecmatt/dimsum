from __future__ import annotations

import uuid

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from dimsum.extensions import db
from dimsum.models.project import Project

views_projects_bp = Blueprint("views_projects", __name__, url_prefix="/projects")


@views_projects_bp.route("/")
@login_required
def list_projects():
    projects = db.session.execute(
        db.select(Project).filter_by(owner_id=current_user.id).order_by(Project.updated_at.desc())
    ).scalars().all()
    return render_template("projects/list.html", projects=projects)


@views_projects_bp.route("/new", methods=["GET", "POST"])
@login_required
def create_project():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        if not name:
            flash("Project name is required.", "error")
        else:
            project = Project(name=name, description=description or None, owner_id=current_user.id)
            db.session.add(project)
            db.session.commit()
            flash("Project created.", "success")
            return redirect(url_for("views_projects.detail", project_id=project.id))

    return render_template("projects/create.html")


@views_projects_bp.route("/<project_id>")
@login_required
def detail(project_id):
    project = _get_project(project_id)
    if project is None:
        flash("Project not found.", "error")
        return redirect(url_for("views_projects.list_projects"))
    return render_template("projects/detail.html", project=project)


def _get_project(project_id: str) -> Project | None:
    try:
        pid = uuid.UUID(project_id)
    except ValueError:
        return None
    return db.session.execute(
        db.select(Project).filter_by(id=pid, owner_id=current_user.id)
    ).scalar_one_or_none()
