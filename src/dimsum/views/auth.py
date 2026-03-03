from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from dimsum.extensions import db
from dimsum.models.user import User

views_auth_bp = Blueprint("views_auth", __name__)


@views_auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("views_dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = db.session.execute(
            db.select(User).filter_by(username=username)
        ).scalar_one_or_none()

        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get("next")
            return redirect(next_page or url_for("views_dashboard.index"))

        flash("Invalid username or password.", "error")

    return render_template("auth/login.html")


@views_auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("views_auth.login"))
