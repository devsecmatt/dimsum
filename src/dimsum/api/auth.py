from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required, login_user, logout_user

from dimsum.extensions import db
from dimsum.models.user import User

auth_api_bp = Blueprint("api_auth", __name__)


@auth_api_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    user = db.session.execute(
        db.select(User).filter_by(username=username)
    ).scalar_one_or_none()

    if user is None or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    login_user(user)
    return jsonify({"message": "Logged in", "user": {"id": str(user.id), "username": user.username}})


@auth_api_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out"})


@auth_api_bp.route("/me", methods=["GET"])
@login_required
def get_current_user():
    return jsonify({
        "id": str(current_user.id),
        "username": current_user.username,
        "email": current_user.email,
    })
