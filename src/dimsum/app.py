from __future__ import annotations

import os

from flask import Flask

from dimsum.config import config_by_name
from dimsum.extensions import db, login_manager, migrate


def create_app(config_name: str | None = None) -> Flask:
    """Flask application factory."""
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config.from_object(config_by_name[config_name])

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    # Import models so they are registered with SQLAlchemy
    with app.app_context():
        import dimsum.models  # noqa: F401

    # Register blueprints
    _register_blueprints(app)

    # Register error handlers
    _register_error_handlers(app)

    # Create first admin user if needed
    _ensure_admin_user(app)

    return app


def _register_blueprints(app: Flask) -> None:
    from dimsum.api.auth import auth_api_bp
    from dimsum.api.projects import projects_bp
    from dimsum.api.targets import targets_bp
    from dimsum.api.scans import scans_bp
    from dimsum.api.findings import findings_bp
    from dimsum.api.reports import reports_bp
    from dimsum.api.asvs import asvs_bp
    from dimsum.api.wordlists import wordlists_bp
    from dimsum.api.source_analysis import source_analysis_bp
    from dimsum.views.auth import views_auth_bp
    from dimsum.views.dashboard import dashboard_bp
    from dimsum.views.projects import views_projects_bp
    from dimsum.views.scans import views_scans_bp
    from dimsum.views.findings import views_findings_bp
    from dimsum.views.reports import views_reports_bp
    from dimsum.views.settings import views_settings_bp

    # API blueprints
    app.register_blueprint(auth_api_bp, url_prefix="/api/auth")
    app.register_blueprint(projects_bp, url_prefix="/api/projects")
    app.register_blueprint(targets_bp, url_prefix="/api/projects")
    app.register_blueprint(scans_bp, url_prefix="/api/projects")
    app.register_blueprint(findings_bp, url_prefix="/api/findings")
    app.register_blueprint(reports_bp, url_prefix="/api/reports")
    app.register_blueprint(asvs_bp, url_prefix="/api/asvs")
    app.register_blueprint(wordlists_bp, url_prefix="/api/wordlists")
    app.register_blueprint(source_analysis_bp, url_prefix="/api/projects")

    # View blueprints
    app.register_blueprint(views_auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(views_projects_bp)
    app.register_blueprint(views_scans_bp)
    app.register_blueprint(views_findings_bp)
    app.register_blueprint(views_reports_bp)
    app.register_blueprint(views_settings_bp)


def _register_error_handlers(app: Flask) -> None:
    from flask import jsonify, request

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Not found"}), 404
        return "Not found", 404

    @app.errorhandler(500)
    def server_error(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Internal server error"}), 500
        return "Internal server error", 500


def _ensure_admin_user(app: Flask) -> None:
    """Create the admin user on first run if it doesn't exist."""
    username = os.environ.get("ADMIN_USERNAME")
    password = os.environ.get("ADMIN_PASSWORD")
    email = os.environ.get("ADMIN_EMAIL")
    if not (username and password and email):
        return

    with app.app_context():
        from dimsum.models.user import User

        try:
            existing = db.session.execute(
                db.select(User).filter_by(username=username)
            ).scalar_one_or_none()
            if existing is None:
                user = User(username=username, email=email)
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                app.logger.info(f"Admin user '{username}' created.")
        except Exception:
            # Table may not exist yet (before first migration)
            db.session.rollback()
