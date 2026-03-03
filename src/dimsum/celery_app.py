from __future__ import annotations

from celery import Celery


def create_celery_app(flask_app=None) -> Celery:
    """Create and configure the Celery application.

    When flask_app is provided, tasks run inside the Flask app context
    (needed for DB access). When flask_app is None, a Flask app is
    created automatically so the Celery CLI worker has full access.
    """
    if flask_app is None:
        from dimsum.app import create_app
        flask_app = create_app()

    celery = Celery("dimsum")
    celery.conf.update(
        broker_url=flask_app.config.get("CELERY_BROKER_URL", "redis://localhost:6379/0"),
        result_backend=flask_app.config.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/1"),
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        task_soft_time_limit=3600,
        task_time_limit=3900,
        task_routes={
            "dimsum.tasks.scan_tasks.*": {"queue": "scans"},
            "dimsum.tasks.report_tasks.*": {"queue": "reports"},
            "dimsum.tasks.source_analysis_tasks.*": {"queue": "analysis"},
        },
        include=["dimsum.tasks.scan_tasks"],
    )

    class FlaskTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with flask_app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = FlaskTask

    return celery


# Module-level celery instance for CLI: celery -A dimsum.celery_app:celery worker
celery = create_celery_app()
