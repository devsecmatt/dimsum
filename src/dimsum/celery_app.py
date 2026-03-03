from __future__ import annotations

from celery import Celery


def create_celery_app(flask_app=None) -> Celery:
    """Create and configure the Celery application."""
    celery = Celery(
        "dimsum",
        broker_url="redis://localhost:6379/0",
        result_backend="redis://localhost:6379/1",
    )
    celery.conf.update(
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
    )

    if flask_app:
        celery.conf.update(broker_url=flask_app.config["CELERY_BROKER_URL"])
        celery.conf.update(result_backend=flask_app.config["CELERY_RESULT_BACKEND"])

        class FlaskTask(celery.Task):
            def __call__(self, *args, **kwargs):
                with flask_app.app_context():
                    return self.run(*args, **kwargs)

        celery.Task = FlaskTask

    return celery


# Module-level celery instance for CLI: celery -A dimsum.celery_app:celery worker
celery = create_celery_app()
