from __future__ import annotations

from celery import shared_task


@shared_task(bind=True, name="dimsum.tasks.scan_tasks.run_scan")
def run_scan(self, scan_id: str) -> dict:
    """Main scan task — will be implemented in Phase 3."""
    return {"status": "not_implemented", "scan_id": scan_id}
