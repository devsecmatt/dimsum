from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(bind=True, name="dimsum.tasks.scan_tasks.run_scan")
def run_scan(self, scan_id: str) -> dict:
    """Main Celery task that executes a scan via the ScanEngine.

    1. Load Scan + config + targets from DB
    2. Build ScanContext
    3. Run ScanEngine (async) within the sync Celery worker
    4. Persist findings to DB
    5. Update scan status and summary
    """
    from dimsum.extensions import db
    from dimsum.models.finding import Finding
    from dimsum.models.scan import Scan
    from dimsum.scanner.context import ScanContext
    from dimsum.scanner.engine import ScanEngine

    sid = uuid.UUID(scan_id)
    scan = db.session.get(Scan, sid)
    if scan is None:
        logger.error("Scan %s not found", scan_id)
        return {"status": "error", "message": "Scan not found"}

    # Mark as running
    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    scan.progress_percent = 0
    scan.progress_message = "Initializing..."
    db.session.commit()

    def progress_callback(percent: int, message: str):
        """Update scan progress in DB (called from async context)."""
        try:
            scan.progress_percent = percent
            scan.progress_message = message
            db.session.commit()
        except Exception:
            logger.debug("Failed to update progress for scan %s", scan_id)

    try:
        # Build context from scan + config + targets
        context = _build_context(scan)

        # Run the async engine in a new event loop
        engine = ScanEngine(context, progress_callback=progress_callback)
        loop = asyncio.new_event_loop()
        try:
            findings = loop.run_until_complete(engine.run())
        finally:
            loop.close()

        # Persist findings
        finding_count = 0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for sf in findings:
            finding = Finding(
                scan_id=scan.id,
                plugin_id=sf.plugin_id,
                title=sf.title,
                description=sf.description,
                severity=sf.severity.value,
                confidence=sf.confidence.value,
                url=sf.url,
                method=sf.method,
                parameter=sf.parameter,
                payload=sf.payload,
                evidence=sf.evidence,
                request_dump=sf.request_dump,
                response_dump=sf.response_dump,
                cwe_id=sf.cwe_id,
                cvss_score=sf.cvss_score,
                remediation=sf.remediation,
                source_file=sf.source_file,
                source_line=sf.source_line,
            )
            db.session.add(finding)
            finding_count += 1
            severity_counts[sf.severity.value] = severity_counts.get(sf.severity.value, 0) + 1

        # Update scan status
        now = datetime.now(timezone.utc)
        scan.status = "completed"
        scan.completed_at = now
        scan.duration_seconds = (now - scan.started_at).total_seconds()
        scan.total_requests = context.completed_checks
        scan.progress_percent = 100
        scan.progress_message = "Scan complete"
        scan.summary_stats = {
            "total_findings": finding_count,
            "severity_counts": severity_counts,
            "urls_scanned": len(context.all_urls),
            "plugins_run": context.completed_checks,
        }
        db.session.commit()

        logger.info(
            "Scan %s completed: %d findings (%s)",
            scan_id,
            finding_count,
            severity_counts,
        )
        return {
            "status": "completed",
            "scan_id": scan_id,
            "findings": finding_count,
            "severity_counts": severity_counts,
        }

    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        scan.status = "failed"
        scan.error_message = str(exc)[:2000]
        scan.completed_at = datetime.now(timezone.utc)
        if scan.started_at:
            scan.duration_seconds = (scan.completed_at - scan.started_at).total_seconds()
        db.session.commit()
        return {"status": "failed", "scan_id": scan_id, "error": str(exc)[:500]}


def _build_context(scan) -> "ScanContext":
    """Build a ScanContext from a Scan ORM object."""
    from dimsum.extensions import db
    from dimsum.models.scan_config import ScanConfiguration
    from dimsum.models.target import Target
    from dimsum.scanner.context import ScanContext

    context = ScanContext(scan_id=scan.id, scan_type=scan.scan_type)

    # Load targets
    if scan.target_ids:
        for tid_str in scan.target_ids:
            try:
                tid = uuid.UUID(tid_str) if isinstance(tid_str, str) else tid_str
                target = db.session.get(Target, tid)
                if target and target.is_active:
                    _add_target_to_context(target, context)
            except (ValueError, TypeError):
                logger.warning("Invalid target_id in scan: %s", tid_str)
    else:
        # No specific targets — use all active targets from the project
        targets = db.session.execute(
            db.select(Target).filter_by(project_id=scan.project_id, is_active=True)
        ).scalars().all()
        for target in targets:
            _add_target_to_context(target, context)

    # Load config
    if scan.config_id:
        config = db.session.get(ScanConfiguration, scan.config_id)
        if config:
            context.max_concurrency = config.max_concurrency
            context.request_delay_ms = config.request_delay_ms
            context.timeout_seconds = config.timeout_seconds
            context.max_depth = config.max_depth
            context.custom_headers = config.custom_headers or {}
            context.auth_config = config.auth_config
            context.asvs_level = config.asvs_level
            context.enabled_plugin_ids = config.enabled_plugins or []

    return context


def _add_target_to_context(target, context) -> None:
    """Add a single Target ORM object to the ScanContext."""
    if target.target_type == "url":
        context.target_urls.append(target.value)
    elif target.target_type == "domain":
        context.target_domains.append(target.value)
        context.target_urls.append(f"https://{target.value}")
        context.target_urls.append(f"http://{target.value}")
    elif target.target_type == "ip":
        context.target_ips.append(target.value)
        context.target_urls.append(f"http://{target.value}")
    elif target.target_type == "api_spec":
        context.target_urls.append(target.value)
        if target.api_spec_content:
            endpoints = _extract_api_endpoints(
                target.value, target.api_spec_content, target.api_spec_format
            )
            context.discovered_endpoints.extend(endpoints)


def _extract_api_endpoints(base_url: str, spec: dict, spec_format: str | None) -> list[str]:
    """Extract endpoint URLs from an API spec document."""
    endpoints = []
    base_url = base_url.rstrip("/")

    try:
        if spec_format in ("openapi_3", "swagger_2") or "paths" in spec:
            paths = spec.get("paths", {})
            for path in paths:
                endpoints.append(f"{base_url}{path}")
        elif spec_format == "postman":
            items = spec.get("item", [])
            for item in items:
                _extract_postman_urls(item, endpoints)
    except Exception:
        logger.debug("Failed to extract endpoints from API spec")

    return endpoints


def _extract_postman_urls(item: dict, endpoints: list[str]) -> None:
    """Recursively extract URLs from Postman collection items."""
    if "item" in item:
        for sub in item["item"]:
            _extract_postman_urls(sub, endpoints)
    elif "request" in item:
        req = item["request"]
        url = req.get("url", "")
        if isinstance(url, dict):
            raw = url.get("raw", "")
            if raw:
                endpoints.append(raw)
        elif isinstance(url, str) and url:
            endpoints.append(url)
