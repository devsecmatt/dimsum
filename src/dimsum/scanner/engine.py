from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable

from dimsum.scanner.context import ScanContext
from dimsum.scanner.http_client import AsyncHTTPClient, ClientConfig
from dimsum.scanner.registry import PluginRegistry
from dimsum.scanner.result import ScanFinding

logger = logging.getLogger(__name__)


class ScanEngine:
    """Orchestrates a security scan by running plugins against targets."""

    def __init__(
        self,
        context: ScanContext,
        progress_callback: Callable[[int, str], None] | None = None,
    ):
        self.context = context
        self._progress_callback = progress_callback
        self._findings: list[ScanFinding] = []
        self._start_time: float = 0

    def _report_progress(self, percent: int, message: str) -> None:
        if self._progress_callback:
            self._progress_callback(percent, message)

    async def run(self) -> list[ScanFinding]:
        """Execute the full scan lifecycle.

        1. Discover plugins to run
        2. Build HTTP client
        3. Run enumeration plugins (if enabled)
        4. Run security check plugins concurrently
        5. Deduplicate findings
        6. Return findings
        """
        self._start_time = time.monotonic()
        self._findings = []

        # Ensure plugins are discovered
        PluginRegistry.discover_plugins()

        # Select plugins to run
        enum_plugins, security_plugins = self._select_plugins()

        total_plugins = len(enum_plugins) + len(security_plugins)
        if total_plugins == 0:
            logger.warning("No plugins selected for scan %s", self.context.scan_id)
            return []

        self.context.total_checks = total_plugins
        self._report_progress(0, "Initializing scan...")

        client_config = ClientConfig(
            timeout_seconds=self.context.timeout_seconds,
            max_concurrency=self.context.max_concurrency,
            request_delay_ms=self.context.request_delay_ms,
            custom_headers=self.context.custom_headers,
            auth_config=self.context.auth_config,
        )

        async with AsyncHTTPClient(client_config) as http:
            # Phase 1: Enumeration
            if enum_plugins:
                self._report_progress(5, "Running enumeration...")
                await self._run_plugins(enum_plugins, http)

            # Phase 2: Security checks
            self._report_progress(20, "Running security checks...")
            await self._run_plugins(security_plugins, http)

            self._report_progress(95, "Deduplicating findings...")
            self._findings = self._deduplicate(self._findings)

        elapsed = time.monotonic() - self._start_time
        logger.info(
            "Scan %s completed: %d findings in %.1fs (%d requests)",
            self.context.scan_id,
            len(self._findings),
            elapsed,
            http.request_count,
        )
        self._report_progress(100, "Scan complete")
        return self._findings

    def _select_plugins(self):
        """Choose which plugins to run based on context."""
        all_plugins = PluginRegistry.get_all()

        enum_plugins = []
        security_plugins = []

        for pid, pcls in all_plugins.items():
            # If specific plugins are enabled, filter to those
            if self.context.enabled_plugin_ids and pid not in self.context.enabled_plugin_ids:
                continue

            # Skip enumeration for quick/source_only scans
            if pcls.meta.is_enumeration:
                if self.context.scan_type in ("quick", "source_only"):
                    continue
                enum_plugins.append(pcls)
            else:
                # For source_only scans, skip all security plugins
                if self.context.scan_type == "source_only":
                    continue
                security_plugins.append(pcls)

        return enum_plugins, security_plugins

    async def _run_plugins(self, plugin_classes: list, http: AsyncHTTPClient) -> None:
        """Run a set of plugins concurrently with bounded concurrency."""
        sem = asyncio.Semaphore(self.context.max_concurrency)

        async def run_one(pcls):
            async with sem:
                plugin = pcls(self.context, http)
                plugin_id = pcls.meta.plugin_id
                try:
                    logger.info("Running plugin: %s", plugin_id)
                    findings = await plugin.run()
                    self._findings.extend(findings)
                    self.context.completed_checks += 1
                    pct = 20 + int(
                        (self.context.completed_checks / max(self.context.total_checks, 1)) * 70
                    )
                    self._report_progress(pct, f"Completed: {pcls.meta.name}")
                except Exception:
                    logger.exception("Plugin %s failed", plugin_id)
                    self.context.completed_checks += 1

        await asyncio.gather(*[run_one(pcls) for pcls in plugin_classes])

    @staticmethod
    def _deduplicate(findings: list[ScanFinding]) -> list[ScanFinding]:
        """Remove duplicate findings based on plugin_id + url + parameter + payload."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.plugin_id, f.url, f.parameter, f.payload)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
